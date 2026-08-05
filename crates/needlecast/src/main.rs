//! Two commands, one shared secret, and a tunnel needlecast creates and owns.
//!
//! ```text
//! needlecast server ./secret cesium.gio.ninja     # on the machine with the dev servers
//! needlecast client ./secret cadmium.gio.ninja    # on the machine you are typing at
//! ```
//!
//! Each side is given the *other* machine's name — above, the desktop is `cadmium` and the laptop
//! is `cesium`. That is the whole configuration: no pairing step, no config file, no state
//! directory.

mod bpf;
mod client;
mod control;
mod dev;
mod identity;
mod server;
mod shutdown;
mod status;
mod transport;
mod wake;

#[cfg(feature = "testing")]
mod harness;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use needlecast_common::proto::DEFAULT_CONTROL_PORT;
use needlecast_common::{ev, prog, tc, tcev, COUNTER_SLOTS, TC_COUNTER_SLOTS};

use transport::DEFAULT_LISTEN_PORT;

/// The default managed range. Everything outside it is never touched on either side, which is the
/// only limit on what the server exposes — so keep anything you do not want reachable outside it.
const DEFAULT_PORT_LO: u16 = 8000;
const DEFAULT_PORT_HI: u16 = 8999;

#[derive(Parser)]
#[command(
    name = "needlecast",
    version,
    about = "reach the other machine's localhost"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve this machine's loopback ports to the paired client.
    Server {
        /// The shared secret. Both machines need the same file, mode 600.
        secret: PathBuf,
        /// The other machine's DNS name.
        peer: String,
        /// Lowest loopback port to serve.
        #[arg(long, default_value_t = DEFAULT_PORT_LO)]
        port_lo: u16,
        /// Highest loopback port to serve.
        #[arg(long, default_value_t = DEFAULT_PORT_HI)]
        port_hi: u16,
        /// WireGuard port. Must match on both machines.
        #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        /// Control port, inside the tunnel.
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
    },
    /// Reach the paired server's loopback ports as if they were this machine's.
    Client {
        /// The shared secret. Both machines need the same file, mode 600.
        secret: PathBuf,
        /// The other machine's DNS name.
        peer: String,
        /// WireGuard port. Must match on both machines.
        #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        /// Control port, inside the tunnel.
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
        /// TCP_SYNCNT for rewritten sockets. Caps how long a connection hangs when the server
        /// vanishes between heartbeats. Zero leaves the system default of about two minutes.
        #[arg(long, default_value_t = 2)]
        syncnt: u8,
    },
    /// Report what this machine is doing. Reads kernel and filesystem state directly, so it works
    /// when the daemon is wedged or dead — which is when it is worth having.
    Status {
        /// Which half runs here. Both, if you are checking a machine that runs both.
        #[arg(long, value_enum, default_value = "auto")]
        role: StatusRole,
    },
    /// Print both public keys derived from a secret file. Run it on each machine: if the two
    /// outputs differ, the secrets differ, which is the failure the tunnel would otherwise report
    /// only as a handshake that never completes.
    Keys {
        /// The shared secret. Must not be readable by anyone but its owner.
        secret: PathBuf,
    },
    /// Diagnostics: read the pinned maps and inspect the embedded object.
    #[command(subcommand)]
    Dev(DevCommand),
    /// Test scaffolding, compiled only with `--features testing`. Drives one half of the system in
    /// isolation, which the shipped binary deliberately cannot do.
    #[cfg(feature = "testing")]
    #[command(subcommand)]
    Harness(harness::Command),
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum StatusRole {
    Auto,
    Client,
    Server,
}

#[derive(Subcommand)]
enum DevCommand {
    /// Print every non-zero client counter as `program.event=count`.
    Counters,
    /// Print every non-zero server counter as `program.event=count`.
    TcCounters,
    /// Print the loaded client configuration.
    ShowConfig,
    /// Flip the enabled flag without restarting the daemon.
    SetEnabled { value: u8 },
    /// Populate DESKTOP_PORTS.
    Advertise { ports: Vec<u16> },
    /// Remove entries from DESKTOP_PORTS.
    Withdraw { ports: Vec<u16> },
    /// Print the ports this machine is serving, as the control plane would publish them.
    Listeners,
    /// Report the current network namespace cookie.
    NetnsCookie,
    /// Parse an object without touching the kernel. Defaults to the embedded one. Unprivileged.
    VerifyObject { path: Option<PathBuf> },
    /// Prove the embedded object is aligned, and that misalignment is what breaks the parser.
    /// Unprivileged. Exits non-zero if either half of that does not hold.
    AlignmentCheck,
    /// Try loading and attaching only the setsockopt probe. Exits non-zero if the verifier
    /// rejected it.
    ProbeSyncnt,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Server {
            secret,
            peer,
            port_lo,
            port_hi,
            listen_port,
            control_port,
        } => server::run(server::Args {
            secret,
            peer,
            port_lo,
            port_hi,
            listen_port,
            control_port,
        }),
        Command::Client {
            secret,
            peer,
            listen_port,
            control_port,
            syncnt,
        } => client::run(client::Args {
            secret,
            peer,
            listen_port,
            control_port,
            syncnt,
        }),
        Command::Status { role } => status::report(role),
        Command::Keys { secret } => {
            let id = identity::Identity::load(&secret, identity::Role::Server)?;
            println!("server {}", id.own.public_base64());
            println!("client {}", id.peer.public_base64());
            Ok(())
        }
        Command::Dev(d) => match d {
            DevCommand::Counters => dev::counters(),
            DevCommand::TcCounters => dev::tc_counters(),
            DevCommand::ShowConfig => dev::show_config(),
            DevCommand::SetEnabled { value } => dev::set_enabled(value),
            DevCommand::Advertise { ports } => dev::advertise(&ports, true),
            DevCommand::Withdraw { ports } => dev::advertise(&ports, false),
            DevCommand::Listeners => dev::listeners(),
            DevCommand::NetnsCookie => dev::netns_cookie(),
            DevCommand::VerifyObject { path } => dev::verify_object(path),
            DevCommand::AlignmentCheck => dev::alignment_check(),
            DevCommand::ProbeSyncnt => dev::probe_syncnt(),
        },
        #[cfg(feature = "testing")]
        Command::Harness(h) => harness::run(h),
    }
}

const _: () = assert!(COUNTER_SLOTS == prog::COUNT * ev::COUNT);
const _: () = assert!(TC_COUNTER_SLOTS == tc::COUNT * tcev::COUNT);

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_two_commands_need_only_a_secret_and_a_peer_name() {
        let cli = Cli::try_parse_from(["needlecast", "server", "./secret", "cesium"]).unwrap();
        match cli.command {
            Command::Server {
                secret,
                peer,
                port_lo,
                port_hi,
                ..
            } => {
                assert_eq!(secret, PathBuf::from("./secret"));
                assert_eq!(peer, "cesium");
                assert_eq!((port_lo, port_hi), (DEFAULT_PORT_LO, DEFAULT_PORT_HI));
            }
            _ => panic!("wrong command"),
        }

        let cli = Cli::try_parse_from(["needlecast", "client", "./secret", "cadmium"]).unwrap();
        assert!(matches!(cli.command, Command::Client { .. }));
    }

    #[test]
    fn both_halves_need_both_arguments() {
        for cmd in ["server", "client"] {
            assert!(Cli::try_parse_from(["needlecast", cmd]).is_err());
            assert!(Cli::try_parse_from(["needlecast", cmd, "./secret"]).is_err());
        }
    }

    /// The shipped binary must not be able to express any test scaffolding.
    #[cfg(not(feature = "testing"))]
    #[test]
    fn the_harness_is_absent_without_the_testing_feature() {
        assert!(Cli::try_parse_from(["needlecast", "harness", "bridge"]).is_err());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn the_harness_is_present_with_the_testing_feature() {
        assert!(Cli::try_parse_from([
            "needlecast",
            "harness",
            "bridge",
            "--target-v4",
            "10.7.0.2"
        ])
        .is_ok());
    }

    #[test]
    fn the_default_range_is_the_one_the_design_documents() {
        assert_eq!((DEFAULT_PORT_LO, DEFAULT_PORT_HI), (8000, 8999));
        // The control and WireGuard ports must sit outside it, or the control plane would forward
        // itself.
        for port in [DEFAULT_CONTROL_PORT, DEFAULT_LISTEN_PORT] {
            assert!(
                !(DEFAULT_PORT_LO..=DEFAULT_PORT_HI).contains(&port),
                "{port} is inside the managed range"
            );
        }
    }
}
