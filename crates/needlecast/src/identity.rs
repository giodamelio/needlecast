//! Both keypairs from one file, so there is no pairing step and nothing to exchange.
//!
//! ```text
//! head -c 32 /dev/urandom | base64 > secret
//! chmod 600 secret
//! ```
//!
//! **The secret is both machines' identity**, with no revocation short of replacing it on both.
//! Hence a loose file mode being a hard error rather than a warning.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Changing either string changes every derived key; the version suffix makes that deliberate.
const SERVER_INFO: &[u8] = b"needlecast server key v1";
const CLIENT_INFO: &[u8] = b"needlecast client key v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Server,
    Client,
}

impl Role {
    fn info(self) -> &'static [u8] {
        match self {
            Role::Server => SERVER_INFO,
            Role::Client => CLIENT_INFO,
        }
    }

    pub fn peer(self) -> Role {
        match self {
            Role::Server => Role::Client,
            Role::Client => Role::Server,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Client => "client",
        }
    }
}

pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    /// WireGuard's own encoding, so it compares directly against `wg show`.
    pub fn public_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public)
    }
}

/// No `Debug`: a stray `{:?}` would put a private key in a log.
pub struct Identity {
    pub role: Role,
    pub own: KeyPair,
    pub peer: KeyPair,
}

impl Identity {
    pub fn load(path: &Path, role: Role) -> Result<Self> {
        let secret = read_secret(path)?;
        Ok(Self::derive(&secret, role))
    }

    pub fn derive(secret: &[u8], role: Role) -> Self {
        Identity {
            role,
            own: keypair(secret, role),
            peer: keypair(secret, role.peer()),
        }
    }
}

fn keypair(secret: &[u8], role: Role) -> KeyPair {
    // No salt: the secret is already 32 bytes of real randomness, and any salt would have to come
    // from the same file anyway.
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut private = [0u8; 32];
    hk.expand(role.info(), &mut private)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    // X25519 clamps on derivation, as WireGuard does, so this matches `wg pubkey` byte for byte.
    let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
    KeyPair { private, public }
}

/// Trailing whitespace is trimmed so the `base64 > secret` recipe works whether or not the shell
/// left a newline.
fn read_secret(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading the secret at {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {mode:04o}: it is readable by someone other than its owner, and it is \
             both machines' identity. Run `chmod 600 {}`.",
            path.display(),
            path.display()
        );
    }

    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let trimmed = trim_trailing_ascii_whitespace(&raw);
    if trimmed.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(trimmed.to_vec())
}

fn trim_trailing_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"gCPmMEnG3ZucCkC2gzcTGKvIETyufAJXWr6zJVCKk4Q=";

    /// Cross-checked against an independent HKDF-SHA256 implementation and the real `wg pubkey`.
    /// Regenerating these rather than fixing a failure silently unlocks the lock; treat a mismatch
    /// as a protocol change needing both machines upgraded.
    const SERVER_PUBLIC: &str = "ZVnbvcoGI3M2tQwGjUgMjlpUh7hRAZ6ve0/6iCJ0Y3Y=";
    const CLIENT_PUBLIC: &str = "quNwuLJbIui3Quc9cqyXZEbtE22/YzLyou6PbbhKw1I=";

    #[test]
    fn derivation_is_stable() {
        let id = Identity::derive(SECRET, Role::Server);
        assert_eq!(id.own.public_base64(), SERVER_PUBLIC);
        assert_eq!(id.peer.public_base64(), CLIENT_PUBLIC);
    }

    #[test]
    fn both_sides_derive_the_same_pair_and_keep_opposite_halves() {
        let server = Identity::derive(SECRET, Role::Server);
        let client = Identity::derive(SECRET, Role::Client);

        assert_eq!(server.own.public, client.peer.public);
        assert_eq!(client.own.public, server.peer.public);
        assert_eq!(server.own.private, client.peer.private);
    }

    #[test]
    fn the_two_roles_get_different_keys() {
        let id = Identity::derive(SECRET, Role::Server);
        assert_ne!(id.own.private, id.peer.private);
        assert_ne!(id.own.public, id.peer.public);
    }

    #[test]
    fn a_different_secret_gives_different_keys() {
        let a = Identity::derive(b"one", Role::Server);
        let b = Identity::derive(b"two", Role::Server);
        assert_ne!(a.own.public, b.own.public);
    }

    #[test]
    fn peer_is_an_involution() {
        assert_eq!(Role::Server.peer(), Role::Client);
        assert_eq!(Role::Client.peer(), Role::Server);
        assert_eq!(Role::Server.peer().peer(), Role::Server);
    }

    #[test]
    fn trailing_whitespace_does_not_change_the_identity() {
        let bare = Identity::derive(SECRET, Role::Server);
        for suffix in [b"\n".as_slice(), b"\r\n", b"  \n\n", b"\t"] {
            let mut padded = SECRET.to_vec();
            padded.extend_from_slice(suffix);
            let trimmed = trim_trailing_ascii_whitespace(&padded);
            let derived = Identity::derive(trimmed, Role::Server);
            assert_eq!(
                derived.own.public, bare.own.public,
                "a {suffix:?} suffix changed the key"
            );
        }
    }

    /// Unlike trailing, leading whitespace is part of a chosen secret rather than an artefact of
    /// how the file was written.
    #[test]
    fn leading_whitespace_is_significant() {
        let mut led = b" ".to_vec();
        led.extend_from_slice(SECRET);
        assert_eq!(trim_trailing_ascii_whitespace(&led), led.as_slice());
    }

    #[test]
    fn public_key_is_wireguard_base64() {
        let id = Identity::derive(SECRET, Role::Client);
        let encoded = id.own.public_base64();
        assert_eq!(encoded.len(), 44, "32 bytes base64 with padding");
        assert!(encoded.ends_with('='));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("round trips");
        assert_eq!(decoded, id.own.public);
    }

    mod files {
        use super::*;
        use std::io::Write;

        fn write_secret(dir: &Path, name: &str, contents: &[u8], mode: u32) -> std::path::PathBuf {
            let path = dir.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(contents).unwrap();
            drop(f);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }

        fn tmpdir(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("needlecast-identity-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// `Identity` has no `Debug`, so `expect_err` is unavailable.
        fn refusal(r: Result<Identity>, what: &str) -> anyhow::Error {
            match r {
                Ok(_) => panic!("{what} should have been refused"),
                Err(e) => e,
            }
        }

        #[test]
        fn a_well_permissioned_file_loads() {
            let dir = tmpdir("ok");
            let path = write_secret(&dir, "secret", b"abcdefgh\n", 0o600);
            let id = Identity::load(&path, Role::Server).expect("loads");
            assert_eq!(
                id.own.public,
                Identity::derive(b"abcdefgh", Role::Server).own.public
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_group_or_world_readable_file_is_refused() {
            let dir = tmpdir("perm");
            for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o744] {
                let path = write_secret(&dir, "secret", b"abcdefgh", mode);
                let err = refusal(
                    Identity::load(&path, Role::Server),
                    &format!("mode {mode:04o}"),
                );
                assert!(
                    err.to_string()
                        .contains("readable by someone other than its owner"),
                    "mode {mode:04o}: {err}"
                );
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn an_empty_file_is_refused_rather_than_deriving_from_nothing() {
            let dir = tmpdir("empty");
            for contents in [b"".as_slice(), b"\n", b"   \n\t"] {
                let path = write_secret(&dir, "secret", contents, 0o600);
                let err = refusal(Identity::load(&path, Role::Server), "an empty secret");
                assert!(err.to_string().contains("is empty"), "{err}");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_missing_file_names_itself_in_the_error() {
            let path = Path::new("/nonexistent/needlecast/secret");
            let err = refusal(Identity::load(path, Role::Server), "a missing secret");
            assert!(
                err.to_string().contains("/nonexistent/needlecast/secret"),
                "{err}"
            );
        }
    }
}
