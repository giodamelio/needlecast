# Root shell on either demo machine, once `nix run .#demo` has booted them.
#
#     nix run .#demo-ssh -- client
#     nix run .#demo-ssh -- server curl -sf http://localhost:8080/hello.txt
#
# The ports, the key and the `ssh` binary are substituted in above by nix.
def main [
  machine: string = "client" # `server` or `client`
  ...command: string # run this instead of opening a shell
] {
  let port = match $machine {
    "server" => $SERVER_PORT,
    "client" => $CLIENT_PORT,
    _ => {
      print -e $"unknown machine ($machine): expected `server` or `client`"
      exit 2
    }
  }

  # The key lives in the store and is therefore world-readable, which `ssh` refuses.
  let key = (mktemp -t needlecast-demo-key.XXXXXX | str trim)
  ^install -m600 $KEY_SOURCE $key

  # The machines are thrown away with the driver, so pinning their host keys would only produce a
  # warning to ignore on the next boot.
  #
  # The status is taken explicitly rather than left to propagate, because an unhandled failure
  # would skip the cleanup below and leave the key behind.
  let status = (
    try {
      ^$SSH -i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p $port root@localhost ...$command
      0
    } catch {|e| $e.exit_code | default 1 }
  )

  rm -f $key
  exit $status
}
