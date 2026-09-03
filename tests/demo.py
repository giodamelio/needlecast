start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

server.wait_for_unit("devserver.service")
server.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8080'", timeout=30)

server.wait_for_unit("needlecast-server.service")
client.wait_for_unit("needlecast-client.service")
client.wait_until_succeeds(
    "needlecast status --role client | grep -q 'state=connected'", timeout=90
)

# The whole point, in one line.
got = client.succeed("curl -sf http://localhost:8080/hello.txt").strip()
print(f"client curled localhost:8080 and got: {got}")
assert got == "hello from the other machine", got

print(client.succeed("needlecast status"))
print(server.succeed("needlecast status"))

# Asserted rather than documented, or it rots silently.
for m in (server, client):
    m.wait_for_open_port(22)

print(
    "to poke at this:  nix run .#demo  then  start_all()\n"
    "  nix run .#demo-ssh -- client    # or `server`; key-only, no password\n"
    "  or, in the driver:  client.shell_interact()"
)
