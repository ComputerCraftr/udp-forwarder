# pkthere forwarder

Single-client UDP forwarder (IPv4/IPv6) with configurable idle timeout.<br>
Pure L4 forwarder: unprivileged, no payload parsing.

- Locks to the first client (SocketAddr) that sends a packet.
- Forwards client->upstream and upstream->client.
- Uses the listener socket for replies so the client always sees the same source port.
- If no traffic is seen for --timeout-secs (default 10), either:
  - drop: drop the locked client and accept a new one
  - exit: exit the program (status 0)

Build:

- `cargo build --release`

Run examples:

- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:one.one.one.one:53 --timeout-secs 45 --on-timeout drop`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:[2606:4700:4700::1001]:53 --on-timeout exit`
