# pkthere forwarder

Single-client L4 forwarder for UDP and ICMP (IPv4/IPv6) with a configurable idle timeout.<br>
Bind once, drop privileges, and forward traffic between a single local client and an upstream host.

- Locks to the first client (SocketAddr) that sends a packet (either UDP or ICMP Echo).
- Forwards client->upstream and upstream->client.
- Uses the listener socket for replies so the client always sees the same source port.
- If no traffic is seen for --timeout-secs (default 10), either:
  - drop: drop the locked client and accept a new one
  - exit: exit the program (status 0)

Protocols and behaviors:

- **UDP**: forwards datagrams unchanged and preserves source ports.
- **ICMP Echo**: adds payload to request/reply, supports both v4 and v6.
- **Connected/unconnected modes**: optional `--debug no-connect` leaves the client socket unconnected for diagnostics.
- **Drop logging**: `--debug log-drops` prints reasons when packets are rejected.
- **Payload limits**: enforce MTU-like behavior with `--max-payload`.
- **Stats**: periodic JSON lines show per-direction byte/packet counts, latency metrics, and the locked client address.

Notable CLI options:

- `--max-payload N` – drop packets larger than `N` bytes.
- `--debug WHAT` – enable debug behavior (`no-connect` and/or `log-drops`).
- `--stats-interval-mins N` – periodic JSON stats interval (0 prints once per second).
- `--user/--group NAME` (Unix) – drop privileges after binding low ports.

Build:

- `cargo build --release`

Run examples:

- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:one.one.one.one:53 --timeout-secs 45 --on-timeout drop`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:[2606:4700:4700::1001]:53 --on-timeout exit`
- `./target/release/pkthere --here ICMP:0.0.0.0:1234 --there ICMP:8.8.8.8:33434 --debug log-drops`

Tests:

- CLI validation: `cargo test --test cli`
- Integration matrix (UDP/ICMP, IPv4/IPv6, connected/unconnected sockets, timeout watchdog, relock behavior): `cargo test --test integration`
- Stress runs: `cargo test --test stress`
