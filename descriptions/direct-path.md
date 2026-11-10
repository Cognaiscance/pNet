# Direct path beside the SG relay

App bytes still have a path through a server-grade node. This note adds a second path, direct UDP between the two nodes, used only after a probe round trip shows the other side received a packet.

`format_version` stays 2. An older node drops an opcode it does not know and keeps relaying. A direct path works only when both ends and the coordinating SG run this build. Observed addresses and the unstable flag are memory on the node. They are not a directory snapshot.

## What a send proves

A UDP send means the local stack accepted the datagram. It does not mean the peer received it. Each direct path has its own probe and probe answer. The path is up only after the answer. It goes cold when the next answer is late. A cold path is dropped. The next app packet uses the SG, and that packet may start a new direct attempt.

When a node's own address changes, or a direct send fails, that node tells its rank-1 SG in the same turn with op `0x1C`. The rank-1 SG tells the other connected peers. Each receiver drops the LAN path and the punch path for that device without waiting for the probe time-to-live. The app packet still uses the relay. After that down period, the next packet through the SG may try the direct path again.

Apps are not asked to report receipt. The node probes.

## Path order

1. The app packet goes through the SG until a direct probe has been answered. On that same send, while the packet stays on the SG, the node probes every candidate it already knows: each reported or observed address that is on a connected subnet gets a LAN probe (op `0x17`), and an observed address that is not on a connected subnet gets a punch (op `0x1A`). Each candidate is tried once. The app packet is not held for the answer. When both a LAN path and a punch path are up, the later packet uses the one with the lower probe delay. A missing delay leaves the LAN ahead. When the sender knows the destination device key, the app body is sealed to that device (op `0x1E`) and the server session carries it as op `0x42`: a 48-byte header (`dest device`, `dest app`, `sender app`) plus those sealed bytes. The SG checks the address book and the app grant from the header and the session's device, then forwards the op `0x1E` packet unchanged. It does not open the body. When this SG is the destination, it opens the seal the same way a direct receive does. A sender with no destination key still uses op `0x40`, and the SG still opens that packet and re-seals it as op `0x41`. An older node drops `0x42`. The SG stores the UDP source address it saw for the sender. When that address is new or has changed, it sends the observation on the existing session to the destination and, when that is a different node, to the sender's rank-1 SG. A repeat of the same address is not sent again. The app packet still uses the relay.
2. Each node also reads its own private IPv4 addresses and tells its rank-1 SG (op `0x1F`). Rank-1 tells the other connected peers. On a later packet, a node looks up each reported or observed address in its own routing table. It sends a LAN probe (op `0x17`) when that route is a connected subnet: the route is up, it has no gateway, and the device is not `pnetlan`, `tun`, `wg`, or `tailscale`. The probe is aimed at that address, which may differ from the one the SG saw, so two machines on one network still match when one of them reached the SG through a VPN or a public address. The receiver answers with op `0x18` only when the probe's source is on a connected subnet of its own. The path is up only after the answer comes from the address that was probed. Until then the app packet still goes through the SG. The address list is sent again on each five-minute pass. A probe that was not answered is sent again on that pass. A path that is already up is not probed again until its check fails. An older node drops `0x1F`. A gateway route, and a route out a tunnel device, is not a LAN. The overlay in particular would loop, because `pnetlan` can forward only by asking pNet to send. That app packet stays on the SG, or on the punch when that probe is up.
3. After the LAN answer, a grade that wants speed sends on the LAN.
4. If no reported or observed address is on a connected subnet, the app packet stays on the SG. Once the SG has seen both addresses, it sends each side one punch invite (op `0x19`) naming the other's observed address. The SG does not decide whether the two machines share a LAN. Each side sends a punch datagram (op `0x1A`) only when that peer is not on its own connected subnet, and answers with op `0x1B`. The punch is up only after that answer comes from the stored address, and only while the LAN path is down. A repeat invite is not sent for the same pair. A failed LAN probe does not punch; those packets stay on the SG.
5. After the punch answer, a stable peer's app packet is sealed with the two devices' static X25519 keys (op `0x1E`) and sent to the observed address. The server relay packet is not reused. If the peer's key is missing, the packet stays on the SG. An older node drops `0x1E`.

One peer has one live direct path. LAN wins when its probe is up. Otherwise the punch wins when its probe is up. Otherwise the SG.

A private address is on the LAN when `/proc/net/route` has a matching connected route. The route flag `UP` is set, `GATEWAY` is not, and the device name is not `pnetlan` and does not start with `tun`, `wg`, or `tailscale`. The mask comes from that route, so a real `/23` or `/16` still matches. An address reached through the default gateway does not, and those peers hole-punch. A public address is not a LAN address.

## Grades

The app names a grade on send. Omitted or unknown means stable.

| Grade | Path |
| --- | --- |
| stable | LAN if up, else punch if up, else SG. |
| fast | Same order as stable. |
| cellphone | Same order, with a shorter punch time-to-live. |

An unstable peer, or this node while it is unstable, does not start a LAN probe or a punch, and app packets for that peer stay on the SG. The grade does not override that.

## Unstable

The node keeps the last three timestamps of its own address changes. Three changes inside five minutes, with the newest still inside those five minutes, marks the node unstable. A maintenance pass every five minutes (the same cadence as `MaintainConnections`) clears the flag when the window no longer holds. While the flag is set, that device gets no LAN probe, no punch, and no direct app send. When the flag changes, the node tells its rank-1 SG with op `0x1D`. Rank-1 tells the other connected peers. A peer that hears the flag keeps that device on the relay.

## Time-to-live

A LAN path stays up after its probe answer until an address-change notice, a missed check, or this machine leaves that network. When the server reports that this machine's own address moved, every direct path on this machine drops at once and the next send uses the server. When a reported private address disappears, a LAN path aimed into that range drops on the keepalive pass, about every 20 seconds. The same five-minute maintenance pass sends one LAN probe to each peer whose LAN path is up. The answer clears that check. If the next pass still has no answer, the path drops and the node sends the link-down notice. App traffic does not count as the answer.

A punch path stays up for 30 seconds after its probe answer when the send is fast, and for 10 seconds when the send is cellphone. App packets do not move that deadline. When it passes, the next send uses the relay. A later punch answer starts the deadline again. A notify drops either path immediately.
