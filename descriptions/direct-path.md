# Direct path beside the SG relay

App bytes still have a path through a server-grade node. This note adds a second path, direct UDP between the two nodes, used only after a probe round trip shows the other side received a packet.

`format_version` stays 2. An older node drops an opcode it does not know and keeps relaying. A direct path works only when both ends and the coordinating SG run this build. Observed addresses and the unstable flag are memory on the node. They are not a directory snapshot.

## What a send proves

A UDP send means the local stack accepted the datagram. It does not mean the peer received it. Each direct path has its own probe and probe answer. The path is up only after the answer. It goes cold when the next answer is late. A cold path is dropped. The next app packet uses the SG, and that packet may start a new direct attempt.

When a node's own address changes, or a direct send fails, that node tells its rank-1 SG in the same turn with op `0x1C`. The rank-1 SG tells the other connected peers. Each receiver drops the LAN path and the punch path for that device without waiting for the probe time-to-live. The app packet still uses the relay. After that down period, the next packet through the SG may try the direct path again.

Apps are not asked to report receipt. The node probes.

## Path order

1. The first app packet for a peer goes through the SG. The SG stores the UDP source address it saw for the sender. When that address is new or has changed, it sends the observation on the existing session to the destination and, when that is a different node, to the sender's rank-1 SG. A repeat of the same address is not sent again. The app packet still uses the relay.
2. Each node also reads its own private IPv4 addresses and tells its rank-1 SG (op `0x1F`). Rank-1 tells the other connected peers. On a later packet, if any reported or observed pair shares a private /24, each side sends a LAN probe (op `0x17`) to that matching address and answers with op `0x18`. A shared LAN address wins over the address the SG saw, so two machines on one network still match when one of them reached the SG through a VPN or a public address. The path is up only after the answer comes from the address that was probed. Until then the app packet still goes through the SG. The receiver answers a probe when its source shares a private /24 with an address that receiver reported, not only with the address the server saw. The address list is sent again on each five-minute pass. A probe that was not answered is sent again on that pass. A path that is already up is not probed again until its check fails. An older node drops `0x1F`. A target whose route goes out `pnetlan` is not probed and is not used for an app packet. That overlay address is reached only by asking pNet to send, so a direct datagram there would loop. The app packet stays on the SG, or on the punch when that probe is up.
3. After the LAN answer, a grade that wants speed sends on the LAN.
4. If the ranges do not match, the app packet stays on the SG. Once the SG has seen both addresses, it sends each side one punch invite (op `0x19`) naming the other's address. Each side sends a punch datagram (op `0x1A`) and answers with op `0x1B`. The punch is up only after that answer comes from the stored address, and only while the LAN path is down. A repeat invite is not sent for the same pair. A failed LAN probe on a private range does not punch; those packets stay on the SG.
5. After the punch answer, a stable peer's app packet is sealed with the two devices' static X25519 keys (op `0x1E`) and sent to the observed address. The server relay packet is not reused. If the peer's key is missing, the packet stays on the SG. An older node drops `0x1E`.

One peer has one live direct path. LAN wins when its probe is up. Otherwise the punch wins when its probe is up. Otherwise the SG.

Private ranges are the three IPv4 blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. Two addresses match when both are private and the first three octets are the same. `192.168.1.0/24` and `192.168.50.0/24` do not match, so those peers skip the LAN probe and hole-punch. A public address matches neither, so two nodes seen only by their public addresses skip the LAN and use the punch.

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
