# Direct path beside the SG relay

App bytes still have a path through a server-grade node. This note adds a second path, direct UDP between the two nodes, used only after a probe round trip shows the other side received a packet.

`format_version` stays 2. An older node drops an opcode it does not know and keeps relaying. A direct path works only when both ends and the coordinating SG run this build. Observed addresses and the unstable flag are memory on the node. They are not a directory snapshot.

## What a send proves

A UDP send means the local stack accepted the datagram. It does not mean the peer received it. Each direct path has its own probe and probe answer. The path is up only after the answer. It goes cold when the next answer is late. A cold path is dropped. The next app packet uses the SG, and that packet may start a new direct attempt.

When a node's own address changes, or a direct send fails, that node tells its rank-1 SG in the same turn with op `0x1C`. The rank-1 SG tells the other connected peers. Each receiver drops the LAN path and the punch path for that device without waiting for the probe time-to-live. The app packet still uses the relay. After that down period, the next packet through the SG may try the direct path again.

Apps are not asked to report receipt. The node probes.

## Path order

1. The first app packet for a peer goes through the SG. The SG stores the UDP source address it saw for the sender. When that address is new or has changed, it sends the observation on the existing session to the destination and, when that is a different node, to the sender's rank-1 SG. A repeat of the same address is not sent again. The app packet still uses the relay.
2. On a later packet, if both observed addresses are private and in the same range, each side sends a LAN probe (op `0x17`) to the other's observed address and answers with op `0x18`. The sender is also told the address the SG saw, so it can make that comparison. The path is up only after the answer comes from that stored address. Until then the app packet still goes through the SG. A second probe is not sent while one is outstanding.
3. After the LAN answer, a grade that wants speed sends on the LAN.
4. If the ranges do not match, the app packet stays on the SG. Once the SG has seen both addresses, it sends each side one punch invite (op `0x19`) naming the other's address. Each side sends a punch datagram (op `0x1A`) and answers with op `0x1B`. The punch is up only after that answer comes from the stored address, and only while the LAN path is down. A repeat invite is not sent for the same pair. A failed LAN probe on a private range does not punch; those packets stay on the SG.
5. After the punch answer, speed-seeking packets use the punch. If the punch is not answered, packets stay on the SG.

One peer has one live direct path. LAN wins when its probe is up. Otherwise the punch wins when its probe is up. Otherwise the SG.

Private ranges are the three IPv4 blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. Two addresses match when both fall in the same one of those blocks. A public address matches neither, so two nodes seen only by their public addresses skip the LAN and use the punch.

## Grades

The app names a grade on send. Omitted or unknown means stable.

| Grade | Path |
| --- | --- |
| stable | SG only. No LAN probe and no punch. |
| fast | LAN if up, else punch if up, else SG. Try to bring a direct path up. |
| cellphone | Same order as fast, with a shorter probe time-to-live, and no direct path while the peer is marked unstable. |

## Unstable

The node keeps the last three timestamps of its own address changes. Three changes inside five minutes, with the newest still inside those five minutes, marks the node unstable. A maintenance pass every five minutes (the same cadence as `MaintainConnections`) clears the flag when the window no longer holds. While the flag is set, cellphone traffic stays on the SG. Fast and stable ignore the flag. When the flag changes, the node tells its rank-1 SG with op `0x1D`. Rank-1 tells the other connected peers. A peer that hears the flag keeps cellphone traffic for that device on the relay.

## Time-to-live

A LAN path stays up after its probe answer until an address-change or link-down notice. Time alone does not drop it.

A punch path stays up for 30 seconds after its probe answer when the send is fast, and for 10 seconds when the send is cellphone. App packets do not move that deadline. When it passes, the next send uses the relay. A later punch answer starts the deadline again. A notify drops either path immediately.

## Later: device status

Do this after the direct-path work above is finished. pNet should be able to say whether a device is reachable. An app send stays fire-and-forget. The status is separate from that send.

A time-to-live does not mean the other machine is off. It means the last proof is old, so the next app packet uses the relay. That packet does not, by itself, start a new check.

A LAN path stays up until an address-change or link-down notice. It does not expire just because time passed. A punch path keeps a short deadline, because the mapping can die while both machines are still on.

Reachability is a probe answer. After a quiet period, or after a punch deadline, the next send starts that probe again. No answer means pNet marks the device unreachable. An answer marks it reachable and starts the direct path again when the grade wants one. A powered-off machine sends no notice, so this missed answer is the only signal. The app is not told unless it asks pNet for the status.
