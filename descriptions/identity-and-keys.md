# Identity and keys

The user public key is the user. A device key is a device. An app key is an app. Each layer signs the next one. UUIDs stay local indexes for routing and storage. They are not inside a certificate.

This tree uses Ed25519 for the user certificate. The earlier notes named Ed448. Ed25519 stays because contact cards, connect signatures, and the rest of this fabric are already 32-byte Ed25519. Moving the user key to Ed448 would be a separate wire break. The custody rules below are the part that changes who can mint a device.

## Chain

- The user key is self-signed. The signed payload is a domain tag, version, issued-at, expires-at (`0` means none), the alias, and the user public key.
- That user key signs a device certificate: device Ed25519 signing key, device X25519 static key, alias, issuer public key.
- The device signing key signs an app certificate: app Ed25519 public key, alias, issuer (the device signing key).
- `cert_alias` is the alias that was signed. A later rename of the display alias does not invalidate the certificate.
- ConnectRequest and ConnectAck are signed by the device signing key. The peer accepts the signature when that device's stored certificate verifies under the user public key it already knows (the owner, or a contact). A removed device's certificate is gone, so a kept device key cannot authenticate as a different device.

## Who holds the user private key

The first server creates the user key and seals it. An ordinary device invitation does not copy that seed. The new device proves it holds its own signing key, the server signs a device certificate, and the joiner stores the user public certificate.

The device-invitation form has a checkbox: "this device is a server and may enroll other devices". When it is checked, and this node actually holds the user private key, bootstrap includes the raw seed once. The joiner seals it with its own passphrase and can then sign further device certificates. A phone cannot tick itself into that role. A device-grade peer also cannot set the flag by asking a server over the invitation-mint request. Joining as server-grade without the checkbox lets that server relay. It does not let it mint device certificates.

A server that already holds the user seed can still mint certificates. That is the enrollment-issuer case, not a stolen phone.

## Lost device

From Config → Devices, the owner removes a device they no longer have. That publishes `RemoveDevice`. The device and its certificate leave the directory, open sessions to it are dropped, and a later add of the same device uuid loses to the tombstone. Peers reject a connect signature from that device.

The device serving the page cannot remove itself. Use another device that is still in the mesh.

The removed install cannot rejoin. Uninstall pNet on it and set it up again with a new invitation, which mints a new device uuid and a new certificate.

What to do when a server is destroyed, or the user private key itself is lost, is still an open choice. Removing a device does not rotate the user key. A device that was given that seed can still sign certificates until the key is replaced.

## At rest

One module, `keystore`, seals secrets. The envelope is versioned: Argon2id parameters, salt, and an XChaCha20-Poly1305 ciphertext. Production parameters are 64 MiB, 3 iterations, parallelism 1. The derived key is cached for the process so a save does not run Argon2id again.

The passphrase comes from `PNET_KEY_PASSPHRASE` or a prompt on the controlling terminal, and from the setup form when neither is set yet. Minimum length is 8 characters. It is not the admin password. The admin password remains a salted hash for the web UI.

The threat model is a stolen disk. A root user or a memory dump still sees the unsealed keys.

`node.toml` stores `private_key_sealed` for the user seed and for any app seed this device generated. It does not store the raw Ed25519 seed. The device signing seed and the static X25519 secret share `device_secrets_sealed`. Invitation X25519 secrets stay with the invitation, on the server that minted it.

A file written by an older build may still contain a plaintext user seed. Load keeps it, and the next save wraps it. If a sealed blob is present and does not open, the process exits rather than running with an empty seed. A joiner that was never given the user seed has an empty seal and a zero private key next to a real public key. That is not a failure.

## Apps

Registration may include the app's Ed25519 public key. If it does, the app keeps the private key. If it does not, this device generates the key when the app is approved and seals the seed. The certificate is signed at approval (or immediately when `PNET_AUTO_APPROVE_APPS` is set), not when the app merely registers. Approval is still what lets the app send traffic. The register acknowledgement stays 17 bytes: status plus token.
