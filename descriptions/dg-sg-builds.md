# Two pNet builds: device and server

**Status:** plan. Not implemented. The running nodes are still one `pnet` binary.

pNet ships two programs from one library. `pnet-dg` is the device. It joins with a connection code and has no website. `pnet-sg` is the server. It serves the portal, and that portal approves apps for every device. The installed path stays `bin/pnet`, so `start.sh` and systemd do not change.

Three steps, each a pull request into `develop`. sanosuke and tealface are already joined; this does not ask them for a new code and does not wipe `node.env` or `data/`.

## Step 1 — device build and server build

Today one binary, `src/main.rs`, starts the portal for every grade. Grade is only a runtime value.

After this step the package has two bins and a library feature:

- `pnet-dg` from `src/main.rs`, feature `sg` off. The HTTP server, portal pages, and app mounts are not in this binary.
- `pnet-sg` from `src/main.rs`, feature `sg` on. This binary starts the portal.
- `cargo build --release --bin pnet-dg` and `cargo build --release --features sg --bin pnet-sg` are the two release commands. `scripts/release-assets.sh` grows a pack step that puts both files in the archive. The archive no longer contains a single file named `pnet`.
- `--version` prints `pnet-dg <version>` or `pnet-sg <version>`.

Behavior:

- The device build never listens on 8777. It cannot create a user. Setup is `PNET_GRADE=dg`, `PNET_DEVICE_ALIAS`, `PNET_INVITATION_CODE`, and `PNET_KEY_PASSPHRASE`. A device process that is not initialized and has no connection code exits. An initialized device keeps running. The key passphrase still unseals keys. A new device does not ask for an admin password.
- The server build starts the portal. New-user setup stays on this build only.
- If the binary does not match the grade already stored on the node, the process exits and says which build it is. A device build does not run a server node, and a server build does not run a device node.

The release format change waits for step 2. Until that release, `releases/latest` is still the single-file archive.

Tests: the device binary has no HTTP listener; the server binary still binds 8777; a device without a code does not create a user; starting the wrong build for the stored grade exits.

Repo: `pNet`. Pull request into `develop`.

## Step 2 — the installer picks the build

`pnet_installer` today unpacks only a tar member named `pnet` (`src/bootstrap.rs`, `src/release.rs`).

After this step:

- A new archive may contain `pnet-dg` and `pnet-sg`. The installer copies one of them to `prefix/bin/pnet`.
- An older archive that contains only `pnet` still installs, so the current published release keeps working.
- When `node.env` already exists, `PNET_GRADE` in that file chooses the build. Setup flags do not override it, and the file is still not rewritten. The installer reads the grade and does not print the file.
- A new node uses `--grade`. Device grade still requires a connection code. A fresh device bootstrap without that code does not start `pnet` and does not write `node.env`.
- The device message says this node has no website and that apps are approved on a server portal.

Repo: `pnet_installer`. Pull request into `develop`. This can merge before the pNet release that ships both files. It must be the installer in use when that release is published. The published installer itself is not a GitHub Release; the binary William runs is the one that understands both archives.

## Step 3 — approve a device's app from the server

Registration on a device stays local until someone approves it. The server does not hold the device signing key, so it cannot sign the app certificate. A directory pull also does not update an app the device already has: that copy keeps `user_approved`, the token, and the host.

### What the server stores

A separate owner list, not a public app. Contacts do not receive it. Append it after the policy block in `serialize_public_state`. A reader that stops at the policy block leaves the tail unread.

Each pending row: device id, app id, alias, protocol, and the app public key when the app supplied one. The device alias and grade are already on the enrolled device. The token, the app private key, the device signing key, and the loopback host stay on the device.

Each decision row: device id, app id, and approved or rejected.

New `Change` values carry those rows through the writer. `format_version` stays 2. New on-disk fields use serde defaults.

### What the device build does

On register, the device saves the app with `user_approved` false, returns the token, and publishes the pending row. If the writer rejects that publish, registration still succeeds and the device retries. The app cannot send until it is approved.

On startup, the device publishes a pending row for each local app that is still unapproved.

When a pull applies an approval, the device mints a key if needed, signs with the device key, sets `user_approved`, publishes `AddApplication`, and drops the pending row and the decision. A reject deletes the local app and drops the pending row. The server portal does not call `issue_app_cert` for another device.

### The page

`/pending-apps` on the server build lists this server's own unapproved apps and every other own device's pending rows, with device alias and grade. Approve and Reject post the device id and the app id.

After Approve, the row stays as waiting until `AddApplication` arrives with a certificate. Until that device pulls the decision, the app still cannot send. Reject removes the row once the pending record is gone. An offline device keeps the decision on the writer until it pulls.

The public app list and the contact directory still include approved apps only.

### Tests

- A device registration produces a pending row on the writer and no public app card.
- Approve records the decision; the device build then publishes a certificate that verifies under its device key, and the row leaves the pending list.
- Reject deletes the app on the device and publishes nothing a contact can see.
- A snapshot with the new tail still parses, and a snapshot without the tail still parses.
- Token and host on the device are unchanged by the pull.

Repo: `pNet`. Pull request into `develop`.

## Rollout

Step 1 and step 2 land before the release that contains both binaries. Until that tag, bootstrap still installs the single `pnet` from `v0.2.1`.

Publish the two-build release only when step 3 is merged and every server this user runs will move to it before any device publishes a pending row. An older writer rejects the new change. A device on the older build never applies the decision, so the page stays on waiting. Contacts on the previous version still pull the directory, because the new bytes sit after the policy block.

The wire record for that tag says own servers upgrade before any pending-app change is written. `bin/pnet` on a device must be the device build, and on a server the server build. This plan does not tag or publish that release.
