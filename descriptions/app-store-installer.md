# Installer

**Status:** decided. The installer is not a pNet app.

`pnet_installer` bootstraps a node onto a machine: it copies a local `pnet`
binary, collects first-run parameters, writes `node.env` and `start.sh`, and
starts pNet. It does not register with the fabric and it does not mount a
portal page.

Apps are added per device, by the person at that device. They start the app
there. The app registers with the local node. That node approves it in
Config → Pending Apps. Approval stays on the device. When two of your devices
are both running the same app, the fabric carries that app's data.

pNet does not fetch packages, does not start app processes, and does not sync
an "install this on these devices" desire. Core stays a pipe.

An earlier design (catalog, desire sync between installer agents, signed
release tarballs, a long-running installer app) is retired. Do not build it.

See `description.md` in the `pnet_installer` repo.
