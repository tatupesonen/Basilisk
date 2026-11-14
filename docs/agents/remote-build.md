# Track `remote-build`: the Linux build host

Status: in progress.

The project has a dedicated x86-64 Linux machine for heavy work (a QEMU
virtual machine: 20 cores, 32 GB memory, about 430 GB free disk, Debian 13).
`scripts/remote.sh` makes it the build host: it sends a worktree's committed
`HEAD` there and runs the gate or any command in a per-branch checkout.
No host name, user or key is in the repository; see Configuration.

## Done / in progress / next

- [ ] `scripts/remote.sh` and the setup on the machine
- [ ] Reference tools checked / rebuilt into `~/bk/reference`
- [ ] Gate on Linux x86-64, cold and warm, with and without the reference
- [ ] Build-output decision (per-branch or shared `target/`)
- [ ] `bk-cspec` oracle table regenerated on Linux and compared
- [ ] `bk-sleigh` thread scaling at 1–16 threads
