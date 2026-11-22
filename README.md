# gsb: gVisor-style syscall redirection on FreeBSD (PoC)

*gsb* stands for **g**Visor-style **s**andbox on **B**SD. It is an independent experiment, not affiliated with or endorsed by the gVisor project.

This is a proof of concept for running Linux binaries on FreeBSD under a **user-space kernel** in the style of gVisor's Sentry. A small FreeBSD kernel module (`gsb.ko`) turns every syscall a sandboxed process makes into a `SIGSYS`, and a user-space process answers it. The app's syscalls never reach a host syscall implementation. The goal is a two-layer boundary: an escape needs a bug in the user-space kernel **and** a bug in the host kernel.

The repository contains:

- **`kmod/gsb/`**: the redirection module, plus a freestanding test stub and a test suite covering the bypass vectors.
- **`spike/`**: a minimal C "Sentry" that serves a Linux app's syscalls over shared memory, with latency measurements.
- **`lima/`**: a FreeBSD 15.1 amd64 development VM for macOS.

It is not a sandbox you can use yet. This repository holds the kernel-side mechanism and a minimal user-space counterpart that show the design works. The port of gVisor's Sentry itself is in progress separately (see [Sentry port](#sentry-port)).

Target: FreeBSD 15.1-RELEASE, amd64.

## How it works

```
  stub process (FreeBSD, GSB ABI)                     Sentry (user space)
 ┌───────────────────────────────────────┐          ┌─────────────────────┐
 │ app code ──syscall──┐                 │          │                     │
 │                     ▼                 │  shared  │  handle syscall,    │
 │            SIGSYS handler (stub) ─────┼──memory─►│  write result       │
 │                     │◄────────────────┼──────────┤                     │
 │            sigreturn → app            │ _umtx_op └─────────────────────┘
 └─────────────────────┬─────────────────┘
          every syscall│
                       ▼
     gsb.ko: sysentvec → SIGSYS (only allowlisted stub calls pass through)
```

- **Brand.** The stub is a static ELF with a private `GSB` note and `EI_OSABI=255`. `gsb.ko` registers an ELF brand that matches only that note. Without the module loaded the stub **fails to exec**, so it never falls back to running as a normal FreeBSD process.
- **One choke point.** The module's `sv_fetch_syscall_args` sees every syscall entry, both `syscall` and `int 0x80`. By default it sends a synchronous `SIGSYS` with the syscall number in `si_trapno`, and never runs a host implementation.
- **Passthrough is narrow.** A FreeBSD syscall reaches the host only if **all** of these hold:
  1. The thread is in *stub mode*. This is a per-thread kernel flag that only a passthrough `sigreturn` clears (the only way into app code) and only signal delivery sets.
  2. `%rip` is inside the stub's text segment.
  3. The instruction is `syscall` (`0f 05`).
  4. The call is one of 17 allowlisted calls and passes argument checks. For example, `mmap`/`mprotect`/`munmap` cannot touch stub text, and signal handlers and thread entry points must be stub code.

  App code always runs outside stub mode, so jumping into the stub's `syscall` instruction does not help.
- **Linux register semantics.** Before building the signal frame, the module restores `r10` (the 4th argument), `rcx=rip` and `r11=rflags`. FreeBSD's syscall entry doesn't save these the way Linux expects.
- **Observability.** DTrace probes `gsb:::{redirect,passthrough,deny,tostub,toapp}`, and counters under `sysctl security.gsb`.

## Quick start

### Dev VM (macOS)

Requires [Lima](https://lima-vm.io) 2.1 or later and QEMU (`brew install qemu`). On Apple Silicon the guest is emulated: fine for functional and security tests, but take latency numbers on real amd64 hardware.

```sh
limactl create --name=gsb-dev --mount-only "$PWD:w" lima/gsb-dev.yaml
limactl start gsb-dev
limactl shell gsb-dev sudo sh "$PWD/lima/setup.sh"   # pkg, /usr/src, dtrace
limactl shell gsb-dev                                 # repo is at the same path
```

On a native FreeBSD 15.1 amd64 machine, you only need `/usr/src`.

### Build and test the module

```sh
(cd kmod/gsb       && MAKEOBJDIR=/tmp/gsbobj  make)
(cd kmod/gsb/tests && MAKEOBJDIR=/tmp/gsbtest make)
sudo sh kmod/gsb/tests/run_tests.sh /tmp/gsbobj/gsb.ko /tmp/gsbtest/gsbstub
```

The test script unloads and reloads `gsb.ko` itself, because T0 checks that the stub refuses to run without it.

| Test | Checks |
|---|---|
| T0 | stub cannot exec without `gsb.ko` (fail closed) |
| T1, T12 | app `syscall` is redirected and the user-space result is returned |
| T2 | `int 0x80` is redirected |
| T3 | app jumping to the stub's `syscall` instruction is redirected |
| T4, T5 | `sysenter` and the vsyscall page fault instead of making a syscall |
| T6 | stub-mode syscall from outside stub text is redirected |
| T7, T8, T10 | stub text cannot be remapped; handlers and threads must start in stub text |
| T9 | no `SIGSYS` handler means the process is killed |
| T11 | `r10`/`rcx`/`r11` follow Linux semantics |
| T13, T14 | process runs as `GSB ELF64` with the osrel from the note |

### Round-trip spike

With `gsb.ko` loaded:

```sh
(cd spike && MAKEOBJDIR=/tmp/spike make)
/tmp/spike/sentry -n 20000 -r 5 /tmp/spike/spike_stub
/tmp/spike/native_sigsys 20000      # stock FreeBSD SIGSYS round trip, for comparison
```

`sentry` reports per-call latency for four paths:

- native `getpid`;
- the redirect answered inside the stub (the kernel floor);
- the full round trip through the Sentry, with spinning;
- the same round trip with sleep/wake only.

In an emulated VM, the redirect cost matched FreeBSD's own `SIGSYS` delivery: the module adds no measurable overhead. The shared-memory hand-off added about 5% when both sides spin briefly before sleeping.

## Sentry port

The FreeBSD port of gVisor's Sentry lives in a fork: [`moterech/gvisor`, branch `freebsd`](https://github.com/moterech/gvisor/tree/freebsd). It is based on upstream's `go` branch at `release-20261116.0`.

**Done:**
- **Host layer:** kqueue replaces epoll, `_umtx_op` replaces futex, and `shm_open2(SHM_ANON)` replaces memfd. `safecopy`'s fault handler uses FreeBSD `ucontext` offsets. Host errnos are translated from FreeBSD numbering, and the socket and file I/O paths are ported.
- **File layer:**
  - the Sentry's gofer and host filesystems;
  - the lisafs protocol;
  - the Gofer server itself. It uses `statx` emulated on `fstatat`, `O_EMPTY_PATH`/`AT_EMPTY_PATH` instead of `/proc/self/fd`, and a no-symlink component walk instead of `openat2`.
- **Tests:** `test/freebsd/porttest` plus FreeBSD-only tests in the gofer packages run these primitives against a real FreeBSD kernel.

- **Platform:** `bsdtrap`, the counterpart of gVisor's systrap. It drives app threads in stub processes under `gsb.ko`, converts FreeBSD `mcontext`/XSAVE state to and from Linux registers, and derives fault access types from the page-fault error code. Its tests run hand-assembled Linux code through the real kernel module. One syscall round trip takes about 36 µs in the emulated dev VM, about 1.2× FreeBSD's own SIGSYS delivery cost there.

- **First light:** `cmd/gsb-sentry` boots a minimal Sentry on `bsdtrap` and runs an unmodified, static Linux/amd64 Go binary to completion. That covers runtime start-up, threads, futexes, signals, `getpid` and `write`. In that run, `gsb.ko` redirected all 613 app syscalls, and DTrace showed the stub reaching only allowlisted host calls.

  ```sh
  # on the host (gvisor fork, branch freebsd)
  GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -ldflags=-checklinkname=0 ./cmd/gsb-sentry
  # in the VM, with gsb.ko loaded and the stub installed (pkg/sentry/platform/bsdtrap/stub)
  ./gsb-sentry ./hello-linux     # a GOOS=linux static binary
  ```

**Not done yet:**
- **Root filesystem:** a lisafs Gofer root, so dynamically linked binaries (busybox, python3) can load their libraries.
- **Confinement:** Capsicum and jail.
- **Launcher:** a proper launcher.

Host TTYs are still imported as plain character devices until a termios translation exists.

## Known limitations

- amd64 only, and built and tested against 15.1-RELEASE only.
- The stub/app flag uses a spare `td_pflags2` bit, which is specific to this kernel release.
- Signals must stay blocked while the stub is in stub mode. The stub enforces this through `sa_mask`, not the kernel. If it fails, the process crashes rather than escaping.
- Wrapped passthrough calls (`mmap`, `sigaction`, `sigreturn`, …) show up in `gsb:::passthrough` but not in DTrace's `syscall:freebsd::` provider.
- The FreeBSD shared page and vdso sit at the top of the user address space. A full Sentry must treat that range as reserved.

## Licence

Apache License 2.0; see [LICENSE](LICENSE).
