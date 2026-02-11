# Technical Design

## Overview

This tool lets a local AI agent (Claude Code, Codex, etc.) transparently operate on a remote machine. The agent thinks it's working locally, but file operations go through an sshfs mount and shell commands execute remotely via SSH.

```
┌─────────────────────────────────────────────────────────┐
│  Local Machine                                          │
│                                                         │
│  ┌───────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │   Agent    │───▶│  Bash    │───▶│  Orchestrator    │  │
│  │ (claude /  │    │  Shim    │    │  (Unix socket    │  │
│  │  codex)    │    │ (ELF     │    │   server)        │  │
│  │           │    │  binary)  │    │                  │  │
│  └─────┬─────┘    └──────────┘    └────────┬─────────┘  │
│        │ file ops                           │ ssh        │
│  ┌─────▼──────────────────┐                │            │
│  │  Filter FS (FUSE)      │                │            │
│  │  ├─ blocks private     │                │            │
│  │  │  files (.env, etc.) │                │            │
│  │  └─ passes everything  │         ┌──────▼─────────┐  │
│  │     else through       │         │ SSH Control-   │  │
│  └─────────┬──────────────┘         │ Master (mux)   │  │
│  ┌─────────▼──────────────┐         └──────┬─────────┘  │
│  │  sshfs mount           │                │            │
│  │  (remote / mounted     │                │            │
│  │   locally)             │────────────────┘            │
│  └────────────────────────┘       (same SSH connection) │
└─────────────────────────────────────────────────────────┘
                        │
                        │ SSH (single multiplexed connection)
                        ▼
               ┌─────────────────┐
               │  Remote Machine │
               │  (no agent, no  │
               │   binary, no    │
               │   custom setup) │
               └─────────────────┘
```

## Agent Interception

### Claude Code

Claude Code is cooperative — it respects `$SHELL` and searches `$PATH` when spawning shells. Interception is straightforward:

```
┌──────────────────────────────────────────────────────┐
│  How Claude Code finds bash:                         │
│                                                      │
│  1. Reads $SHELL env var  ──▶  /tmp/shim-bin/bash    │
│  2. Searches $PATH        ──▶  /tmp/shim-bin/bash    │
│                                    │                 │
│  Both resolve to our shim binary.  │                 │
│  No special tricks needed.         ▼                 │
│                              ┌──────────┐            │
│                              │ ELF Shim │            │
│                              │ (our     │            │
│                              │  binary) │            │
│                              └──────────┘            │
└──────────────────────────────────────────────────────┘
```

We prepend our shim directory to `PATH` and set `SHELL` to point at our shim binary. When Claude Code spawns `bash`, it finds our shim first. The shim connects to the orchestrator's Unix socket and forwards the command for remote execution.

The system prompt is injected via `--append-system-prompt`, a native Claude Code flag.

### Codex — The Problem

Codex does **not** respect `$SHELL` or `$PATH` when resolving its shell. Instead:

```
┌──────────────────────────────────────────────────────┐
│  How Codex finds bash (problematic):                 │
│                                                      │
│  1. Calls getpwuid(getuid())                         │
│         │                                            │
│         ▼                                            │
│  2. Reads /etc/passwd ──▶ "andrew:..:/bin/bash"      │
│         │                                            │
│         ▼                                            │
│  3. Calls /bin/bash directly (absolute path)         │
│         │                                            │
│         ▼                  ┌─────────────────────┐   │
│  4. cmd.env_clear()  ───▶  │ Wipes ALL inherited │   │
│                            │ env vars (PATH,     │   │
│                            │ SHELL, our tunnel   │   │
│                            │ socket path, etc.)  │   │
│                            └─────────────────────┘   │
│                                                      │
│  Result: bypasses PATH, ignores $SHELL,              │
│  calls /bin/bash by absolute path, and               │
│  clears our env vars. None of our interception       │
│  works.                                              │
└──────────────────────────────────────────────────────┘
```

Three problems to solve:

1. **Shell resolution**: Codex reads `/etc/passwd` via `getpwuid()` and calls the shell by absolute path (`/bin/bash`). `$SHELL` and `$PATH` are ignored entirely. There is no CLI flag or config option to override the shell path.

2. **Environment clearing**: Codex calls `cmd.env_clear()` before spawning the shell process, wiping all inherited environment variables — including `TUNNELAGENT_SOCK` and `TUNNELAGENT_MOUNT` that our shim needs.

3. **System prompt**: Codex has no `--append-system-prompt` equivalent. Instructions must be injected via config flags.

### Codex — The Solution: User Namespaces

We use Linux user namespaces (`unshare`) to bind-mount our shim binary over `/bin/bash` and `/bin/sh` in a private mount namespace. This is invisible to the rest of the system.

```
┌────────────────────────────────────────────────────────────────────┐
│  Codex Launch Sequence                                            │
│                                                                   │
│  codex (wrapper)                                                  │
│    │                                                              │
│    ├─ 1. Find real codex binary (strip shim dir from PATH)        │
│    ├─ 2. Export TUNNEL_CODEX_BIN, TUNNEL_ORIG_PATH                │
│    │                                                              │
│    └─ 3. exec unshare --user --map-root-user --mount              │
│              │                                                    │
│              ▼                                                    │
│         codex-ns-inner.sh (runs inside new namespace)             │
│              │                                                    │
│              ├─ 4. mount --bind shim /bin/bash                    │
│              ├─    mount --bind shim /usr/bin/bash                │
│              ├─    mount --bind shim /bin/sh                      │
│              ├─    mount --bind shim /usr/bin/sh                  │
│              │                                                    │
│              │     ┌──────────────────────────────────────────┐    │
│              │     │  Inside this namespace:                  │    │
│              │     │                                         │    │
│              │     │  /bin/bash  ──▶ our ELF shim binary     │    │
│              │     │  /bin/sh   ──▶ our ELF shim binary      │    │
│              │     │                                         │    │
│              │     │  Outside this namespace:                 │    │
│              │     │  /bin/bash  ──▶ real bash (unaffected)   │    │
│              │     └──────────────────────────────────────────┘    │
│              │                                                    │
│              └─ 5. exec codex                                     │
│                    --config model_instructions_file="..."          │
│                    --config shell_environment_policy.inherit="all" │
│                    --config shell_environment_policy.set.PATH=...  │
│                    --config shell_environment_policy.set.SHELL=... │
│                    --config shell_environment_policy.set            │
│                             .TUNNELAGENT_SOCK=...                 │
│                    --config shell_environment_policy.set            │
│                             .TUNNELAGENT_MOUNT=...                │
│                                                                   │
│  Now when Codex resolves /bin/bash from /etc/passwd               │
│  and calls it ──▶ it hits our shim binary instead.                │
│                                                                   │
│  shell_environment_policy.set.* forces our env vars               │
│  back through Codex's env_clear() barrier.                        │
└────────────────────────────────────────────────────────────────────┘
```

**Why this works:**

- `unshare --user` creates a new user namespace. `--map-root-user` maps our real UID to root inside the namespace, granting `CAP_SYS_ADMIN` for mount operations.
- `--mount` creates a private mount namespace. Bind mounts inside it are invisible to the host.
- The shim is a **compiled ELF binary**, not a shell script. This avoids shebang loops — if it were `#!/bin/bash`, mounting it over `/bin/bash` would create a circular interpreter chain.
- `shell_environment_policy` is Codex's mechanism for controlling subprocess environments. `inherit="all"` preserves all env vars, and `set.*` forces specific values through `env_clear()`.
- `model_instructions_file` points to a file containing the same tunnel instructions that Claude Code receives via `--append-system-prompt`.

**Why not other approaches:**

| Approach | Why it doesn't work |
|---|---|
| Prepend to `$PATH` | Codex calls `/bin/bash` by absolute path, never searches PATH |
| Set `$SHELL` | Codex reads `/etc/passwd`, ignores `$SHELL` entirely |
| `LD_PRELOAD` to intercept `execve` | Rust's `Command` uses `posix_spawnp`, not `fork+execve`. Intercepting `posix_spawnp` works in isolation but fails in practice with cargo |
| Modify `/etc/passwd` | Requires real root, affects entire system, not portable |

## Bash Shim Protocol

The shim binary and orchestrator communicate over a Unix domain socket using length-prefixed JSON:

```
  Shim (bash replacement)              Orchestrator
  ─────────────────────                ───────────
         │                                  │
         │──── ShimRequest ────────────────▶│
         │     { args: ["-c", "ls"],        │
         │       cwd: "/home/user" }        │
         │                                  │
         │                    (translates mount paths
         │                     to remote paths, checks
         │                     private patterns, spawns
         │                     ssh command)
         │                                  │
         │◀─── ShimResponse::Stdout ────────│
         │     { data: "file1\nfile2\n" }   │
         │                                  │
         │◀─── ShimResponse::Stderr ────────│  (if any)
         │     { data: "warning: ..." }     │
         │                                  │
         │◀─── ShimResponse::Done ──────────│
         │     { exit_code: 0 }             │
         │                                  │

  Wire format: [4-byte big-endian length][JSON payload]
```

Path translation happens transparently — the agent sees paths like `/tmp/tunnelagent-mount/.../file.txt`, and the orchestrator strips the mount prefix before executing remotely.

## Private File Protection

Files matching `--private` patterns (or `.tunnelagent-private`) are protected at two layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Filter FS (FUSE)                                  │
│                                                             │
│  Agent does: Read("/tmp/mount/home/user/.env")              │
│                    │                                        │
│                    ▼                                        │
│  Filter FS: open(".env") ──▶ matches ".env" pattern         │
│                            ──▶ returns EACCES               │
│                                                             │
│  Symlink handling:                                          │
│  Agent does: Read("/tmp/mount/home/user/mylink")            │
│  where mylink -> .env                                       │
│                    │                                        │
│                    ▼                                        │
│  Kernel resolves symlink through FUSE:                      │
│    1. readlink("mylink") ──▶ ".env"                         │
│    2. open(".env")        ──▶ EACCES (blocked)              │
│                                                             │
│  The kernel does symlink resolution, not the agent.         │
│  The filter FS sees the final target path.                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Shim (shell commands)                             │
│                                                             │
│  Agent does: bash -c "cat /home/user/.env"                  │
│                    │                                        │
│                    ▼                                        │
│  Orchestrator: tokenizes args, checks each token            │
│  against private patterns                                   │
│    ──▶ ".env" matches ──▶ returns "access denied"           │
│                                                             │
│  For tokens that look like paths (contain /, start with     │
│  . or ~ or /), also resolves symlinks via the sshfs mount   │
│  and re-checks the resolved target.                         │
│                                                             │
│  Known limitation: bare-name tokens (e.g. "somefile"        │
│  where somefile is a symlink to .env) are not checked       │
│  in the shim to avoid expensive FUSE round-trips (~200ms    │
│  per stat). These are caught by Layer 1 when the command    │
│  actually tries to read the file.                           │
└─────────────────────────────────────────────────────────────┘
```

## SSH ControlMaster

All SSH and sshfs traffic is multiplexed over a single persistent connection:

```
  ssh (ControlMaster, background)  ──────────  Remote sshd
       ▲         ▲         ▲
       │         │         │
    sshfs    shim cmd   shim cmd
    mount    "ls -la"   "git status"

  All share the same TCP connection via the Unix socket
  at /tmp/tunnelagent-{user}-{host}.sock
```

This avoids repeated key exchanges and authentication. The ControlMaster is established once at startup and reused by all subsequent operations, including across multiple tunnel instances targeting the same host.

## Multi-Instance Support

Multiple tunnel instances to the same host share the sshfs mount and ControlMaster via a PID registry (`/tmp/tunnelagent-{user}-{host}.pids`). Each instance gets its own shim directory, Unix socket, and filter FS mount. Shared resources are only cleaned up when the last instance exits.
