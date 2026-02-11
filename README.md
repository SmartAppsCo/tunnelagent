# tunnelagent

<p align="center">
  <img src="site/banner.png" alt="tunnelagent — bring your agents anywhere SSH can go" width="800">
</p>

Bring your AI agents anywhere SSH can go. No installation on the remote machine, no elevated permissions, no custom server — just point tunnelagent at any SSH host and your agent works there.

## Update (Feb 2025)

Claude Code Desktop now supports SSH connections natively on macOS (not the CLI). If you're on a Mac and only use Claude Code Desktop, that may be all you need. tunnelagent still covers ground it doesn't: Linux support, works with the CLI, works with any agent (Codex, etc.), zero remote installation, and private file guardrails.

## The problem

AI coding agents like Claude Code and Codex run locally. They read files from your filesystem and execute shell commands on your machine. When you need an agent to work on a remote server — a production box, a VM, a cloud instance, a beefy dev machine — your options are limited:

- **Install the agent remotely.** Requires install permissions, compatible runtimes, API keys on the remote machine, and maintaining another installation. Many servers you can SSH into aren't ones you can (or want to) install software on.
- **Copy files back and forth.** Tedious, error-prone, and breaks the agent's ability to run commands in the real environment.
- **Use a remote development tool.** Ties you to a specific IDE or editor, and most don't support AI agents.

The common thread: if you can `ssh` into a machine, you should be able to use your agent there. But agents aren't designed for that.

## How tunnelagent solves it

tunnelagent makes a remote machine look local to your agent. It mounts the remote filesystem via `sshfs` and intercepts shell commands to execute them over SSH. The agent uses its normal file tools and shell commands, and tunnelagent transparently routes everything to the remote machine. The agent wouldn't otherwise know or care that it's working remotely — a custom system prompt is injected just to keep it (and you!) correctly oriented.

**Nothing is installed on the remote machine.** tunnelagent runs entirely on your local machine and talks to the remote over a standard SSH connection. If you can `ssh` into it, tunnelagent works there.

**Guardrails for sensitive files.** Giving an agent access to a remote machine is powerful, and tunnelagent is built to prevent footguns. Private file protection works at three layers: the FUSE filesystem denies all access to files matching private patterns, the shell shim blocks commands that reference private paths, and the agent's system prompt instructs it not to attempt access in the first place. Defense in depth — even if one layer is bypassed, the others catch it.

## Use cases

- **Work on a remote dev server** — run Claude Code against your project on a powerful remote machine without installing anything there
- **Operate on production/staging** — let your agent inspect logs, debug issues, or make changes on servers you can SSH into but don't want to install tools on
- **Cloud instances and VMs** — spin up a machine, point tunnelagent at it, and start working immediately
- **Jump hosts and bastion servers** — works with any SSH configuration including ProxyJump chains
- **Shared team servers** — each developer brings their own agent without polluting the shared environment

## Quick start

### 1. Prerequisites

You need three things on your **local** machine:

```bash
# Arch/Manjaro
sudo pacman -S sshfs

# Ubuntu/Debian
sudo apt install sshfs

# macOS
brew install macfuse sshfs
```

SSH key auth must be set up for your target host (password prompts will hang the connection):

```bash
ssh-copy-id user@remote   # if not already done
ssh user@remote            # verify it works without a password prompt
```

### 2. Install

```bash
# From source
cargo install --path .

# Or just build
cargo build --release
# Binary is at target/release/tunnelagent
```

### 3. Run

```bash
# Launch Claude Code on a remote machine
tunnelagent --host user@remote --exec claude

# Or use OpenAI Codex
tunnelagent --host user@remote --exec codex

# Specific remote directory
tunnelagent --host user@remote --remote-dir /home/user/project --exec claude

# Drop into a remote bash shell instead
tunnelagent --host user@remote --exec bash
```

That's it. Claude Code sees remote files via its normal file tools, and shell commands execute on the remote machine.

## Protecting sensitive files

Block the agent from reading specific files or directories:

```bash
tunnelagent --host user@remote --private .env "*.key" secrets/ --exec claude
```

Or create a `.tunnelagent-private` file in the remote working directory:

```
.env
*.key
secrets/
.ssh/
```

Private patterns use gitignore syntax. Protection works at two levels: the filesystem hides files from file tools, and the shell shim blocks commands that reference private paths.

## Options

```
--host user@remote       SSH destination (required)
--remote-dir /path       Remote directory to mount (default: home dir)
--mount /local/path      Custom local mount point
--exec <command>         Command to run after setup (e.g., claude, bash)
--private <patterns>     Gitignore-style patterns for files to hide
--ephemeral              Use PID-based mount (not shared across instances)
-p, --port <port>        SSH port
-i <identity_file>       SSH identity file
-o <ssh_option>          Additional SSH options (repeatable)
--debug                  Log to ./tunnelagent.log
--trace                  Verbose debug logging (includes FUSE ops)
```

## How it works

1. Opens a multiplexed SSH connection (ControlMaster)
2. Mounts the remote filesystem locally via `sshfs`
3. Symlinks itself as `bash` in a temp directory on PATH — when the agent spawns bash, the shim intercepts it, translates local mount paths to remote paths, and runs the command over SSH
4. On exit, unmounts and cleans up

Multiple instances targeting the same host share the SSH connection and mount automatically.

## License

MIT
