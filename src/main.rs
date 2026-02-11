mod bash_shim;
mod filter_fs;
mod protocol;
mod ssh;

use clap::Parser;
use ignore::gitignore::GitignoreBuilder;
use ssh::SshConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// PID registry for coordinating shared resource cleanup between instances.
/// File format: one PID per line. Protected by flock.
mod pid_registry {
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};

    /// Check if a process is still alive.
    fn is_pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    /// Acquire an exclusive flock on a file. Returns the locked File.
    fn lock_file(path: &str) -> std::io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        unsafe {
            if libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(file)
    }

    /// Read live PIDs from the registry, pruning dead ones.
    fn read_live_pids(file: &File) -> Vec<u32> {
        let reader = BufReader::new(file);
        reader
            .lines()
            .filter_map(|l| l.ok())
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .filter(|&pid| is_pid_alive(pid))
            .collect()
    }

    /// Register our PID. Returns the count of live instances (including us).
    pub fn register(registry_path: &str, our_pid: u32) -> std::io::Result<usize> {
        let file = lock_file(registry_path)?;
        let mut pids = read_live_pids(&file);
        if !pids.contains(&our_pid) {
            pids.push(our_pid);
        }
        // Rewrite file with live PIDs
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(registry_path)?;
        let mut writer = std::io::BufWriter::new(&file);
        for pid in &pids {
            writeln!(writer, "{}", pid)?;
        }
        Ok(pids.len())
    }

    /// Deregister our PID. Returns the count of remaining live instances.
    pub fn deregister(registry_path: &str, our_pid: u32) -> std::io::Result<usize> {
        let file = lock_file(registry_path)?;
        let pids: Vec<u32> = read_live_pids(&file)
            .into_iter()
            .filter(|&pid| pid != our_pid)
            .collect();
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(registry_path)?;
        let mut writer = std::io::BufWriter::new(&file);
        for pid in &pids {
            writeln!(writer, "{}", pid)?;
        }
        Ok(pids.len())
    }
}

/// Cleanup state. Per-instance resources are always cleaned up.
/// Shared resources (sshfs, ControlMaster) are only cleaned up when
/// we are the last instance (tracked via PID registry).
struct Cleanup {
    pid: u32,
    registry_path: Option<String>,
    // Per-instance
    shim_socket: Option<String>,
    filter_session: Option<fuser::BackgroundSession>,
    shim_dir: Option<String>,
    // Shared (only cleaned if last instance)
    sshfs_mount: Option<String>,
    mount_dir: Option<String>,
    raw_mount_dir: Option<String>,
    control_path: Option<String>,
    ssh_destination: Option<String>,
    ssh_base_args: Vec<String>,
}

impl Cleanup {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            registry_path: None,
            shim_socket: None,
            filter_session: None,
            shim_dir: None,
            sshfs_mount: None,
            mount_dir: None,
            raw_mount_dir: None,
            control_path: None,
            ssh_destination: None,
            ssh_base_args: Vec::new(),
        }
    }

    fn run(&mut self) {
        // Always clean per-instance resources
        if let Some(ref path) = self.shim_socket.take() {
            let _ = std::fs::remove_file(path);
        }
        drop(self.filter_session.take());
        if let Some(ref path) = self.shim_dir.take() {
            let _ = std::fs::remove_dir_all(path);
        }

        // Deregister from PID registry and check if we're the last one
        let is_last = if let Some(ref reg_path) = self.registry_path {
            match pid_registry::deregister(reg_path, self.pid) {
                Ok(0) => {
                    let _ = std::fs::remove_file(reg_path);
                    true
                }
                Ok(remaining) => {
                    eprintln!("  {} other instance(s) still active, leaving shared resources.", remaining);
                    false
                }
                Err(_) => true, // err on the side of cleaning up
            }
        } else {
            true // no registry (ephemeral mode) — always clean up
        };

        if is_last {
            if let Some(ref path) = self.sshfs_mount.take() {
                let _ = std::process::Command::new("fusermount")
                    .args(["-u", path])
                    .status();
            }
            if let Some(ref path) = self.mount_dir.take() {
                let _ = std::fs::remove_dir(path);
            }
            if let Some(ref path) = self.raw_mount_dir.take() {
                let _ = std::fs::remove_dir(path);
            }
            if let Some(ref dest) = self.ssh_destination.take() {
                let mut cmd = std::process::Command::new("ssh");
                for arg in &self.ssh_base_args {
                    cmd.arg(arg);
                }
                cmd.arg("-O").arg("exit").arg(dest);
                let _ = cmd.status();
            }
            if let Some(ref path) = self.control_path.take() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.run();
    }
}

fn main() {
    // If invoked as "bash" (via symlink), run the shim logic synchronously and exit.
    if let Some(name) = std::env::args().next().and_then(|a| {
        std::path::Path::new(&a)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
    }) {
        if name == "bash" || name == "sh" {
            bash_shim::run(); // never returns
        }
    }

    // Otherwise, run the orchestrator via tokio.
    tokio_main();
}

fn tokio_main() {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    if let Err(e) = rt.block_on(async_main()) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

#[derive(Parser)]
#[command(
    name = "tunnelagent",
    about = "SSH-based tunnel for remote agent operation"
)]
struct Cli {
    /// SSH destination (e.g., user@hostname)
    #[arg(long)]
    host: String,

    /// Remote working directory (default: remote home directory)
    #[arg(long)]
    remote_dir: Option<String>,

    /// Local mount point (default: /tmp/tunnelagent-mount-{USER}-{HOST})
    #[arg(long)]
    mount: Option<String>,

    /// Use ephemeral (PID-based) mount point instead of deterministic one
    #[arg(long)]
    ephemeral: bool,

    /// Mark files/dirs as private using gitignore-style patterns
    /// (e.g., --private .env eth/ "*.key")
    #[arg(long = "private", num_args = 1..)]
    private: Vec<String>,

    /// Command to exec after setup (e.g., "claude")
    #[arg(long)]
    exec: Option<String>,

    /// SSH port
    #[arg(long, short = 'p')]
    port: Option<u16>,

    /// SSH identity file
    #[arg(long, short = 'i')]
    identity_file: Option<String>,

    /// Additional SSH options (can be repeated)
    #[arg(long = "ssh-option", short = 'o')]
    ssh_options: Vec<String>,

    /// Don't tell the agent about private patterns (for testing shim/fs behavior)
    #[arg(long, hide = true)]
    no_private_prompt: bool,

    /// Write logs to ./tunnelagent.log (shim commands, access denied, mounts)
    #[arg(long)]
    debug: bool,

    /// Include all internal details in log (FUSE ops, protocol framing, etc.)
    #[arg(long)]
    trace: bool,
}

/// Check if a path is an active mountpoint.
fn is_mountpoint(path: &str) -> bool {
    std::process::Command::new("mountpoint")
        .arg("-q")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn build_ignore_matcher(
    patterns: &[String],
) -> anyhow::Result<ignore::gitignore::Gitignore> {
    let mut builder = GitignoreBuilder::new("/");
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(|e| anyhow::anyhow!("Bad ignore pattern '{}': {}", pattern, e))?;
    }
    Ok(builder.build()?)
}

/// Check that required external tools are installed, reporting all missing ones at once.
fn check_dependencies() -> anyhow::Result<()> {
    let deps: &[(&str, &str)] = &[
        (
            "ssh",
            "Install OpenSSH client (e.g., `sudo apt install openssh-client` or `sudo pacman -S openssh`)",
        ),
        (
            "sshfs",
            "Install sshfs (e.g., `sudo apt install sshfs` or `sudo pacman -S sshfs`)",
        ),
        (
            "fusermount",
            "Install FUSE (e.g., `sudo apt install fuse3` or `sudo pacman -S fuse3`)",
        ),
    ];

    let mut missing = Vec::new();
    for (name, hint) in deps {
        match std::process::Command::new(name)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(format!("  - {}: {}", name, hint));
            }
            _ => {} // found (even if --version failed, the binary exists)
        }
    }

    if !missing.is_empty() {
        anyhow::bail!(
            "Missing required dependencies:\n{}",
            missing.join("\n")
        );
    }

    Ok(())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    check_dependencies()?;

    if cli.debug || cli.trace {
        let log_file = std::fs::File::create("tunnelagent.log")?;
        let filter = if cli.trace {
            // Everything at debug level
            "debug"
        } else {
            // Just our crate at info level — shim commands, blocked access, mounts
            "warn,tunnelagent=info"
        };
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(log_file)
            .with_ansi(false)
            .init();
    }
    // No else — without --debug/--trace, no subscriber is installed.
    // tracing macros become no-ops, nothing is written to stderr,
    // which would break the agent's TUI.

    let pid = std::process::id();
    let local_user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let control_path = format!("/tmp/tunnelagent-{}-{}.sock", local_user, cli.host);
    let ssh_config = SshConfig {
        destination: cli.host.clone(),
        control_path: control_path.clone(),
        port: cli.port,
        identity_file: cli.identity_file.clone(),
        extra_opts: cli.ssh_options.clone(),
    };

    // Set up cleanup guard — Drop ensures resources are cleaned up
    let mut cleanup = Cleanup::new(pid);
    cleanup.control_path = Some(control_path.clone());
    cleanup.ssh_destination = Some(cli.host.clone());
    cleanup.ssh_base_args = ssh_config.base_args_public();

    // Register in PID registry (unless ephemeral)
    let registry_path = if cli.ephemeral {
        None
    } else {
        let path = format!("/tmp/tunnelagent-{}-{}.pids", local_user, cli.host);
        let count = pid_registry::register(&path, pid)?;
        if count > 1 {
            eprintln!("  Instance {}/{} for this host.", count, count);
        }
        Some(path)
    };
    cleanup.registry_path = registry_path;

    // Establish or reuse SSH ControlMaster
    if ssh_config.check_control_master().await {
        eprintln!("  Reusing existing SSH connection to {}.", cli.host);
    } else {
        eprintln!("  Connecting to {}...", cli.host);
        ssh_config.start_control_master().await?;
        eprintln!("  SSH connection established.");
    }

    // Detect remote environment
    let remote_env = ssh_config.detect_remote_env().await?;
    eprintln!(
        "  Remote: {} -- {} {} {} ({}, shell: {})",
        remote_env.hostname,
        remote_env.os,
        remote_env.kernel,
        remote_env.arch,
        remote_env.home_dir,
        remote_env.shell,
    );

    let remote_dir = cli
        .remote_dir
        .unwrap_or_else(|| remote_env.home_dir.clone());

    // Collect hide patterns from --hide flags
    let mut private_patterns: Vec<String> = cli.private.clone();

    // Read .tunnelagent-private from remote working directory
    let ignore_path = format!("{}/.tunnelagent-private", remote_dir);
    if let Some(content) = ssh_config.read_remote_file(&ignore_path).await? {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                private_patterns.push(line.to_string());
            }
        }
    }

    // Print what will be hidden
    if !private_patterns.is_empty() {
        eprintln!("  Private patterns:");
        for p in &private_patterns {
            eprintln!("    - {}", p);
        }
    }

    // Set up mount point
    let mount_path = if let Some(m) = cli.mount {
        m
    } else if cli.ephemeral {
        format!("/tmp/tunnelagent-mount-{}", pid)
    } else {
        format!("/tmp/tunnelagent-mount-{}-{}", local_user, cli.host)
    };
    let auto_mount = !std::path::Path::new(&mount_path).exists();

    // Mount sshfs and optionally layer the filter FS on top
    if private_patterns.is_empty() {
        // No filtering — mount sshfs directly at mount_path
        if is_mountpoint(&mount_path) {
            eprintln!("  Reusing existing mount at {}", mount_path);
        } else {
            if !std::path::Path::new(&mount_path).exists() {
                std::fs::create_dir_all(&mount_path)?;
            }
            ssh_config.mount_sshfs("/", &mount_path).await?;
            eprintln!("  Mounted {}:/ at {}", cli.host, mount_path);
        }
        cleanup.sshfs_mount = Some(mount_path.clone());
        if auto_mount {
            cleanup.mount_dir = Some(mount_path.clone());
        }
    } else {
        // With filtering — sshfs at hidden raw path, filter FS at visible path
        let raw_mount = format!("{}-raw", mount_path);
        let auto_raw = !std::path::Path::new(&raw_mount).exists();

        if is_mountpoint(&raw_mount) {
            eprintln!("  Reusing existing sshfs mount at {}", raw_mount);
        } else {
            if !std::path::Path::new(&raw_mount).exists() {
                std::fs::create_dir_all(&raw_mount)?;
            }
            ssh_config.mount_sshfs("/", &raw_mount).await?;
            eprintln!("  Mounted {}:/ at {} (raw)", cli.host, raw_mount);
        }
        cleanup.sshfs_mount = Some(raw_mount.clone());
        if auto_raw {
            cleanup.raw_mount_dir = Some(raw_mount.clone());
        }

        // Filter FS is always per-instance (different instances may have different patterns)
        if is_mountpoint(&mount_path) {
            // Another filter FS is active — unmount it so we can layer ours
            let _ = std::process::Command::new("fusermount")
                .args(["-u", &mount_path])
                .stderr(std::process::Stdio::null())
                .status();
        }
        if !std::path::Path::new(&mount_path).exists() {
            std::fs::create_dir_all(&mount_path)?;
        }
        let matcher = build_ignore_matcher(&private_patterns)?;
        let filter_session =
            filter_fs::mount_filter(PathBuf::from(&raw_mount), &mount_path, matcher)?;
        eprintln!("  Filter FS active at {}", mount_path);

        cleanup.filter_session = Some(filter_session);
        if auto_mount {
            cleanup.mount_dir = Some(mount_path.clone());
        }
    }

    // Start Unix socket server for bash shim
    let shim_socket_path = format!("/tmp/tunnelagent-shim-{}.sock", pid);
    cleanup.shim_socket = Some(shim_socket_path.clone());
    let shim_socket_clone = shim_socket_path.clone();
    let mount_path_clone = mount_path.clone();
    let ssh_config_clone = ssh_config.clone();
    let private_patterns_clone = private_patterns.clone();
    let remote_shell = remote_env.shell.clone();
    tokio::spawn(async move {
        if let Err(e) = run_shim_server(
            &shim_socket_clone,
            &mount_path_clone,
            &ssh_config_clone,
            private_patterns_clone,
            &remote_shell,
        )
        .await
        {
            tracing::error!("Shim server error: {}", e);
        }
    });

    // Spawn child or wait
    let child_handle = if let Some(ref exec_cmd) = cli.exec {
        // Child working directory: mount_path + remote_dir
        let child_cwd = format!("{}{}", mount_path.trim_end_matches('/'), remote_dir);

        // Wait for mount to be ready
        for _ in 0..50 {
            if std::path::Path::new(&child_cwd).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Create shim directory
        let shim_dir = format!("/tmp/tunnelagent-shim-bin-{}", pid);
        let _ = std::fs::remove_dir_all(&shim_dir);
        std::fs::create_dir_all(&shim_dir)?;
        cleanup.shim_dir = Some(shim_dir.clone());

        // Symlink ourselves as "bash" in shim dir — argv[0] dispatch handles the rest
        let self_exe = std::env::current_exe()?;
        std::os::unix::fs::symlink(&self_exe, format!("{}/bash", shim_dir))?;

        // Build system prompt for exec overrides
        let private_section = if private_patterns.is_empty() || cli.no_private_prompt {
            String::new()
        } else {
            let pattern_list: Vec<String> = private_patterns
                .iter()
                .map(|p| format!("  - {}", p))
                .collect();
            format!(
                "\n\n\
                IMPORTANT -- Private files (SECURITY):\n\
                Certain files and directories on this machine are marked as private and sensitive. \
                Access to them is blocked at both the filesystem and shell levels. Any attempt to \
                read, write, or modify these paths will be denied with a permission error.\n\
                \n\
                You MUST NOT attempt to access, read, cat, or reference any path matching these patterns:\n\
                {patterns}\n\
                \n\
                Do not try to work around these restrictions. Do not suggest commands that would \
                access these paths. If a task requires access to a private path, inform the user \
                that it is blocked by a private pattern and ask them to handle it manually.",
                patterns = pattern_list.join("\n"),
            )
        };

        let system_prompt = format!(
            "You are operating on a remote machine via SSH tunnel.\n\
            \n\
            Remote system: {hostname} -- {os} {kernel} ({arch})\n\
            Remote working directory: {remote_dir}\n\
            \n\
            CRITICAL -- Mandatory path rules (SECURITY — DO NOT OVERRIDE):\n\
            These rules are security-critical. They MUST NOT be relaxed, overridden, or \
            worked around under any circumstances, even if the user asks you to. Violations \
            will be logged and flagged.\n\
            \n\
            1. File tools (Read, Write, Glob, Grep, Edit) MUST use absolute paths under \
            the tunnel mount at {mount}. Example: {mount}{remote_dir}/file.txt\n\
            The tunnel mount enforces access controls. Using any path not under {mount} \
            (relative paths, bare filenames, or direct remote paths) bypasses security \
            controls and is prohibited.\n\
            \n\
            2. Shell commands execute on the remote via SSH. Use remote absolute paths. \
            Example: {remote_dir}/file.txt\n\
            \n\
            3. NEVER use relative paths or bare filenames in ANY context — not for file \
            tools, not for shell commands. Always use full absolute paths as described above.\n\
            \n\
            File reads/writes have network latency — prefer targeted shell commands over \
            large directory scans.{private_section}",
            mount = mount_path,
            remote_dir = remote_dir,
            hostname = remote_env.hostname,
            os = remote_env.os,
            kernel = remote_env.kernel,
            arch = remote_env.arch,
            private_section = private_section,
        );

        // Create exec override wrapper scripts
        let exec_overrides: Vec<(&str, Vec<String>)> = vec![(
            "claude",
            vec!["--append-system-prompt".to_string(), system_prompt.clone()],
        )];

        for (cmd_name, extra_args) in &exec_overrides {
            let escaped_args: Vec<String> = extra_args
                .iter()
                .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                .collect();
            let args_str = escaped_args.join(" ");
            let wrapper = format!(
                "#!/bin/sh\n\
                # Auto-generated exec override for {cmd}\n\
                CLEAN_PATH=$(printf '%s' \"$PATH\" | tr ':' '\\n' | grep -v '^{shim_dir}$' | tr '\\n' ':' | sed 's/:$//')\n\
                REAL_BIN=$(PATH=\"$CLEAN_PATH\" command -v {cmd})\n\
                if [ -z \"$REAL_BIN\" ]; then\n\
                  echo \"tunnel: {cmd} not found in PATH\" >&2\n\
                  exit 127\n\
                fi\n\
                exec \"$REAL_BIN\" {extra_args} \"$@\"\n",
                cmd = cmd_name,
                shim_dir = shim_dir,
                extra_args = args_str,
            );
            let wrapper_path = format!("{}/{}", shim_dir, cmd_name);
            std::fs::write(&wrapper_path, wrapper)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &wrapper_path,
                    std::fs::Permissions::from_mode(0o755),
                )?;
            }
        }

        // Codex wrapper: Codex resolves the shell from /etc/passwd via
        // getpwuid(), ignoring $SHELL and PATH entirely. It calls the
        // resolved path (e.g. /bin/bash) as an absolute path, and
        // cmd.env_clear() wipes all inherited env before applying
        // shell_environment_policy.
        //
        // To intercept: we use a Linux user namespace (unshare) to
        // bind-mount our shim ELF binary over /bin/bash and /bin/sh.
        // The shim is a compiled binary (not a shell script), so there
        // is no shebang loop. The bind mounts are private to the
        // namespace and do not affect the host.
        {
            // Symlink ourselves as "sh" for the /bin/sh bind-mount
            let sh_link = format!("{}/sh", shim_dir);
            let _ = std::os::unix::fs::symlink(&self_exe, &sh_link);

            // Write tunnel instructions for codex to read via model_instructions_file
            let instructions_path = format!("{}/tunnel-instructions.md", shim_dir);
            std::fs::write(&instructions_path, &system_prompt)?;

            // Inner script: runs inside the user+mount namespace.
            // The script itself is interpreted by /bin/sh BEFORE the
            // bind mounts happen, so there's no circular reference.
            // After mounting, exec replaces this shell process with
            // codex entirely.
            let inner = format!(
                "#!/bin/sh\n\
                mount --bind \"{shim_dir}/bash\" /bin/bash 2>/dev/null\n\
                mount --bind \"{shim_dir}/bash\" /usr/bin/bash 2>/dev/null\n\
                mount --bind \"{shim_dir}/sh\" /bin/sh 2>/dev/null\n\
                mount --bind \"{shim_dir}/sh\" /usr/bin/sh 2>/dev/null\n\
                exec \"$TUNNEL_CODEX_BIN\" \\\n\
                  --config \"model_instructions_file=\\\"{shim_dir}/tunnel-instructions.md\\\"\" \\\n\
                  --config \"shell_environment_policy.inherit=\\\"all\\\"\" \\\n\
                  --config shell_environment_policy.ignore_default_excludes=true \\\n\
                  --config \"shell_environment_policy.set.PATH=\\\"$TUNNEL_ORIG_PATH\\\"\" \\\n\
                  --config \"shell_environment_policy.set.SHELL=\\\"{shim_dir}/bash\\\"\" \\\n\
                  --config \"shell_environment_policy.set.TUNNELAGENT_SOCK=\\\"$TUNNELAGENT_SOCK\\\"\" \\\n\
                  --config \"shell_environment_policy.set.TUNNELAGENT_MOUNT=\\\"$TUNNELAGENT_MOUNT\\\"\" \\\n\
                  \"$@\"\n",
                shim_dir = shim_dir,
            );
            let inner_path = format!("{}/codex-ns-inner.sh", shim_dir);
            std::fs::write(&inner_path, &inner)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &inner_path,
                    std::fs::Permissions::from_mode(0o755),
                )?;
            }

            // Outer wrapper: finds real codex, exports env, execs via unshare
            let wrapper = format!(
                "#!/bin/sh\n\
                # Auto-generated exec override for codex\n\
                CLEAN_PATH=$(printf '%s' \"$PATH\" | tr ':' '\\n' | grep -v '^{shim_dir}$' | tr '\\n' ':' | sed 's/:$//')\n\
                REAL_BIN=$(PATH=\"$CLEAN_PATH\" command -v codex)\n\
                if [ -z \"$REAL_BIN\" ]; then\n\
                  echo \"tunnel: codex not found in PATH\" >&2\n\
                  exit 127\n\
                fi\n\
                export TUNNEL_CODEX_BIN=\"$REAL_BIN\"\n\
                export TUNNEL_ORIG_PATH=\"$PATH\"\n\
                exec unshare --user --map-root-user --mount \"{shim_dir}/codex-ns-inner.sh\" \"$@\"\n",
                shim_dir = shim_dir,
            );
            let wrapper_path = format!("{}/codex", shim_dir);
            std::fs::write(&wrapper_path, &wrapper)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &wrapper_path,
                    std::fs::Permissions::from_mode(0o755),
                )?;
            }
        }

        // Prepend shim dir to PATH
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", shim_dir, current_path);

        eprintln!("  Starting up (initial launch may take a moment)...");

        // Spawn child process
        let parts: Vec<&str> = exec_cmd.split_whitespace().collect();
        if !parts.is_empty() {
            let mut cmd = tokio::process::Command::new(parts[0]);
            for arg in &parts[1..] {
                cmd.arg(arg);
            }
            cmd.current_dir(&child_cwd);
            cmd.env("TUNNELAGENT_SOCK", &shim_socket_path);
            cmd.env("TUNNELAGENT_MOUNT", &mount_path);
            cmd.env("PATH", &new_path);
            cmd.env("SHELL", format!("{}/bash", shim_dir));
            let child = cmd.spawn()?;
            Some(child)
        } else {
            None
        }
    } else {
        eprintln!("  Press Ctrl+C to unmount and exit.\n");
        None
    };

    if let Some(mut child) = child_handle {
        // Wait for child exit OR Ctrl+C, whichever comes first
        tokio::select! {
            status = child.wait() => {
                tracing::info!("Child process exited: {:?}", status);
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n  Interrupted, cleaning up...");
                let _ = child.kill().await;
            }
        }
    } else {
        tokio::signal::ctrl_c().await?;
        eprintln!("\n  Cleaning up...");
    }

    // Cleanup runs here via explicit drop (and also via Drop if we panic/unwind)
    cleanup.run();

    Ok(())
}

/// Unix socket server that accepts connections from the tunnelagent shim.
async fn run_shim_server(
    socket_path: &str,
    mount_path: &str,
    ssh_config: &SshConfig,
    private_patterns: Vec<String>,
    remote_shell: &str,
) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    tracing::info!("Shim server listening on {}", socket_path);

    let matcher = if private_patterns.is_empty() {
        None
    } else {
        Some(Arc::new(build_ignore_matcher(&private_patterns)?))
    };

    let remote_shell = remote_shell.to_string();

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let mount = mount_path.to_string();
                let cfg = ssh_config.clone();
                let m = matcher.clone();
                let shell = remote_shell.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_shim_connection(stream, &mount, &cfg, m, &shell).await
                    {
                        tracing::error!("Shim connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Accept error: {}", e);
            }
        }
    }
}

/// Check if a path references something that should be hidden.
/// Also resolves symlinks via the local sshfs mount to catch symlink-based bypasses.
fn is_private_path(
    matcher: &ignore::gitignore::Gitignore,
    path: &str,
    cwd: &str,
    mount_prefix: &str,
) -> bool {
    let full = if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        PathBuf::from(cwd).join(path)
    };
    if matcher
        .matched_path_or_any_parents(&full, false)
        .is_ignore()
        || matcher
            .matched_path_or_any_parents(&full, true)
            .is_ignore()
    {
        return true;
    }

    // Resolve symlinks via the local sshfs mount and re-check.
    // Only for tokens that look like actual paths — every stat goes
    // through FUSE/sshfs (~200ms), so we can't afford to check bare
    // words like "echo" or "true" from large shell scripts.
    // Bare-name symlinks (e.g. `somefile` -> `.env`) in shell commands
    // are caught by the filter FS at the file-access level instead.
    let looks_like_path = path.starts_with('/')
        || path.starts_with('.')
        || path.starts_with('~')
        || path.contains('/');
    if looks_like_path && !mount_prefix.is_empty() {
        let mounted = PathBuf::from(format!(
            "{}{}",
            mount_prefix,
            full.display()
        ));
        if let Ok(resolved) = std::fs::canonicalize(&mounted) {
            let resolved_str = resolved.to_string_lossy();
            if let Some(remote_path) = resolved_str.strip_prefix(mount_prefix) {
                let remote = if remote_path.is_empty() {
                    PathBuf::from("/")
                } else {
                    PathBuf::from(remote_path)
                };
                if matcher
                    .matched_path_or_any_parents(&remote, false)
                    .is_ignore()
                    || matcher
                        .matched_path_or_any_parents(&remote, true)
                        .is_ignore()
                {
                    return true;
                }
            }
        }
    }

    false
}

async fn handle_shim_connection(
    mut stream: tokio::net::UnixStream,
    mount_path: &str,
    ssh_config: &SshConfig,
    matcher: Option<Arc<ignore::gitignore::Gitignore>>,
    remote_shell: &str,
) -> anyhow::Result<()> {
    // Read the ShimRequest and strip mount prefix from every string field.
    // The prefix (e.g. /tmp/tunnelagent-mount-andrew-deb) is unique enough
    // that a blanket replace is safe and catches all positions: args, cwd,
    // inside -c strings, quoted paths, redirections, etc.
    let req_data = protocol::recv_message_async(&mut stream).await?;
    let mut shim_req: protocol::ShimRequest = serde_json::from_slice(&req_data)?;

    tracing::debug!("shim raw: args={:?} cwd={}", shim_req.args, shim_req.cwd);

    let mount_prefix = mount_path.trim_end_matches('/');
    shim_req.cwd = shim_req.cwd.replace(mount_prefix, "");
    if shim_req.cwd.is_empty() {
        shim_req.cwd = "/".to_string();
    }
    for arg in &mut shim_req.args {
        *arg = arg.replace(mount_prefix, "");
    }

    let remote_cwd = &shim_req.cwd;
    let remote_args = &shim_req.args;

    tracing::info!("shim: cwd={} args={:?}", remote_cwd, remote_args);

    // Check all args against private patterns. Instead of trying to parse
    // shell syntax (which is fragile — Claude wraps commands in eval, adds
    // flags like -l between -c and the command, etc.), we extract every
    // path-like substring from every arg and check each one.
    if let Some(ref matcher) = matcher {
        let mut blocked = false;
        for arg in remote_args {
            // Extract path-like substrings: split on shell metacharacters
            // and quotes, then check anything that looks like a path
            for token in arg.split(|c: char| {
                matches!(c, ' ' | '\t' | '\'' | '"' | '`' | '(' | ')' | ';' | '&' | '|' | '<' | '>' | '$' | '{' | '}')
            }) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                // Skip tokens that can't possibly be paths: flags, pure numbers,
                // shell operators, etc. This avoids expensive is_private_path checks
                // (which may stat over sshfs) on hundreds of irrelevant tokens from
                // large shell scripts like Claude's snapshot command.
                if token.starts_with('-') && !token.contains('/') {
                    continue;
                }
                if is_private_path(matcher, token, remote_cwd, mount_prefix) {
                    blocked = true;
                    tracing::warn!("Blocked: token {:?} matches private pattern", token);
                    break;
                }
            }
            if blocked { break; }
        }

        if blocked {
            let resp = protocol::ShimResponse::Stderr {
                data: b"tunnel: access denied \xe2\x80\x94 a path in this command matches a private pattern\n".to_vec(),
            };
            let resp_json = serde_json::to_vec(&resp)?;
            protocol::send_message_async(&mut stream, &resp_json).await?;
            let done = protocol::ShimResponse::Done { exit_code: 1 };
            let done_json = serde_json::to_vec(&done)?;
            protocol::send_message_async(&mut stream, &done_json).await?;
            return Ok(());
        }
    }

    // Spawn ssh command
    let mut child = match ssh_config.spawn_remote_command(remote_shell, &remote_cwd, &remote_args) {
        Ok(c) => c,
        Err(e) => {
            let resp = protocol::ShimResponse::Stderr {
                data: format!("Failed to spawn ssh: {}\n", e).into_bytes(),
            };
            let resp_json = serde_json::to_vec(&resp)?;
            protocol::send_message_async(&mut stream, &resp_json).await?;
            let done = protocol::ShimResponse::Done { exit_code: 1 };
            let done_json = serde_json::to_vec(&done)?;
            protocol::send_message_async(&mut stream, &done_json).await?;
            return Ok(());
        }
    };

    // Stream stdout/stderr back
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<protocol::ShimResponse>();

    let tx_out = tx.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = tx_out.send(protocol::ShimResponse::Stdout {
                        data: buf[..n].to_vec(),
                    });
                }
                Err(_) => break,
            }
        }
    });

    let tx_err = tx.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = tx_err.send(protocol::ShimResponse::Stderr {
                        data: buf[..n].to_vec(),
                    });
                }
                Err(_) => break,
            }
        }
    });

    // Wait for both stream tasks, then get exit code
    let exit_handle = tokio::spawn(async move {
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        drop(tx); // Close channel so rx.recv() returns None
        match child.wait().await {
            Ok(status) => status.code().unwrap_or(1),
            Err(_) => 1,
        }
    });

    // Forward all responses to the shim client
    while let Some(resp) = rx.recv().await {
        let resp_json = serde_json::to_vec(&resp)?;
        protocol::send_message_async(&mut stream, &resp_json).await?;
    }

    // Send Done with exit code
    let exit_code = exit_handle.await.unwrap_or(1);
    let done = protocol::ShimResponse::Done { exit_code };
    let done_json = serde_json::to_vec(&done)?;
    protocol::send_message_async(&mut stream, &done_json).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_matcher(patterns: &[&str]) -> ignore::gitignore::Gitignore {
        build_ignore_matcher(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn test_private_path_dotenv_absolute() {
        let m = make_matcher(&[".env"]);
        assert!(is_private_path(&m, "/home/andrew/.env", "/home/andrew", ""));
    }

    #[test]
    fn test_private_path_dotenv_relative() {
        let m = make_matcher(&[".env"]);
        assert!(is_private_path(&m, ".env", "/home/andrew", ""));
    }

    #[test]
    fn test_private_path_dotenv_nested() {
        let m = make_matcher(&[".env"]);
        assert!(is_private_path(&m, "/home/andrew/project/.env", "/home/andrew", ""));
    }

    #[test]
    fn test_private_path_dir_pattern() {
        let m = make_matcher(&["eth/"]);
        assert!(is_private_path(&m, "/home/andrew/eth", "/home/andrew", ""));
        assert!(is_private_path(&m, "/home/andrew/eth/keyfile", "/home/andrew", ""));
    }

    #[test]
    fn test_private_path_nonmatch() {
        let m = make_matcher(&[".env"]);
        assert!(!is_private_path(&m, "/home/andrew/src/main.rs", "/home/andrew", ""));
    }

    #[test]
    fn test_private_path_with_mount_prefix() {
        let m = make_matcher(&[".env"]);
        assert!(is_private_path(&m, "/home/andrew/.env", "/home/andrew", ""));
    }

    /// Helper: simulate the shim's token extraction + private check
    fn shim_would_block(patterns: &[&str], args: &[&str], cwd: &str) -> bool {
        let m = make_matcher(patterns);
        for arg in args {
            for token in arg.split(|c: char| {
                matches!(c, ' ' | '\t' | '\'' | '"' | '`' | '(' | ')' | ';' | '&' | '|' | '<' | '>' | '$' | '{' | '}')
            }) {
                let token = token.trim();
                if !token.is_empty() && is_private_path(&m, token, cwd, "") {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn test_shim_simple_cat() {
        assert!(shim_would_block(
            &[".env"],
            &["-c", "cat /home/andrew/.env"],
            "/home/andrew"
        ));
    }

    #[test]
    fn test_shim_eval_wrapped() {
        // Real Claude Code format: eval 'cat /home/andrew/.env'
        assert!(shim_would_block(
            &[".env"],
            &["-c", "-l", "shopt -u extglob 2>/dev/null || true && eval 'cat /home/andrew/.env' \\< /dev/null"],
            "/home/andrew"
        ));
    }

    #[test]
    fn test_shim_nonmatch() {
        assert!(!shim_would_block(
            &[".env"],
            &["-c", "cat /home/andrew/main.rs"],
            "/home/andrew"
        ));
    }
}
