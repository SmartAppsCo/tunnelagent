use anyhow::bail;

/// Shell-quote a string for safe embedding in a remote `sh -c '...'` invocation.
/// Uses single-quote wrapping: replaces internal `'` with `'\''` then wraps in `'...'`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Reorder shell arguments for POSIX sh compatibility.
///
/// Bash accepts flags in any order relative to `-c` (e.g., `bash -c -l "cmd"`
/// treats both `-c` and `-l` as flags, then takes `"cmd"` as the command string).
/// POSIX sh requires the command string immediately after `-c`, so
/// `sh -c -l "cmd"` tries to execute `-l` as a command.
///
/// This reorders so all flags come before `-c`:
///   `["-c", "-l", "cmd"]` → `["-l", "-c", "cmd"]`
fn reorder_shell_args(args: &[String]) -> Vec<String> {
    let c_pos = match args.iter().position(|a| a == "-c") {
        Some(pos) => pos,
        None => return args.to_vec(),
    };

    let before_c = &args[..c_pos];
    let after_c = &args[c_pos + 1..];

    // Separate flags (like -l, -i) from the command string and positional args.
    // Flags are short options starting with '-'; the first non-flag arg after -c
    // is the command string.
    let mut extra_flags = Vec::new();
    let mut rest = Vec::new();
    let mut found_command = false;

    for arg in after_c {
        if !found_command && arg.starts_with('-') && arg.len() > 1 {
            extra_flags.push(arg.clone());
        } else {
            found_command = true;
            rest.push(arg.clone());
        }
    }

    let mut result = Vec::with_capacity(args.len());
    result.extend_from_slice(before_c);
    result.extend(extra_flags);
    result.push("-c".to_string());
    result.extend(rest);
    result
}

/// Build a remote shell command string: `cd '/remote/cwd' && sh -l -c 'command'`
/// All components are shell-quoted for safe remote execution.
/// The `shell` parameter specifies which shell to invoke on the remote (e.g. "bash", "sh").
/// Arguments are reordered for POSIX sh compatibility (flags before -c).
fn build_remote_command(shell: &str, remote_cwd: &str, args: &[String]) -> String {
    let cd_part = format!("cd {}", shell_quote(remote_cwd));
    let cmd_part = if args.is_empty() {
        shell.to_string()
    } else {
        let reordered = reorder_shell_args(args);
        let quoted_args: Vec<String> = reordered.iter().map(|a| shell_quote(a)).collect();
        format!("{} {}", shell, quoted_args.join(" "))
    };
    format!("{} && {}", cd_part, cmd_part)
}

#[derive(Clone, Debug)]
pub struct SshConfig {
    /// Full SSH destination, e.g. "user@hostname" or "hostname"
    pub destination: String,
    /// Path to the ControlMaster Unix socket
    pub control_path: String,
    /// Optional SSH port override
    pub port: Option<u16>,
    /// Optional identity file path
    pub identity_file: Option<String>,
    /// Any additional SSH options to pass through
    pub extra_opts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RemoteEnv {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub home_dir: String,
    /// Remote shell to use for command execution ("bash" or "sh").
    pub shell: String,
}

impl SshConfig {
    /// Common SSH arguments for use outside of SshConfig methods (e.g., cleanup).
    pub fn base_args_public(&self) -> Vec<String> {
        self.base_args()
    }

    /// Common SSH arguments that every ssh/sshfs invocation needs.
    fn base_args(&self) -> Vec<String> {
        let mut args = vec![
            "-o".to_string(),
            format!("ControlPath={}", self.control_path),
        ];
        if let Some(port) = self.port {
            args.extend(["-p".to_string(), port.to_string()]);
        }
        if let Some(ref id) = self.identity_file {
            args.extend(["-i".to_string(), id.clone()]);
        }
        for opt in &self.extra_opts {
            args.extend(["-o".to_string(), opt.clone()]);
        }
        args
    }

    /// Check if a ControlMaster is already running for this config.
    pub async fn check_control_master(&self) -> bool {
        tokio::process::Command::new("ssh")
            .args(self.base_args())
            .arg("-O")
            .arg("check")
            .arg(&self.destination)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Start an SSH ControlMaster in the background.
    pub async fn start_control_master(&self) -> anyhow::Result<()> {
        let mut cmd = tokio::process::Command::new("ssh");
        cmd.arg("-o").arg("ControlMaster=yes");
        cmd.args(self.base_args());
        cmd.arg("-o").arg("ControlPersist=yes");
        cmd.arg("-N"); // No remote command
        cmd.arg("-f"); // Fork to background
        cmd.arg(&self.destination);
        let status = cmd.status().await?;
        if !status.success() {
            bail!(
                "Failed to establish SSH ControlMaster (exit code: {:?})",
                status.code()
            );
        }
        Ok(())
    }

    /// Stop the ControlMaster.
    #[allow(dead_code)]
    pub async fn stop_control_master(&self) {
        let _ = tokio::process::Command::new("ssh")
            .args(self.base_args())
            .arg("-O")
            .arg("exit")
            .arg(&self.destination)
            .status()
            .await;
    }

    /// Detect remote environment by running a probe command.
    pub async fn detect_remote_env(&self) -> anyhow::Result<RemoteEnv> {
        // The shell detection is wrapped in `sh -c '...'` so it works regardless
        // of the remote login shell (bash, csh, opnsense-shell, fish, etc.).
        // The login shell just needs to be able to invoke `sh` as an external command.
        let probe_cmd = "hostname; uname -s; uname -m; uname -r; pwd; sh -c 'command -v bash >/dev/null 2>&1 && echo bash || echo sh'";
        let output = tokio::process::Command::new("ssh")
            .args(self.base_args())
            .arg(&self.destination)
            .arg("--")
            .arg(probe_cmd)
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Remote environment detection failed: {}", stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() < 5 {
            bail!(
                "Unexpected output from remote probe (got {} lines)",
                lines.len()
            );
        }
        Ok(RemoteEnv {
            hostname: lines[0].to_string(),
            os: lines[1].to_string(),
            arch: lines[2].to_string(),
            kernel: lines[3].to_string(),
            home_dir: lines[4].to_string(),
            shell: lines.get(5).unwrap_or(&"sh").to_string(),
        })
    }

    /// Mount remote filesystem via sshfs.
    pub async fn mount_sshfs(
        &self,
        remote_dir: &str,
        mount_point: &str,
    ) -> anyhow::Result<()> {
        let source = format!("{}:{}", self.destination, remote_dir);
        let mut cmd = tokio::process::Command::new("sshfs");
        cmd.arg(&source);
        cmd.arg(mount_point);
        cmd.arg("-o")
            .arg(format!("ControlPath={}", self.control_path));
        cmd.arg("-o").arg("reconnect");
        cmd.arg("-o").arg("ServerAliveInterval=15");
        if let Some(port) = self.port {
            cmd.arg("-p").arg(port.to_string());
        }
        if let Some(ref id) = self.identity_file {
            cmd.arg("-o").arg(format!("IdentityFile={}", id));
        }
        for opt in &self.extra_opts {
            cmd.arg("-o").arg(opt);
        }
        let status = cmd.status().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("sshfs not found — install it (e.g., `sudo pacman -S sshfs` or `sudo apt install sshfs`)")
            } else {
                e.into()
            }
        })?;
        if !status.success() {
            bail!("sshfs mount failed (exit code: {:?})", status.code());
        }
        Ok(())
    }

    /// Read a file from the remote host. Returns None if the file doesn't exist.
    pub async fn read_remote_file(&self, path: &str) -> anyhow::Result<Option<String>> {
        let output = tokio::process::Command::new("ssh")
            .args(self.base_args())
            .arg(&self.destination)
            .arg("--")
            .arg(format!("cat {}", shell_quote(path)))
            .output()
            .await?;
        if output.status.success() {
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        } else {
            Ok(None)
        }
    }

    /// Execute a command on the remote host, returning a spawned child process
    /// with piped stdout/stderr for streaming.
    /// `remote_shell` specifies which shell to invoke (e.g. "bash" or "sh").
    pub fn spawn_remote_command(
        &self,
        remote_shell: &str,
        remote_cwd: &str,
        args: &[String],
    ) -> anyhow::Result<tokio::process::Child> {
        let remote_command = build_remote_command(remote_shell, remote_cwd, args);
        let mut cmd = tokio::process::Command::new("ssh");
        cmd.args(self.base_args());
        cmd.arg(&self.destination);
        cmd.arg("--");
        cmd.arg(&remote_command);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        Ok(cmd.spawn()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn test_shell_quote_spaces() {
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_quote_empty() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn test_shell_quote_special_chars() {
        assert_eq!(shell_quote("a;b&&c|d"), "'a;b&&c|d'");
    }

    #[test]
    fn test_build_remote_command_no_args_bash() {
        let cmd = build_remote_command("bash", "/home/user", &[]);
        assert_eq!(cmd, "cd '/home/user' && bash");
    }

    #[test]
    fn test_build_remote_command_with_args_bash() {
        let args = vec!["-c".to_string(), "echo hello".to_string()];
        let cmd = build_remote_command("bash", "/home/user", &args);
        assert_eq!(cmd, "cd '/home/user' && bash '-c' 'echo hello'");
    }

    #[test]
    fn test_build_remote_command_no_args_sh() {
        let cmd = build_remote_command("sh", "/home/user", &[]);
        assert_eq!(cmd, "cd '/home/user' && sh");
    }

    #[test]
    fn test_build_remote_command_with_args_sh() {
        let args = vec!["-c".to_string(), "echo hello".to_string()];
        let cmd = build_remote_command("sh", "/home/user", &args);
        assert_eq!(cmd, "cd '/home/user' && sh '-c' 'echo hello'");
    }

    // reorder_shell_args tests

    #[test]
    fn test_reorder_no_c_flag() {
        let args = vec!["script.sh".to_string()];
        assert_eq!(reorder_shell_args(&args), args);
    }

    #[test]
    fn test_reorder_c_already_last() {
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        assert_eq!(
            reorder_shell_args(&args),
            vec!["-c", "echo hi"]
        );
    }

    #[test]
    fn test_reorder_c_then_l() {
        // Claude Code pattern: bash -c -l "command"
        let args = vec![
            "-c".to_string(),
            "-l".to_string(),
            "echo hi".to_string(),
        ];
        assert_eq!(
            reorder_shell_args(&args),
            vec!["-l", "-c", "echo hi"]
        );
    }

    #[test]
    fn test_reorder_c_then_multiple_flags() {
        let args = vec![
            "-c".to_string(),
            "-l".to_string(),
            "-i".to_string(),
            "echo hi".to_string(),
        ];
        assert_eq!(
            reorder_shell_args(&args),
            vec!["-l", "-i", "-c", "echo hi"]
        );
    }

    #[test]
    fn test_reorder_flags_before_and_after_c() {
        let args = vec![
            "-l".to_string(),
            "-c".to_string(),
            "-i".to_string(),
            "echo hi".to_string(),
        ];
        assert_eq!(
            reorder_shell_args(&args),
            vec!["-l", "-i", "-c", "echo hi"]
        );
    }

    #[test]
    fn test_reorder_preserves_positional_after_command() {
        // sh -c "cmd" arg0 arg1 — positional args after command string
        let args = vec![
            "-c".to_string(),
            "-l".to_string(),
            "echo $0".to_string(),
            "hello".to_string(),
        ];
        assert_eq!(
            reorder_shell_args(&args),
            vec!["-l", "-c", "echo $0", "hello"]
        );
    }

    #[test]
    fn test_build_remote_command_reorders_for_sh() {
        // The real Claude Code pattern
        let args = vec![
            "-c".to_string(),
            "-l".to_string(),
            "shopt -u extglob 2>/dev/null || true && eval 'uname -a' < /dev/null".to_string(),
        ];
        let cmd = build_remote_command("sh", "/root", &args);
        assert_eq!(
            cmd,
            "cd '/root' && sh '-l' '-c' 'shopt -u extglob 2>/dev/null || true && eval '\\''uname -a'\\'' < /dev/null'"
        );
    }
}
