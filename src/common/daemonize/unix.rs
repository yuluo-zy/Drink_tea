use std::fs::File;
use std::path::Path;

use daemonize::Daemonize;
use log::error;

/// Daemonize a server process in a *nix standard way
///
/// This function will redirect `stdout`, `stderr` to `/dev/null`,
pub fn daemonize<F: AsRef<Path>>(pid_path: Option<F>) {
    let stdout = File::create("/tmp/daemon.out").unwrap();
    let stderr = File::create("/tmp/daemon.err").unwrap();

    let mut d = Daemonize::new()
        .umask(0)
        .chroot("/")
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr);
    if let Some(p) = pid_path {
        d = d.pid_file(p);
    }

    if let Err(err) = d.start() {
        error!("failed to daemonize, {}", err);
    }
}
