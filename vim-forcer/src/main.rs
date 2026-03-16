use std::{collections::HashMap as StdHashMap, fs, os::unix::{io::IntoRawFd, process::CommandExt}, process::Command};

use clap::Parser;

#[derive(Parser)]
#[command(about = "Force vim on users running other editors")]
struct Args {
    /// Comma-separated list of tools to intercept
    #[arg(short = 'e', default_value = "nano")]
    tools: String,

    /// File to write per-user swap counts to
    #[arg(short = 'o')]
    output_file: Option<String>,
}

use aya::{Pod, maps::{HashMap, RingBuf}, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::unix::AsyncFd, signal};

use vim_forcer_common::{ExecEvent,MAX_NAME,MAX_PATH};


// Convert string to bytes for better kernel access
fn add_watched_tool(map: &mut HashMap<&mut aya::maps::MapData, [u8; MAX_NAME], u8>, tool: &str) {
    let mut key = [0u8; MAX_NAME];
    let bytes = tool.as_bytes();
    let len = bytes.len().min(MAX_NAME-1); // leave room for null terminator
    key[..len].copy_from_slice(&bytes[..len]);
    map.insert(key, 1, 0).expect("failed to insert tool");
}

// TODO: this should only be done once at start, is there a better way?
fn username_for_uid(uid: u32) -> String {
    fs::read_to_string("/etc/passwd").ok()
        .and_then(|contents| {
            contents.lines()
                .find(|line| {
                    let mut fields = line.splitn(4, ':');
                    fields.next();
                    fields.next();
                    fields.next().and_then(|s| s.parse::<u32>().ok()) == Some(uid)
                })
                .and_then(|line| line.split(':').next().map(String::from))
        })
        .unwrap_or_else(|| uid.to_string())
}

// TODO: better file format obviously needed.
// The idea is to read/store it somewhere for e.g. motd to read it.
fn write_swap_counts(path: &str, counts: &StdHashMap<u32, u64>) {
    let mut lines: Vec<String> = counts
        .iter()
        .map(|(&uid, &count)| format!("{}: {}", username_for_uid(uid), count))
        .collect();
    lines.sort();
    if let Err(e) = fs::write(path, lines.join("\n") + "\n") {
        warn!("failed to write swap counts to {}: {}", path, e);
    }
}

fn get_parent_pid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(ppid) = line.strip_prefix("PPid:\t") {
            return ppid.trim().parse().ok();
        }
    }
    None
}

fn get_gid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Gid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn vim_swap(pid: u32, uid: u32, file_arg: &str) {
    // Get tty of terminal that currently runs editor
    let tty = match fs::read_link(format!("/proc/{}/fd/0", pid)) {
        Ok(t) => t,
        Err(_) => return,
    };

    // If path is relative, capture it from the working directory of the terminal
    let file_path = if file_arg.starts_with('/') {
        file_arg.to_string()
    } else {
        match fs::read_link(format!("/proc/{}/cwd", pid)) {
            Ok(cwd) => cwd.join(file_arg).to_string_lossy().to_string(),
            Err(_) => file_arg.to_string(),
        }
    };

    // Read gid before killing the process (proc entry disappears after kill)
    let gid = get_gid(pid).unwrap_or(uid);

    // Get parent shell PID before killing current editor (proc entry disappears after kill)
    let shell_pid = get_parent_pid(pid);

    // Important: We need to stop the shell first so it can't reclaim the TTY when we kill nano
    if let Some(spid) = shell_pid {
        unsafe { libc::kill(spid as i32, libc::SIGSTOP); }
    }

    // Now we kill nano
    unsafe { libc::kill(pid as i32, libc::SIGKILL); }
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Claim TTY
    let tty_fd = match std::fs::OpenOptions::new().read(true).write(true).open(tty) {
        Ok(f) => f.into_raw_fd(),
        Err(_) => {
            // If failed to get tty, resume shell by sending SIGCONT
            if let Some(spid) = shell_pid {
                unsafe { libc::kill(spid as i32, libc::SIGCONT); }
            }
            return;
        }
    };

    // Spawn vim on tty
    std::thread::spawn(move || {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", &format!("stty sane; clear; exec vim '{}'", file_path)]);
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::dup2(tty_fd, 0);
                libc::dup2(tty_fd, 1);
                libc::dup2(tty_fd, 2);
                if tty_fd > 2 {
                    libc::close(tty_fd);
                }
                libc::tcflush(0, libc::TCIFLUSH);
                // Drop privileges to the original user
                libc::setresgid(gid, gid, gid);
                libc::setresuid(uid, uid, uid);
                Ok(())
            });
        }
        if let Ok(mut child) = cmd.spawn() {
            child.wait().ok();
        }
        // Resume the shell once vim exits
        if let Some(spid) = shell_pid {
            unsafe { libc::kill(spid as i32, libc::SIGCONT); }
            // TODO: Send clear command? We can still see the kill message after returning from vim
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vim-forcer"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut TracePoint = ebpf.program_mut("detect_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // ---------------- After template! ----------------

    let mut watched: HashMap<_, [u8; MAX_NAME], u8> =
        HashMap::try_from(ebpf.map_mut("WATCHED_TOOLS").unwrap())?;

    let tools: Vec<&str> = args.tools.split(',').map(str::trim).collect();
    let output_file = args.output_file;

    for tool in &tools {
        add_watched_tool(&mut watched, tool);
        println!("Watching: {}", tool);
    }

    // Channel from kernel, use asyncfc to wait for events without polling
    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    let mut swap_counts: StdHashMap<u32, u64> = StdHashMap::new();

    loop {
        // Wait for data to be available
        let mut guard = async_fd.readable_mut().await?;
        let ring = guard.get_inner_mut();

        while let Some(item) = ring.next() {
            let data = item.as_ref(); // Data is read as slice of bytes
            if data.len() >= std::mem::size_of::<ExecEvent>() {

                // Read data from pointed memory, necessary unsafe action
                let event: &ExecEvent = unsafe { &*(data.as_ptr() as *const ExecEvent) };

                let path = std::str::from_utf8(&event.filename)
                    .unwrap_or_default()
                    .trim_end_matches('\0');
                let arg = std::str::from_utf8(&event.argv1)
                    .unwrap_or_default()
                    .trim_end_matches('\0');

                *swap_counts.entry(event.uid).or_insert(0) += 1;
                println!("PID {} exec {} {} - Swapping to VIM!", event.pid, path, arg);
                if let Some(ref out) = output_file {
                    write_swap_counts(out, &swap_counts);
                }


                // Now swap to VIM
                vim_swap(event.pid, event.uid, arg);

            }
        }

        guard.clear_ready();
    }

    Ok(())
}
