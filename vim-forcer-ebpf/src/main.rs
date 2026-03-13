#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use aya_log_ebpf::info;
use vim_forcer_common::{MAX_NAME,MAX_PATH,ExecEvent};

#[map]
static WATCHED_TOOLS: HashMap<[u8; MAX_NAME], u8> = HashMap::with_max_entries(64, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn detect_exec(ctx: TracePointContext) -> u32 {
    match try_detect_exec(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_detect_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16)? };
    let argv_ptr: *const *const u8 = unsafe { ctx.read_at(24)? };

    // Read the full executable path
    let mut full_path = [0u8; MAX_PATH];
    unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut full_path)?;
    }

    // Find the start of the basename (byte after the last '/')
    let mut basename_start = 0usize;
    for i in 0..MAX_PATH {
        if full_path[i] == b'/' {
            basename_start = i + 1;
        }
    }

    // Read the basename directly from userspace at filename_ptr + basename_start.
    // Using a helper avoids a manual copy loop with a runtime-variable index,
    // which would cause O(MAX_PATH * MAX_NAME) verifier state explosion.
    let mut key = [0u8; MAX_NAME];
    unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr.add(basename_start), &mut key)?;
    }

    // Lookup — if not in the map, skip entirely
    if unsafe { WATCHED_TOOLS.get(key) }.is_none() {
        return Ok(0);
    }

    // Reserve space in the ring buffer
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*event).uid = bpf_get_current_uid_gid() as u32;
            (*event).filename = full_path;
            (*event).argv1 = [0u8; MAX_PATH];

            let arg1_ptr: *const u8 = match bpf_probe_read_user(argv_ptr.add(1)) {
                Ok(ptr) => ptr,
                Err(_) => {
                    entry.discard(0);
                    return Ok(0);
                }
            };
            if !arg1_ptr.is_null()
                && bpf_probe_read_user_str_bytes(arg1_ptr, &mut (*event).argv1).is_err()
            {
                entry.discard(0);
                return Ok(0);
            }
        }
        entry.submit(0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
