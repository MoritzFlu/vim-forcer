#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use vim_forcer_common::{
    CandidateActivity, ExecEvent, MATCH_KIND_EDITOR_ARG_CANDIDATE, MATCH_KIND_WATCHED_NAME,
    MAX_NAME, MAX_PATH,
};

const NS_PER_SEC: u64 = 1_000_000_000;
const CANDIDATE_WINDOW_NS: u64 = 60 * NS_PER_SEC;
const CANDIDATE_SUPPRESS_NS: u64 = 5 * 60 * NS_PER_SEC;
const CANDIDATE_REPEAT_THRESHOLD: u32 = 3;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
#[map]
static CANDIDATE_ACTIVITY: HashMap<[u8; MAX_NAME], CandidateActivity> =
    HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn detect_exec(ctx: TracePointContext) -> u32 {
    match try_detect_exec(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn has_non_flag_arg(arg: &[u8; MAX_PATH]) -> bool {
    arg[0] != 0 && arg[0] != b'-'
}

fn is_nano_basename(name: &[u8; MAX_NAME]) -> bool {
    name[0] == b'n' && name[1] == b'a' && name[2] == b'n' && name[3] == b'o' && name[4] == 0
}

fn should_emit_candidate(key: &[u8; MAX_NAME]) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };

    let mut activity = match unsafe { CANDIDATE_ACTIVITY.get(key) } {
        Some(existing) => *existing,
        None => CandidateActivity {
            window_start_ns: now,
            suppress_until_ns: 0,
            count: 0,
        },
    };

    if activity.suppress_until_ns > now {
        return false;
    }

    if now.saturating_sub(activity.window_start_ns) > CANDIDATE_WINDOW_NS {
        activity.window_start_ns = now;
        activity.count = 0;
    }

    activity.count = activity.count.saturating_add(1);
    let emit = activity.count < CANDIDATE_REPEAT_THRESHOLD;

    if !emit {
        activity.suppress_until_ns = now.saturating_add(CANDIDATE_SUPPRESS_NS);
    }

    let _ = CANDIDATE_ACTIVITY.insert(key, &activity, 0);
    emit
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

    let watched_name = is_nano_basename(&key);
    let mut argv1 = [0u8; MAX_PATH];

    let arg1_ptr: *const u8 = match unsafe { bpf_probe_read_user(argv_ptr.add(1)) } {
        Ok(ptr) => ptr,
        Err(_) => return Ok(0),
    };
    if !arg1_ptr.is_null() {
        unsafe {
            bpf_probe_read_user_str_bytes(arg1_ptr, &mut argv1)?;
        }
    }

    let mut match_kind = MATCH_KIND_WATCHED_NAME;
    if !watched_name {
        // eBPF can cheaply inspect launch metadata such as argv. It cannot open
        // filename and hash or parse the executable here; userspace must do that.
        if !has_non_flag_arg(&argv1) {
            return Ok(0);
        }
        if !should_emit_candidate(&key) {
            return Ok(0);
        }
        match_kind = MATCH_KIND_EDITOR_ARG_CANDIDATE;
    }

    // Reserve space in the ring buffer
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*event).uid = bpf_get_current_uid_gid() as u32;
            (*event).match_kind = match_kind;
            (*event).filename = full_path;
            (*event).argv1 = argv1;
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
