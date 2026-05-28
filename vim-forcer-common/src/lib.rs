#![no_std]

pub const MAX_PATH: usize = 128;
pub const MAX_NAME: usize = 64;

pub const MATCH_KIND_WATCHED_NAME: u32 = 1;
pub const MATCH_KIND_EDITOR_ARG_CANDIDATE: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CandidateActivity {
    pub window_start_ns: u64,
    pub suppress_until_ns: u64,
    pub count: u32,
}

#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub match_kind: u32,
    pub filename: [u8; MAX_PATH],
    pub argv1: [u8; MAX_PATH], // the first argument: the file being edited if it is vim
}
