#![no_std]

pub const MAX_PATH: usize = 128;
pub const MAX_NAME: usize = 64;

#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; MAX_PATH],
    pub argv1: [u8; MAX_PATH], // the first argument: the file being edited if it is vim
}