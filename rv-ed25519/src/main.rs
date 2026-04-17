#![no_std]
#![allow(incomplete_features)]
#![feature(allocator_api)]
#![feature(generic_const_exprs)]
#![no_main]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

extern "C" {
    // Boundaries of the heap
    static mut _sheap: usize;
    static mut _eheap: usize;

    // Boundaries of the stack
    static mut _sstack: usize;
    static mut _estack: usize;

    // Boundaries of the data region - to init .data section. Yet unused
    static mut _sdata: usize;
    static mut _edata: usize;
    static mut _sidata: usize;
}

core::arch::global_asm!(include_str!("../scripts/asm/asm_reduced.S"));

#[no_mangle]
extern "C" fn eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    rust_abort();
}

#[inline(never)]
pub fn zksync_os_finish_error() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub fn rust_abort() -> ! {
    zksync_os_finish_error()
}

#[link_section = ".init.rust"]
#[export_name = "_start_rust"]
unsafe extern "C" fn start_rust() -> ! {
    main()
}

#[export_name = "_setup_interrupts"]
pub unsafe fn custom_setup_interrupts() {
    extern "C" {
        fn _machine_start_trap();
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct MachineTrapFrame {
    pub registers: [u32; 32],
}

/// Exception (trap) handler in rust.
/// Called from the asm/asm.S
#[link_section = ".trap.rust"]
#[export_name = "_machine_start_trap_rust"]
pub extern "C" fn machine_start_trap_rust(_trap_frame: *mut MachineTrapFrame) -> usize {
    {
        unsafe { core::hint::unreachable_unchecked() }
    }
}

#[inline(never)]
pub fn zksync_os_finish_success(data: &[u32; 8]) -> ! {
    let mut result = [0u32; 16];
    result[..8].copy_from_slice(data);
    zksync_os_finish_success_extended(&result)
}

/// Set data as a output of the current execution.
/// By convention, the data that is stored in registers 10-25 after
/// execution has finished is considered 'output' of the computation.
#[inline(never)]
pub fn zksync_os_finish_success_extended(data: &[u32; 16]) -> ! {
    let data_ptr = core::hint::black_box(data.as_ptr().cast::<u32>());
    unsafe {
        core::arch::asm!(
            "lw x10, 0(x26)",
            "lw x11, 4(x26)",
            "lw x12, 8(x26)",
            "lw x13, 12(x26)",
            "lw x14, 16(x26)",
            "lw x15, 20(x26)",
            "lw x16, 24(x26)",
            "lw x17, 28(x26)",
            "lw x18, 32(x26)",
            "lw x19, 36(x26)",
            "lw x20, 40(x26)",
            "lw x21, 44(x26)",
            "lw x22, 48(x26)",
            "lw x23, 52(x26)",
            "lw x24, 56(x26)",
            "lw x25, 60(x26)",
            in("x26") data_ptr,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            out("x18") _,
            out("x19") _,
            out("x20") _,
            out("x21") _,
            out("x22") _,
            out("x23") _,
            out("x24") _,
            out("x25") _,
            options(nostack, preserves_flags)
        )
    }
    loop {
        continue;
    }
}

#[inline(always)]
fn csr_write_word(word: usize) {
    unsafe {
        core::arch::asm!(
            "csrrw x0, 0x7c0, {rd}",
            rd = in(reg) word,
            options(nomem, nostack, preserves_flags)
        )
    }
}

/// QuasiUART start marker recognized by the simulator host logger.
const QUASI_UART_HELLO: u32 = u32::MAX;

/// Send a log line to host console using QuasiUART framing on CSR 0x7c0.
fn guest_log(msg: &str) {
    let bytes = msg.as_bytes();
    let len = bytes.len();
    csr_write_word(QUASI_UART_HELLO as usize);
    csr_write_word(len.next_multiple_of(4) / 4 + 1);
    csr_write_word(len);

    let mut i = 0usize;
    while i < len {
        let mut chunk = [0u8; 4];
        let end = (i + 4).min(len);
        chunk[..end - i].copy_from_slice(&bytes[i..end]);
        csr_write_word(u32::from_le_bytes(chunk) as usize);
        i = end;
    }
}

#[inline(always)]
const fn to_hex_ascii(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

fn log_bytes_hex(label: &str, bytes: &[u8]) {
    // Covers up to 64 bytes (signature), i.e. 128 hex chars.
    let mut hex = [0u8; 128];
    let hex_len = bytes.len() * 2;
    if hex_len > hex.len() {
        guest_log("[rv-ed25519] hex buffer too small");
        return;
    }

    for (i, &byte) in bytes.iter().enumerate() {
        hex[2 * i] = to_hex_ascii(byte >> 4);
        hex[2 * i + 1] = to_hex_ascii(byte & 0x0f);
    }

    guest_log(label);
    if let Ok(hex_str) = core::str::from_utf8(&hex[..hex_len]) {
        guest_log(hex_str);
    } else {
        guest_log("[rv-ed25519] failed to encode bytes hex");
    }
}

unsafe fn workload() -> ! {
    let message = b"hardcoded message from fastcrypto";
    let public_key_bytes = [
        234u8, 74, 108, 99, 226, 156, 82, 10, 190, 245, 80, 123, 19, 46, 197, 249, 149, 71,
        118, 174, 190, 190, 123, 146, 66, 30, 234, 105, 20, 70, 210, 44,
    ];
    let signature_bytes = [
        255u8, 245, 39, 85, 27, 98, 207, 130, 204, 178, 39, 144, 23, 135, 11, 44, 178, 66, 250,
        5, 7, 69, 235, 140, 203, 65, 176, 44, 235, 27, 1, 96, 20, 10, 137, 2, 108, 142, 64, 247,
        88, 134, 39, 85, 181, 252, 11, 36, 249, 23, 96, 20, 200, 28, 102, 3, 172, 1, 199, 194,
        188, 216, 167, 15,
    ];
    log_bytes_hex("[rv-ed25519] public_key_bytes hex:", &public_key_bytes);
    log_bytes_hex("[rv-ed25519] signature_bytes hex:", &signature_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(vk) => vk,
        Err(_) => rust_abort(),
    };
    let signature = Signature::from_bytes(&signature_bytes);
    if verifying_key.verify(message, &signature).is_err() {
        guest_log("[rv-ed25519] signature verification failed");
        rust_abort();
    }

    guest_log("[rv-ed25519] signature verification passed");

    let mut key_words = [0u32; 8];
    for (i, chunk) in public_key_bytes.chunks_exact(4).enumerate() {
        key_words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    zksync_os_finish_success(&[
        key_words[0],
        key_words[1],
        key_words[2],
        key_words[3],
        key_words[4],
        key_words[5],
        key_words[6],
        key_words[7],
    ]);
}

#[inline(never)]
fn main() -> ! {
    unsafe { workload() }
}