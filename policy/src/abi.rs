//! Fresh-instance WASM-v2 argument arena, following upstream evaluators/v2.rs.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{addr_of, addr_of_mut, null_mut};

pub const MAX_VIEW: usize = 1_048_576;
const MAX_ARGUMENT: usize = 65_536;
const INPUT_CAPACITY: usize = MAX_VIEW + 3 * MAX_ARGUMENT;
static mut INPUT: [u8; INPUT_CAPACITY] = [0; INPUT_CAPACITY];
static mut INPUT_USED: usize = 0;

// Deserialization is the only heap user. Client JSON is capped at 4096 bytes;
// this separate, aligned arena bounds all String and parser scratch allocations.
// The host creates a fresh instance per request and forbids reentrancy.
#[repr(C, align(16))]
struct Heap([u8; 65_536]);
static mut HEAP: Heap = Heap([0; 65_536]);
static mut HEAP_USED: usize = 0;
struct Arena;

#[global_allocator]
static ALLOCATOR: Arena = Arena;

unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = addr_of_mut!(HEAP).cast::<u8>() as usize;
        let Some(start) = base
            .checked_add(HEAP_USED)
            .and_then(|address| address.checked_add(layout.align() - 1))
            .map(|address| address & !(layout.align() - 1))
        else {
            return null_mut();
        };
        let Some(end) = start
            .checked_sub(base)
            .and_then(|offset| offset.checked_add(layout.size()))
        else {
            return null_mut();
        };
        if end > 65_536 {
            return null_mut();
        }
        HEAP_USED = end;
        start as *mut u8
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        // The complete instance, including this bounded heap, is discarded.
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[no_mangle]
pub extern "C" fn sapio_alloc_v2(length: u32) -> u32 {
    unsafe {
        let used = INPUT_USED;
        let Some(end) = used.checked_add(length as usize) else {
            return 0;
        };
        if end > INPUT_CAPACITY {
            return 0;
        }
        INPUT_USED = end;
        addr_of_mut!(INPUT).cast::<u8>().add(used) as u32
    }
}

pub struct Arguments<'a> {
    pub parameters: &'a [u8],
    pub view: &'a [u8],
    pub witness: &'a [u8],
}

pub fn arguments(pointers: [u32; 8]) -> Option<Arguments<'static>> {
    let [pp, pl, ap, al, vp, vl, wp, wl] = pointers;
    if [pl, al, wl]
        .iter()
        .any(|length| *length as usize > MAX_ARGUMENT)
        || vl as usize > MAX_VIEW
    {
        return None;
    }
    // Inline programs have no additional program bytecode argument.
    if !input_slice(pp, pl)?.is_empty() {
        return None;
    }
    Some(Arguments {
        parameters: input_slice(ap, al)?,
        view: input_slice(vp, vl)?,
        witness: input_slice(wp, wl)?,
    })
}

fn input_slice(pointer: u32, length: u32) -> Option<&'static [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    let start = addr_of!(INPUT).cast::<u8>() as usize;
    let offset = (pointer as usize).checked_sub(start)?;
    let end = offset.checked_add(length as usize)?;
    // Never turn arbitrary guest pointers into slices. Input memory is not
    // mutated by the evaluator, and deserializer scratch lives in HEAP.
    unsafe {
        if end > INPUT_USED {
            return None;
        }
        Some(core::slice::from_raw_parts(
            pointer as *const u8,
            length as usize,
        ))
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn sized(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    pub fn finish(self) -> Option<()> {
        (self.remaining() == 0).then_some(())
    }
}
