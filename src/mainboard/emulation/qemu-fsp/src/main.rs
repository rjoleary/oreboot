#![feature(lang_items, start)]
#![no_std]
#![no_main]
#![feature(global_asm)]

use arch::bzimage::BzImage;
use arch::ioport::IOPort;
use core::fmt;
use core::fmt::Write;
use core::mem::size_of;
use core::num::Wrapping;
use core::panic::PanicInfo;
use core::slice;
use model::Driver;
use print;
use uart::i8250::I8250;

use fsp_qemu_sys::{
    EFI_COMMON_SECTION_HEADER, EFI_COMMON_SECTION_HEADER2, EFI_FFS_FILE_HEADER, EFI_FFS_FILE_HEADER2, EFI_FIRMWARE_VOLUME_EXT_HEADER, EFI_FIRMWARE_VOLUME_HEADER, EFI_FV_FILETYPE_RAW, EFI_GUID, EFI_SECTION_RAW, FFS_ATTRIB_CHECKSUM, FFS_ATTRIB_LARGE_FILE,
    FSPS_UPD, FSP_INFO_HEADER,
};

// Unless we mention the fsp_qemu_sys crate, the compiler will optimize it away. This crate
// introduces the symbols containing the FSP binary which get picked up by the linker.
extern crate fsp_qemu_sys;

global_asm!(include_str!("../../../../arch/x86/x86_64/src/bootblock.S"));

#[no_mangle]
pub extern "C" fn _start(_fdt_address: usize) -> ! {
    let io = &mut IOPort;
    let uart0 = &mut I8250::new(0x3f8, 0, io);
    uart0.init().unwrap();
    uart0.pwrite(b"Welcome to oreboot\r\n", 0).unwrap();

    let w = &mut print::WriteTo::new(uart0);

    match find_fsp(0xFFF80000) {
        Ok(x) => {
            write!(w, "Found FSP: {:x?}\r\n", x).unwrap();
            unsafe {
                let fsps = core::mem::transmute::<usize, unsafe extern "C" fn(*const FSPS_UPD)>((0xFFF80000 + x.FspSiliconInitEntryOffset) as usize);
                fsps(0 as *const FSPS_UPD);
            }
        }
        Err(err) => panic!("Error finding FSP: {}\r\n", err),
    };

    // TODO: Get these values from the fdt
    let payload = &mut BzImage { low_mem_size: 0x80_000_000, high_mem_start: 0x1_000_000_000, high_mem_size: 0, rom_base: 0xff_000_000, rom_size: 0x1_000_000, load: 0x1_000_000, entry: 0x1_000_200 };

    write!(w, "Running payload\r\n").unwrap();
    payload.run(w);

    write!(w, "Unexpected return from payload\r\n").unwrap();
    arch::halt()
}

enum FvTraverseError {
    InvalidFvGuid { base: usize, guid: EFI_GUID },
    InvalidFvChecksum { base: usize, checksum: u16 },
    InvalidFfsSize { base: usize },
    InvalidFfsHeaderChecksum { base: usize, checksum: u8 },
    InvalidFfsDataChecksum { base: usize, got_checksum: u8, want_checksum: u8 },
}

use FvTraverseError::*;

impl fmt::Display for FvTraverseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidFvGuid { base, guid } => write!(f, "FV@0x{:x} has invalid guid {:?}, expected {:?} or {:?}", base, guid, EFI_FIRMWARE_FILE_SYSTEM2_GUID, EFI_FIRMWARE_FILE_SYSTEM3_GUID),
            InvalidFvChecksum { base, checksum } => write!(f, "FV@0x{:x} has invalid checksum {:x}, expected 0", base, checksum),
            InvalidFfsSize { base } => write!(f, "FV@0x{:x} has invalid extended size", base),
            InvalidFfsHeaderChecksum { base, checksum } => write!(f, "FV@0x{:x} ffs has invalid checksum 0x{:x}, expected 0", base, checksum),
            InvalidFfsDataChecksum { base, got_checksum, want_checksum } => write!(f, "FV@0x{:x} ffs has invalid checksum 0x{:x}, expected 0x{:x}", base, got_checksum, want_checksum),
        }
    }
}

const EFI_FIRMWARE_FILE_SYSTEM2_GUID: EFI_GUID = EFI_GUID(0x8c8ce578, 0x8a3d, 0x4f1c, [0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3]);
const EFI_FIRMWARE_FILE_SYSTEM3_GUID: EFI_GUID = EFI_GUID(0x5473c07a, 0x3dcb, 0x4dca, [0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a]);
const EFI_FVH_SIGNATURE: u32 = 0x4856465f; // "FVH_"

const FSP_FFS_INFORMATION_FILE_GUID: EFI_GUID = EFI_GUID(0x912740be, 0x2284, 0x4734, [0xb9, 0x71, 0x84, 0xb0, 0x27, 0x35, 0x3f, 0x0c]);
const FSP_S_UPD_FFS_GUID: EFI_GUID = EFI_GUID(0xe3cd9b18, 0x998c, 0x4f76, [0xb6, 0x5e, 0x98, 0xb1, 0x54, 0xe5, 0x44, 0x6f]);

#[no_mangle]
fn find_fsp(fsp_base: usize) -> Result<FSP_INFO_HEADER, FvTraverseError> {
    let mut info: Option<FSP_INFO_HEADER> = None;

    fv_traverse(fsp_base, |guid, file_type, sec_type, data| {
        // All three parts must match.
        match (guid, file_type, sec_type) {
            (FSP_FFS_INFORMATION_FILE_GUID, EFI_FV_FILETYPE_RAW, EFI_SECTION_RAW) => {
                info = Some(unsafe { *(data.as_ptr() as *const FSP_INFO_HEADER) }.clone());
            }
            (FSP_S_UPD_FFS_GUID, EFI_FV_FILETYPE_RAW, EFI_SECTION_RAW) => (),
            _ => (),
        }
    })?;

    match info {
        None => panic!("couldn't find fsp"),
        Some(x) => Ok(x),
    }
}

fn fv_traverse<F>(base: usize, mut visitor: F) -> Result<(), FvTraverseError>
where
    F: FnMut(EFI_GUID, u32, u32, &[u8]),
{
    // This procedure is defined in the FSP spec and the "Platform Initialization Specification,
    // Vol. 3".
    let mut counter = base;

    for fv_idx in 0.. {
        let fv = unsafe { &*(counter as *const EFI_FIRMWARE_VOLUME_HEADER) };

        // Check FV header signature.
        if fv.Signature != EFI_FVH_SIGNATURE {
            break;
        }

        // Check FV header GUID.
        if fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM2_GUID && fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM3_GUID {
            return Err(InvalidFvGuid { base, guid: fv.FileSystemGuid.clone() });
        }

        // Check FV header checksum.
        let words = unsafe { slice::from_raw_parts(counter as *const u16, size_of::<EFI_FIRMWARE_VOLUME_HEADER>() / 2) };
        let checksum = words.iter().fold(0u16, |sum, &val| (Wrapping(sum) + Wrapping(val)).0);
        if checksum != 0 {
            return Err(InvalidFvChecksum { base, checksum });
        }

        // Skip FV headers.
        let fv_end = counter + fv.FvLength as usize;
        if fv.ExtHeaderOffset == 0 {
            counter += fv.HeaderLength as usize;
        } else {
            counter += fv.ExtHeaderOffset as usize;
            let fveh = unsafe { &*(counter as *const EFI_FIRMWARE_VOLUME_EXT_HEADER) };
            counter += fveh.ExtHeaderSize as usize;
        }

        // Iterate through files.
        while {
            counter = (counter + 7) & !7; // align to 8 bytes
            counter < fv_end
        } {
            let ffs = unsafe { &*(counter as *const EFI_FFS_FILE_HEADER) };

            // Determine the file sizes.
            let (ffs_header_size, ffs_size) = if ffs.Attributes & (FFS_ATTRIB_LARGE_FILE as u8) == 0 {
                (size_of::<EFI_FFS_FILE_HEADER>(), little_endian3(ffs.Size))
            } else {
                match little_endian3(ffs.Size) {
                    0xffffff => break, // Reached FV free space.
                    0 => (),
                    _ => return Err(InvalidFfsSize { base }),
                }
                (size_of::<EFI_FFS_FILE_HEADER2>(), unsafe { &*(counter as *const EFI_FFS_FILE_HEADER2) }.ExtendedSize as usize)
            };
            let ffs_data_size = ffs_size - ffs_header_size;

            // Check the FFS header checksum.
            let file_checksum = unsafe { ffs.IntegrityCheck.Checksum.File };
            let bytes = unsafe { slice::from_raw_parts(counter as *const u8, ffs_header_size) };
            let checksum = (bytes.iter().fold(Wrapping(0u8), |sum, &val| sum + Wrapping(val)) - Wrapping(ffs.State) - Wrapping(file_checksum)).0;
            if checksum != 0 {
                return Err(InvalidFfsHeaderChecksum { base, checksum });
            }

            // Check the FFS file checksum.
            if ffs.Attributes & (FFS_ATTRIB_CHECKSUM as u8) == 0 {
                if file_checksum != 0xaa {
                    return Err(InvalidFfsDataChecksum { base, got_checksum: file_checksum, want_checksum: 0xaa });
                }
            } else {
                let bytes = unsafe { slice::from_raw_parts((counter + ffs_header_size) as *const u8, ffs_data_size) };
                let checksum = bytes.iter().fold(0u8, |sum, &val| (Wrapping(sum) + Wrapping(val)).0);
                if checksum != file_checksum {
                    return Err(InvalidFfsDataChecksum { base, got_checksum: checksum, want_checksum: file_checksum });
                }
            }

            // Skip the FFS header.
            counter += ffs_header_size;

            // Iterate through sections.
            let file_end = counter + ffs_data_size;
            while {
                counter = (counter + 3) & !3; // align to 4 bytes
                counter < file_end
            } {
                let section_common = unsafe { &*(counter as *const EFI_COMMON_SECTION_HEADER) };

                // Determine section sizes.
                let (section_header_size, section_size) = match little_endian3(section_common.Size) {
                    0xffffff => (size_of::<EFI_COMMON_SECTION_HEADER2>(), unsafe { &*(counter as *const EFI_COMMON_SECTION_HEADER2) }.ExtendedSize as usize),
                    x => (size_of::<EFI_COMMON_SECTION_HEADER>(), x),
                };
                let section_data_size = section_size - section_header_size;

                // Apply visitor.
                let bytes = unsafe { slice::from_raw_parts((counter + section_header_size) as *const u8, section_data_size) };
                visitor(ffs.Name.clone(), ffs.Type as u32, section_common.Type as u32, bytes);

                // Skip to next section.
                counter += section_size;
            }
        }
    }
    Ok(())
}

fn little_endian3(x: [u8; 3]) -> usize {
    ((x[2] as usize) << 16) | ((x[1] as usize) << 8) | (x[0] as usize)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Assume that uart0.init() has already been called before the panic.
    let io = &mut IOPort;
    let uart0 = &mut I8250::new(0x3f8, 0, io);
    let w = &mut print::WriteTo::new(uart0);
    // Printing in the panic handler is best-effort because we really don't want to invoke the panic
    // handler from inside itself.
    let _ = write!(w, "PANIC: {}\r\n", info);
    arch::halt()
}
