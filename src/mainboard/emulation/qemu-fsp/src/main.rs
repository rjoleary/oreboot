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

use heapless::Vec;
use heapless::consts::U4;

use fsp_qemu_sys as efi;
use efi::EFI_GUID as GUID;

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

    const FSP_BASE: usize = 0xFFF80000;
    let infos = match find_fsp(FSP_BASE) {
        Ok(x) => x,
        Err(err) => panic!("Error finding FSP: {}\r\n", err),
    };
    write!(w, "Found FSP_INFO: {:#x?}\r\n", infos).unwrap();

    if let Some(fspm_entry) = FspMemoryInitEntry(&infos) {
        write!(w, "Calling FspMemoryInit@{:#x}\r\n", fspm_entry).unwrap();

        // TODO: This struct has to be aligned to 4.
        // mut because we can't make the assumption FSP won't modify it.
        let mut fspm_upd = efi::FSPM_UPD{
            FspUpdHeader: efi::FSP_UPD_HEADER{
                Signature: efi::FSPM_UPD_SIGNATURE,
                Revision: 2, // FSP 2.2
                Reserved: [0u8; 23],
            },
            FspmArchUpd: efi::FSPM_ARCH_UPD{
                Revision: 2, // FSP 2.2
                Reserved: [0u8; 3],
                NvsBufferPtr: 0, // non-volatile storage not available
                StackBase: 0x20000000, // TODO: I picked this at random
                StackSize: 0x10000, // TODO: I picked this at random
                BootLoaderTolumSize: 0, // Don't reserve "top of low usable memory" for bootloader.
                BootMode: efi::BOOT_WITH_FULL_CONFIGURATION,
                FspEventHandler: 0 as *mut efi::FSP_EVENT_HANDLER, // optional
                Reserved1: [0u8; 4],
            },
            FspmConfig: efi::FSP_M_CONFIG{
                SerialDebugPortAddress: 0x3f8,
                SerialDebugPortType: 1, // I/O
                SerialDebugPortDevice: 3, // External Device
                SerialDebugPortStrideSize: 0, // 1
                UnusedUpdSpace0: [0; 49],
                ReservedFspmUpd: [0; 4],
            },
            UnusedUpdSpace1: [0u8; 2],
            UpdTerminator: 0x55AA, // ???
        };

        let status = unsafe {
            type FSP_MEMORY_INIT = unsafe extern "win64" fn(FspmUpdDataPtr: *mut core::ffi::c_void, HobListPtr: *mut *mut core::ffi::c_void) -> efi::EFI_STATUS;
            let fsps = core::mem::transmute::<usize, FSP_MEMORY_INIT>(fspm_entry);
            fsps(core::mem::transmute(&mut fspm_upd), 0 as *mut _)
        };
        write!(w, "Returned {}\r\n", status);
    } else {
        write!(w, "Could not find FspMemoryInit\r\n");
    }

    /*write!(w, "Calling FSP-M\r\n").unwrap();

    write!(w, "Calling FSP-S\r\n").unwrap();

    let status = unsafe {
        let fsps = core::mem::transmute::<usize, unsafe extern "efiapi" fn(*const efi::FSPS_UPD) -> efi::EFI_STATUS>((FSP_BASE + x.FspSiliconInitEntryOffset) as usize);
        fsps(0 as *const efi::FSPS_UPD)
    };
    write!(w, "FSPS Status: {}", status);
    */

    // TODO: Get these values from the fdt
    let payload = &mut BzImage { low_mem_size: 0x80_000_000, high_mem_start: 0x1_000_000_000, high_mem_size: 0, rom_base: 0xff_000_000, rom_size: 0x1_000_000, load: 0x1_000_000, entry: 0x1_000_200 };

    write!(w, "Running payload\r\n").unwrap();
    payload.run(w);

    write!(w, "Unexpected return from payload\r\n").unwrap();
    arch::halt()
}

enum FvTraverseError {
    InvalidFvGuid { base: usize, guid: GUID },
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

const EFI_FIRMWARE_FILE_SYSTEM2_GUID: GUID = GUID(0x8c8ce578, 0x8a3d, 0x4f1c, [0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3]);
const EFI_FIRMWARE_FILE_SYSTEM3_GUID: GUID = GUID(0x5473c07a, 0x3dcb, 0x4dca, [0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a]);
const EFI_FVH_SIGNATURE: u32 = 0x4856465f; // "FVH_"

const FSP_FFS_INFORMATION_FILE_GUID: GUID = GUID(0x912740be, 0x2284, 0x4734, [0xb9, 0x71, 0x84, 0xb0, 0x27, 0x35, 0x3f, 0x0c]);
const FSP_S_UPD_FFS_GUID: GUID = GUID(0xe3cd9b18, 0x998c, 0x4f76, [0xb6, 0x5e, 0x98, 0xb1, 0x54, 0xe5, 0x44, 0x6f]);

#[derive(Debug)]
struct FspInfoEntry {
    addr: usize,
    info: efi::FSP_INFO_HEADER,
}
type FspInfos = Vec<FspInfoEntry, U4>;

fn FspMemoryInitEntry(infos: &FspInfos) -> Option<usize> {
    for entry in infos.iter() {
        if entry.info.ComponentAttribute & 0xf000 == 0x2000 {
            return Some(entry.addr + entry.info.FspMemoryInitEntryOffset as usize)
        }
    }
    None
}

#[no_mangle]
fn find_fsp(fsp_base: usize) -> Result<FspInfos, FvTraverseError> {
    let mut infos = FspInfos::new();

    fv_traverse(fsp_base, |ctx: TraverseContext| {
        // All three parts must match.
        match (ctx.ffs_guid, ctx.ffs_type, ctx.sec_type) {
            (FSP_FFS_INFORMATION_FILE_GUID, efi::EFI_FV_FILETYPE_RAW, efi::EFI_SECTION_RAW) => {
                if infos.len() != infos.capacity() {
                    infos.push(FspInfoEntry{
                        addr: ctx.fv_base,
                        info: unsafe { *(ctx.sec_data.as_ptr() as *const efi::FSP_INFO_HEADER) }.clone(),
                    });
                }
            }
            (FSP_S_UPD_FFS_GUID, efi::EFI_FV_FILETYPE_RAW, efi::EFI_SECTION_RAW) => (),
            _ => (),
        }
    })?;
    Ok(infos)
}

struct TraverseContext<'a> {
    fv_base: usize,
    ffs_guid: GUID,
    ffs_type: u32,
    sec_type: u32,
    sec_data: &'a [u8],
}

fn fv_traverse<F>(base: usize, mut visitor: F) -> Result<(), FvTraverseError>
where
    F: FnMut(TraverseContext),
{
    // This procedure is defined in the FSP spec and the "Platform Initialization Specification,
    // Vol. 3".
    let mut counter = base;

    for _fv_idx in 0.. {
        let fv_base = counter;
        let fv = unsafe { &*(counter as *const efi::EFI_FIRMWARE_VOLUME_HEADER) };

        // Check FV header signature.
        if fv.Signature != EFI_FVH_SIGNATURE {
            break;
        }

        // Check FV header GUID.
        if fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM2_GUID && fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM3_GUID {
            return Err(InvalidFvGuid { base, guid: fv.FileSystemGuid.clone() });
        }

        // Check FV header checksum.
        let words = unsafe { slice::from_raw_parts(counter as *const u16, size_of::<efi::EFI_FIRMWARE_VOLUME_HEADER>() / 2) };
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
            let fveh = unsafe { &*(counter as *const efi::EFI_FIRMWARE_VOLUME_EXT_HEADER) };
            counter += fveh.ExtHeaderSize as usize;
        }

        // Iterate through files.
        while {
            counter = (counter + 7) & !7; // align to 8 bytes
            counter < fv_end
        } {
            let ffs = unsafe { &*(counter as *const efi::EFI_FFS_FILE_HEADER) };

            // Determine the file sizes.
            let (ffs_header_size, ffs_size) = if ffs.Attributes & (efi::FFS_ATTRIB_LARGE_FILE as u8) == 0 {
                (size_of::<efi::EFI_FFS_FILE_HEADER>(), little_endian3(ffs.Size))
            } else {
                match little_endian3(ffs.Size) {
                    0xffffff => break, // Reached FV free space.
                    0 => (),
                    _ => return Err(InvalidFfsSize { base }),
                }
                (size_of::<efi::EFI_FFS_FILE_HEADER2>(), unsafe { &*(counter as *const efi::EFI_FFS_FILE_HEADER2) }.ExtendedSize as usize)
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
            if ffs.Attributes & (efi::FFS_ATTRIB_CHECKSUM as u8) == 0 {
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
                let section_common = unsafe { &*(counter as *const efi::EFI_COMMON_SECTION_HEADER) };

                // Determine section sizes.
                let (section_header_size, section_size) = match little_endian3(section_common.Size) {
                    0xffffff => (size_of::<efi::EFI_COMMON_SECTION_HEADER2>(), unsafe { &*(counter as *const efi::EFI_COMMON_SECTION_HEADER2) }.ExtendedSize as usize),
                    x => (size_of::<efi::EFI_COMMON_SECTION_HEADER>(), x),
                };
                let section_data_size = section_size - section_header_size;

                // Apply visitor.
                let bytes = unsafe { slice::from_raw_parts((counter + section_header_size) as *const u8, section_data_size) };
                visitor(TraverseContext{
                    fv_base: fv_base,
                    ffs_guid: ffs.Name.clone(),
                    ffs_type: ffs.Type as u32,
                    sec_type: section_common.Type as u32,
                    sec_data: bytes,
                });

                // Skip to next section.
                counter += section_size;
            }
        }

        counter = fv_end;
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
