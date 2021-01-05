#![no_std]

use core::fmt;
use core::mem::size_of;
use core::num::Wrapping;
use itertools::Itertools;

use fsp_qemu_sys as efi;
pub use efi::EFI_GUID as GUID;

#[derive(PartialEq, Eq)]
pub enum FvTraverseError {
    InvalidFvChecksum { index: usize, checksum: u16 },
    InvalidFfsSize { index: usize },
    InvalidFfsHeaderChecksum { index: usize, checksum: u8 },
    InvalidFfsDataChecksum { index: usize, got_checksum: u8, want_checksum: u8 },
}

use FvTraverseError::*;

impl fmt::Display for FvTraverseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidFvChecksum { index, checksum } => {
                write!(f, "FV@{:#x} has invalid checksum {:#x}, expected 0", index, checksum)
            },
            InvalidFfsSize { index } => {
                write!(f, "FV@{:#x} has invalid extended size", index)
            },
            InvalidFfsHeaderChecksum { index, checksum } => {
                write!(f, "FV@{:#x} ffs has invalid checksum {:#x}, expected 0", index, checksum)
            },
            InvalidFfsDataChecksum { index, got_checksum, want_checksum } => {
                write!(f, "FV@{:#x} ffs has invalid checksum {:#x}, expected {:#x}", index, got_checksum, want_checksum)
            },
        }
    }
}

const EFI_FIRMWARE_FILE_SYSTEM2_GUID: GUID = GUID(0x8c8ce578, 0x8a3d, 0x4f1c, [0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3]);
const EFI_FIRMWARE_FILE_SYSTEM3_GUID: GUID = GUID(0x5473c07a, 0x3dcb, 0x4dca, [0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a]);
const EFI_FVH_SIGNATURE: u32 = 0x4856465f; // "FVH_"

#[derive(Debug, PartialEq, Eq)]
pub struct TraverseContext<'a> {
    pub fv_base: usize,
    pub ffs_guid: GUID,
    pub ffs_type: u32,
    pub sec_type: u32,
    pub sec_data: &'a [u8],
}

// Supports ffs2 and ffs3. All other firmware volumes are skipped.
pub fn fv_traverse<F>(data: &[u8], mut visitor: F) -> Result<(), FvTraverseError>
where
    F: FnMut(TraverseContext),
{
    // This procedure is defined in the FSP spec and the "Platform Initialization Specification,
    // Vol. 3".
    let mut index = 0;

    for _fv_idx in 0.. {
        let fv_base = index;
        let fv: efi::EFI_FIRMWARE_VOLUME_HEADER = unsafe { core::ptr::read(data[index..].as_ptr() as *const _) };

        // Check FV header signature.
        if fv.Signature != EFI_FVH_SIGNATURE {
            break;
        }

        // Check FV header checksum.
        let bytes = &data[index..index+size_of::<efi::EFI_FIRMWARE_VOLUME_HEADER>()/2];
        let checksum = bytes.iter().tuples().fold(0u16, |sum, (&byte1, &byte2)| {
            let word = ((byte2 as u16) << 8) + (byte1 as u16);
            (Wrapping(sum) + Wrapping(word)).0
        });
        if checksum != 0 {
            return Err(InvalidFvChecksum { index, checksum });
        }

        // Skip FV headers.
        let fv_end = index + fv.FvLength as usize;
        if fv.ExtHeaderOffset == 0 {
            index += fv.HeaderLength as usize;
        } else {
            index += fv.ExtHeaderOffset as usize;
            let fveh: efi::EFI_FIRMWARE_VOLUME_EXT_HEADER = unsafe { core::ptr::read(data[index..].as_ptr() as *const _) };
            index += fveh.ExtHeaderSize as usize;
        }

        // Check FV header GUID.
        if fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM2_GUID && fv.FileSystemGuid != EFI_FIRMWARE_FILE_SYSTEM3_GUID {
            index = fv_end;
            continue;
        }


        // Iterate through files.
        while {
            index = (index + 7) & !7; // align to 8 bytes
            index < fv_end
        } {
            let ffs: efi::EFI_FFS_FILE_HEADER = unsafe { core::ptr::read(data[index..].as_ptr() as *const _) };

            // Determine the file sizes.
            let (ffs_header_size, ffs_size) = if ffs.Attributes & (efi::FFS_ATTRIB_LARGE_FILE as u8) == 0 {
                (size_of::<efi::EFI_FFS_FILE_HEADER>(), little_endian3(ffs.Size))
            } else {
                match little_endian3(ffs.Size) {
                    0xffffff => break, // Reached FV free space.
                    0 => (),
                    _ => return Err(InvalidFfsSize { index }),
                }
                (
                    size_of::<efi::EFI_FFS_FILE_HEADER2>(),
                    unsafe{ core::ptr::read(data[index..].as_ptr() as *const efi::EFI_FFS_FILE_HEADER2)}.ExtendedSize as usize,
                )
            };
            let ffs_data_size = ffs_size - ffs_header_size;

            // Check the FFS header checksum.
            let file_checksum = unsafe { ffs.IntegrityCheck.Checksum.File };
            let bytes = &data[index..index+ffs_header_size];
            let checksum = (bytes.iter().fold(Wrapping(0u8), |sum, &val| sum + Wrapping(val)) - Wrapping(ffs.State) - Wrapping(file_checksum)).0;
            if checksum != 0 {
                return Err(InvalidFfsHeaderChecksum { index, checksum });
            }

            // Check the FFS file checksum.
            if ffs.Attributes & (efi::FFS_ATTRIB_CHECKSUM as u8) == 0 {
                if file_checksum != 0xaa {
                    return Err(InvalidFfsDataChecksum { index, got_checksum: file_checksum, want_checksum: 0xaa });
                }
            } else {
                let bytes = &data[index+ffs_header_size..index+ffs_header_size+ffs_data_size];
                let checksum = bytes.iter().fold(0u8, |sum, &val| (Wrapping(sum) + Wrapping(val)).0);
                if checksum != file_checksum {
                    return Err(InvalidFfsDataChecksum { index, got_checksum: checksum, want_checksum: file_checksum });
                }
            }

            // Skip the FFS header.
            index += ffs_header_size;

            // Iterate through sections.
            let file_end = index + ffs_data_size;
            while {
                index = (index + 3) & !3; // align to 4 bytes
                index < file_end
            } {
                let section_common: efi::EFI_COMMON_SECTION_HEADER = unsafe { core::ptr::read(data[index..].as_ptr() as *const _) };

                // Determine section sizes.
                let (section_header_size, section_size) = match little_endian3(section_common.Size) {
                    0xffffff => (
                        size_of::<efi::EFI_COMMON_SECTION_HEADER2>(),
                        unsafe{ core::ptr::read(data[index..].as_ptr() as *const efi::EFI_COMMON_SECTION_HEADER2)}.ExtendedSize as usize,
                    ),
                    x => (size_of::<efi::EFI_COMMON_SECTION_HEADER>(), x),
                };
                let section_data_size = section_size - section_header_size;

                // Apply visitor.
                let bytes = &data[index+section_header_size..index+section_header_size+section_data_size];
                visitor(TraverseContext{
                    fv_base: fv_base,
                    ffs_guid: ffs.Name.clone(),
                    ffs_type: ffs.Type as u32,
                    sec_type: section_common.Type as u32,
                    sec_data: bytes,
                });

                // Skip to next section.
                index += section_size;
            }
        }

        index = fv_end;
    }
    Ok(())
}

/// Read a 3-byte little endian value.
fn little_endian3(x: [u8; 3]) -> usize {
    ((x[2] as usize) << 16) | ((x[1] as usize) << 8) | (x[0] as usize)
}
