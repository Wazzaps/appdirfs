use crate::multi_cursor::FileSliceCursor;
use crate::InfoParams;
use byteorder::{ReadBytesExt, LE};
use std::fmt::Write as _w2;
use std::fs::File;
use std::io::Write as _w1;
use std::io::{BufRead, BufReader, Read, Seek};
use std::os::unix::fs::FileExt;

pub type BytesTupleVec = Vec<(Vec<u8>, Vec<u8>)>;

pub trait BufReadExt: BufRead {
    fn read_cstring(&mut self) -> std::io::Result<Vec<u8>>;
}

impl<T: BufRead> BufReadExt for T {
    fn read_cstring(&mut self) -> std::io::Result<Vec<u8>> {
        let mut val = vec![];
        self.read_until(b'\x00', &mut val)?;
        val.pop();
        Ok(val)
    }
}

fn to_byte_string_literal(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut result = String::new();

    for &byte in bytes {
        if byte == b'"' {
            result.push('\\');
            result.push('"');
        } else if byte == b'\\' {
            result.push('\\');
            result.push('\\');
        } else if (b' '..=b'~').contains(&byte) {
            result.push(byte as char);
        } else {
            let _ = write!(result, "\\x{byte:02X}");
        }
    }

    result
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AppSignatureHdr {
    pre_padding_size: u32,
    post_padding_size: u64,
    hdr_size: u32,
}

impl AppSignatureHdr {
    pub fn parse<F: FileExt>(fd: &mut FileSliceCursor<F>) -> anyhow::Result<(Self, BytesTupleVec)> {
        fd.with_buffering(|fd| {
            let mut hdr_size = 10 + 8 + 4;

            // Check for the magic
            let mut magic = [0u8; 10];
            fd.read_exact(&mut magic)?;
            if &magic != b"AppDirSig\x01" {
                anyhow::bail!("Missing AppDirSig magic");
            }

            // Read static fields
            let post_padding_size = fd.read_u64::<LE>()?;
            let pre_padding_size = fd.read_u32::<LE>()?;

            // Read attrs
            let attrs_size = fd.read_u32::<LE>()?;
            let mut attrs = vec![];
            let mut attrs_reader = fd.take(attrs_size as u64);
            while attrs_reader.has_data_left()? {
                let attr_name = attrs_reader.read_cstring()?;
                let attr_val = attrs_reader.read_cstring()?;
                hdr_size += attr_name.len() + 1 + attr_val.len() + 1;
                attrs.push((attr_name, attr_val));
            }

            Ok((
                Self {
                    pre_padding_size,
                    post_padding_size,
                    hdr_size: hdr_size as u32,
                },
                attrs,
            ))
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AppTrustedHdr {
    block_size_pow: u8,
    block_size: u32,
    entries_size: u32,
    bptree_size: u32,
    required_flags: u64,
    optional_flags: u64,
    name: Vec<u8>,
}

impl AppTrustedHdr {
    pub fn parse<F: FileExt>(fd: &mut FileSliceCursor<F>) -> anyhow::Result<(Self, BytesTupleVec)> {
        fd.with_buffering(|fd| {
            // Check for the magic
            let mut magic = [0u8; 10];
            fd.read_exact(&mut magic)?;
            if &magic != b"AppDirApp\x01" {
                anyhow::bail!("Missing AppDirApp magic");
            }

            // Read static fields
            let format_version = fd.read_u16::<LE>()?;

            if format_version != 0 {
                anyhow::bail!("Invalid format version {} (expected {})", format_version, 0);
            }

            let block_size_pow = fd.read_u8()?;
            if block_size_pow > 31 {
                // Max alignment is 2GiB
                anyhow::bail!(
                    "Block size is too big (1<<{}), max allowed is 2GiB (1<<31)",
                    block_size_pow
                );
            }
            let block_size = 1 << block_size_pow;
            let attrs_size = fd.read_u32::<LE>()?;
            let entries_size = fd.read_u32::<LE>()?;
            let bptree_size = fd.read_u32::<LE>()?;
            if bptree_size % block_size != 0 {
                anyhow::bail!(
                    "B+Tree size ({}) not aligned to block size ({})",
                    bptree_size,
                    block_size
                );
            }
            let required_flags = fd.read_u64::<LE>()?;

            if required_flags != 0 {
                anyhow::bail!(
                    "No required_flags supported yet (got 0x{:x})",
                    required_flags
                );
            }

            let optional_flags = fd.read_u64::<LE>()?;
            let name = fd.read_cstring()?;

            // Read attrs
            let mut attrs = vec![];
            let mut attrs_reader = fd.by_ref().take(attrs_size as u64);
            while attrs_reader.has_data_left()? {
                let attr_name = attrs_reader.read_cstring()?;
                let attr_val = attrs_reader.read_cstring()?;
                attrs.push((attr_name, attr_val));
            }

            Ok((
                Self {
                    block_size_pow,
                    block_size,
                    entries_size,
                    bptree_size,
                    required_flags,
                    optional_flags,
                    name,
                },
                attrs,
            ))
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Entry {
    entry_type: u8,
    name_len: u8,
    flags: u16,
    parent_entry: u32,
    size: u64,
    data_offset: u64,
    name: Vec<u8>,
}

impl Entry {
    pub fn parse<F: FileExt>(fd: &mut BufReader<FileSliceCursor<F>>) -> anyhow::Result<Self> {
        // Read static fields
        let entry_type = fd.read_u8()?;
        let name_len = fd.read_u8()?;
        let flags = fd.read_u16::<LE>()?;
        let parent_entry = fd.read_u32::<LE>()?;
        let size = fd.read_u64::<LE>()?;
        let data_offset = fd.read_u64::<LE>()?;

        let mut name = vec![0u8; name_len as usize];
        fd.read_exact(&mut name)?;
        assert_eq!(fd.read_u8()?, 0, "Name not null terminated");

        Ok(Self {
            entry_type,
            name_len,
            flags,
            parent_entry,
            size,
            data_offset,
            name,
        })
    }
}

#[allow(dead_code)]
pub struct AppdirParser<'a, F: FileExt> {
    fd: FileSliceCursor<'a, F>,
    entries_start: u64,
    sig_hdr: AppSignatureHdr,
    hdr: AppTrustedHdr,
    bptree_start: u64,
    data_start: u64,
    supplied_hash: Option<Vec<u8>>,
    supplied_signature: Option<Vec<u8>>,
    compression: bool,
}

impl<'a, F: FileExt> AppdirParser<'a, F> {
    pub fn open(mut fd: FileSliceCursor<'a, F>) -> anyhow::Result<Self> {
        let (sig_hdr, untrusted_attrs) = AppSignatureHdr::parse(&mut fd)?;
        let mut supplied_hash = None;
        let mut supplied_signature = None;
        let mut compression = false;
        for (attr_name, attr_val) in untrusted_attrs {
            match attr_name.as_slice() {
                b"hash" => supplied_hash = Some(attr_val),
                b"sign" => supplied_signature = Some(attr_val),
                b"compress" => {
                    if &*attr_val == b"zstd" {
                        compression = true;
                        todo!("Compression not supported yet");
                    } else {
                        anyhow::bail!(
                            "Unknown compression type `{}`",
                            String::from_utf8_lossy(&*attr_val)
                        );
                    }
                }
                attr_name => {
                    println!("WARNING: Unknown attribute {:?}", attr_name);
                }
            }
        }

        let (hdr, trusted_attrs) = AppTrustedHdr::parse(&mut fd)?;
        for (attr_name, _attr_val) in trusted_attrs {
            println!("WARNING: Unknown trusted attribute {:?}", attr_name);
        }

        let padding_start = sig_hdr.hdr_size + sig_hdr.pre_padding_size;

        fn align_up_blksize(val: u64, block_size_pow: u8) -> u64 {
            let mask = (1 << block_size_pow) - 1;
            (val + mask) & !mask
        }

        let bptree_start = if compression {
            // There's no padding when using compression (useless)
            padding_start as u64
        } else {
            align_up_blksize(padding_start as u64, hdr.block_size_pow)
        };

        let data_start = if compression {
            // There's no alignment when using compression (useless)
            bptree_start + hdr.bptree_size as u64
        } else {
            align_up_blksize(bptree_start + hdr.bptree_size as u64, hdr.block_size_pow)
        };

        let entries_start = fd.stream_position()?;
        Ok(Self {
            fd,
            entries_start,
            sig_hdr,
            hdr,
            bptree_start,
            data_start,
            supplied_hash,
            supplied_signature,
            compression,
        })
    }

    pub fn entries(&mut self) -> anyhow::Result<()> {
        let mut stdout = std::io::stdout().lock();
        self.fd
            .slice(self.entries_start..self.entries_start + self.hdr.entries_size as u64)
            .with_buffering(|entry_reader| {
                let mut dir_offset_stack = vec![];
                let mut dir_name_stack = vec![];
                while entry_reader.has_data_left()? {
                    let entry = Entry::parse(entry_reader)?;

                    // Manage dir stack
                    if let Some(idx) = dir_offset_stack
                        .iter()
                        .rposition(|e| *e == entry.parent_entry)
                    {
                        dir_offset_stack.truncate(idx + 1);
                        dir_name_stack.truncate(idx);
                    } else {
                        dir_offset_stack.push(entry.parent_entry);
                    }

                    // Tree-like left-padding
                    // let padding = "  ".repeat((dir_offset_stack.len() as isize - 1).max(0) as usize)
                    //     + if dir_offset_stack.len() > 0 { "| " } else { "" };

                    // Simple padding
                    // let padding = "  ".repeat(dir_offset_stack.len());

                    // Full path padding
                    let mut padding = dir_name_stack.join("/");
                    if !padding.is_empty() {
                        padding += "/";
                    }

                    // Get chunk of the file / symlink
                    const DATA_CHUNK_LEN: usize = 10;
                    const READ_FILE_CONTENTS: bool = false;
                    let mut real_data_chunk_len =
                        u64::min(entry.size, DATA_CHUNK_LEN as u64) as usize;
                    let mut data_chunk = [0u8; DATA_CHUNK_LEN];
                    if (READ_FILE_CONTENTS && entry.entry_type == 8) || entry.entry_type == 10 {
                        self.fd.read_at(
                            &mut data_chunk[..real_data_chunk_len],
                            self.data_start + entry.data_offset,
                        )?;
                    } else {
                        real_data_chunk_len = 0;
                    }

                    // Print main line
                    match entry.entry_type {
                        4 => {
                            // Directory
                            writeln!(
                                stdout,
                                "         {}{}",
                                padding,
                                String::from_utf8_lossy(&entry.name)
                            )?;
                        }
                        10 => {
                            // Symlink
                            writeln!(
                                stdout,
                                "         {}{} -> {}",
                                padding,
                                String::from_utf8_lossy(&entry.name),
                                to_byte_string_literal(&data_chunk[..real_data_chunk_len]),
                            )?;
                        }
                        8 => {
                            // File
                            writeln!(
                                stdout,
                                "{:>8} {}{} = \"{}\"",
                                pretty_print_size(entry.size),
                                padding,
                                String::from_utf8_lossy(&entry.name),
                                to_byte_string_literal(&data_chunk[..real_data_chunk_len]),
                            )?;
                        }
                        _ => anyhow::bail!("Unknown entry type {}", entry.entry_type),
                    }

                    // Push dir names to name stack
                    if entry.entry_type == 4 {
                        dir_name_stack.push(String::from_utf8_lossy(&*entry.name).to_string());
                    }
                }
                Ok(())
            })?;

        Ok(())
    }
}

fn pretty_print_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 * 1024 * 1024 {
        format!("{} PiB", size / 1024 / 1024 / 1024 / 1024 / 1024)
    } else if size >= 1024 * 1024 * 1024 * 1024 {
        format!("{} TiB", size / 1024 / 1024 / 1024 / 1024)
    } else if size >= 1024 * 1024 * 1024 {
        format!("{} GiB", size / 1024 / 1024 / 1024)
    } else if size >= 1024 * 1024 {
        format!("{} MiB", size / 1024 / 1024)
    } else if size >= 1024 {
        format!("{} KiB", size / 1024)
    } else {
        format!("{} B  ", size)
    }
}

pub fn get_info(info_params: InfoParams) {
    let mut file = File::open(info_params.appdir_path).unwrap();
    let file_slice = FileSliceCursor::from_file(&mut file);
    let mut parser = AppdirParser::open(file_slice).unwrap();
    parser.entries().unwrap();
}
