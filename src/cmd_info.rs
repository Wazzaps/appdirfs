use crate::InfoParams;
use byteorder::{ReadBytesExt, LE};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

pub type BytesTupleVec = Vec<(Vec<u8>, Vec<u8>)>;

pub trait BufReadSeek: BufRead + Seek {}

impl BufReadSeek for BufReader<File> {}

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

#[derive(Debug)]
#[allow(dead_code)]
pub struct AppSignatureHdr {
    pre_padding_size: u32,
    post_padding_size: u64,
    hdr_size: u32,
}

impl AppSignatureHdr {
    pub fn parse<READER: BufReadSeek>(
        fd: &mut READER,
    ) -> Result<(Self, BytesTupleVec), Box<dyn Error>> {
        let mut hdr_size = 10 + 8 + 4;
        // Check for the magic
        let mut magic = [0u8; 10];
        fd.read_exact(&mut magic)?;
        if &magic != b"AppDirSig\x01" {
            return Err("Missing AppDirSig magic".into());
        }

        // Read static fields
        let post_padding_size = fd.read_u64::<LE>()?;
        let pre_padding_size = fd.read_u32::<LE>()?;

        // Read attrs
        let attrs_size = fd.read_u32::<LE>()?;
        let mut attrs = vec![];
        let mut attrs_reader = fd.by_ref().take(attrs_size as u64);
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
    pub fn parse<READER: BufReadSeek>(
        fd: &mut READER,
    ) -> Result<(Self, BytesTupleVec), Box<dyn Error>> {
        // Check for the magic
        let mut magic = [0u8; 10];
        fd.read_exact(&mut magic)?;
        if &magic != b"AppDirApp\x01" {
            return Err("Missing AppDirApp magic".into());
        }

        // Read static fields
        let format_version = fd.read_u16::<LE>()?;

        if format_version != 0 {
            return Err(
                format!("Invalid format version {} (expected {})", format_version, 0).into(),
            );
        }

        let block_size_pow = fd.read_u8()?;
        if block_size_pow > 31 {
            // Max alignment is 2GiB
            return Err(format!(
                "Block size is too big (1<<{}), max allowed is 2GiB (1<<31)",
                block_size_pow
            )
            .into());
        }
        let block_size = 1 << block_size_pow;
        let attrs_size = fd.read_u32::<LE>()?;
        let entries_size = fd.read_u32::<LE>()?;
        let bptree_size = fd.read_u32::<LE>()?;
        if bptree_size % block_size != 0 {
            return Err(format!(
                "B+Tree size ({}) not aligned to block size ({})",
                bptree_size, block_size
            )
            .into());
        }
        let required_flags = fd.read_u64::<LE>()?;

        if required_flags != 0 {
            return Err(format!(
                "No required_flags supported yet (got 0x{:x})",
                required_flags
            )
            .into());
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
    pub fn parse<READER: BufRead>(fd: &mut READER) -> Result<Self, Box<dyn Error>> {
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
pub struct AppdirParser<'a, READER: BufReadSeek> {
    fd: &'a mut READER,
    fd_offset: u64,
    sig_hdr: AppSignatureHdr,
    hdr: AppTrustedHdr,
    padding_begin_internal: u32,
    padding_end_internal: u64,
    supplied_hash: Option<Vec<u8>>,
    supplied_signature: Option<Vec<u8>>,
    compression: bool,
}

impl<'a, READER: BufReadSeek> AppdirParser<'a, READER> {
    pub fn open(fd: &'a mut READER) -> Result<Self, Box<dyn Error>> {
        let (sig_hdr, untrusted_attrs) = AppSignatureHdr::parse(fd)?;
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
                        return Err(format!(
                            "Unknown compression type `{}`",
                            String::from_utf8_lossy(&*attr_val)
                        )
                        .into());
                    }
                }
                attr_name => {
                    println!("WARNING: Unknown attribute {:?}", attr_name);
                }
            }
        }

        let (hdr, trusted_attrs) = AppTrustedHdr::parse(fd)?;
        for (attr_name, _attr_val) in trusted_attrs {
            println!("WARNING: Unknown trusted attribute {:?}", attr_name);
        }

        let padding_begin = sig_hdr.hdr_size + sig_hdr.pre_padding_size;

        fn align_up_blksize(val: u64, block_size_pow: u8) -> u64 {
            let mask = (1 << block_size_pow) - 1;
            (val + mask) & !mask
        }
        let padding_end = if compression {
            // There's no padding when using compression (useless)
            padding_begin as u64
        } else {
            align_up_blksize(padding_begin as u64, hdr.block_size_pow)
        };

        let fd_offset = fd.stream_position()?;
        Ok(Self {
            fd,
            fd_offset,
            sig_hdr,
            hdr,
            padding_begin_internal: padding_begin,
            padding_end_internal: padding_end,
            supplied_hash,
            supplied_signature,
            compression,
        })
    }

    pub fn entries(&mut self) -> Result<(), Box<dyn Error>> {
        self.fd.seek(SeekFrom::Start(self.fd_offset))?;
        let mut entry_reader = self.fd.by_ref().take(self.hdr.entries_size as u64);
        let mut dir_offset_stack = vec![];
        let mut dir_name_stack = vec![];
        while entry_reader.has_data_left()? {
            let entry = Entry::parse(&mut entry_reader)?;

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

            // Print main line
            match entry.entry_type {
                4 => {
                    // Directory
                    println!(
                        "         {}{}",
                        padding,
                        String::from_utf8_lossy(&entry.name)
                    );
                }
                10 => {
                    // Symlink
                    println!(
                        "         {}{} ->",
                        padding,
                        String::from_utf8_lossy(&entry.name)
                    );
                }
                8 => {
                    println!(
                        "{:>8} {}{}",
                        pretty_print_size(entry.size),
                        padding,
                        String::from_utf8_lossy(&entry.name)
                    );
                }
                _ => return Err(format!("Unknown entry type {}", entry.entry_type).into()),
            }

            // Push dir names to name stack
            if entry.entry_type == 4 {
                dir_name_stack.push(String::from_utf8_lossy(&*entry.name).to_string());
            }
        }

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
    let mut file = BufReader::new(File::open(info_params.appdir_path).unwrap());

    let mut parser = AppdirParser::open(&mut file).unwrap();
    parser.entries().unwrap();
}
