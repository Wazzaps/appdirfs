use crate::multi_cursor::FileSliceCursor;
use crate::InfoParams;
use anyhow::bail;
use byte_slice_cast::AsSliceOf;
use byteorder::{ByteOrder, ReadBytesExt, LE};
use sha2::Digest;
use std::cmp::min;
use std::fmt::Write as _w2;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::io::{SeekFrom, Write as _w1};
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
    idxtbl_size: u32,
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
            let idxtbl_size = fd.read_u32::<LE>()?;
            if idxtbl_size % 8 != 0 {
                anyhow::bail!("Index table size ({}) not aligned to 8", idxtbl_size);
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
                    idxtbl_size,
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
    idxtbl_start: u64,
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
                            String::from_utf8_lossy(&attr_val)
                        );
                    }
                }
                attr_name => {
                    println!("WARNING: Unknown attribute {attr_name:?}");
                }
            }
        }

        let (hdr, trusted_attrs) = AppTrustedHdr::parse(&mut fd)?;
        for (attr_name, _attr_val) in trusted_attrs {
            println!("WARNING: Unknown trusted attribute {attr_name:?}");
        }

        let padding_start = sig_hdr.hdr_size + sig_hdr.pre_padding_size;

        fn align_up_blksize(val: u64, block_size_pow: u8) -> u64 {
            let mask = (1 << block_size_pow) - 1;
            (val + mask) & !mask
        }

        let data_start = if compression {
            // There's no padding when using compression (useless)
            padding_start as u64
        } else {
            align_up_blksize(padding_start as u64, hdr.block_size_pow)
        };

        let entries_start = fd.stream_position()?;

        let idxtbl_start = entries_start + hdr.entries_size as u64;
        Ok(Self {
            fd,
            entries_start,
            sig_hdr,
            hdr,
            idxtbl_start,
            data_start,
            supplied_hash,
            supplied_signature,
            compression,
        })
    }

    pub fn entries(&self) -> anyhow::Result<()> {
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
                        dir_name_stack.push(String::from_utf8_lossy(&entry.name).to_string());
                    }
                }
                Ok(())
            })?;

        Ok(())
    }

    fn full_path_of(
        &self,
        entry: &Entry,
        res: &mut Vec<u8>,
        max_depth: usize,
    ) -> anyhow::Result<()> {
        if max_depth == 0 {
            bail!("Malformed appdir: recursive directories");
        }

        if entry.parent_entry != 0xffffffff {
            let parent = self.lookup_by_entry_offset(entry.parent_entry as u64)?;
            self.full_path_of(&parent, res, max_depth - 1)?;
            res.push(b'/');
        }
        res.extend_from_slice(&entry.name);
        Ok(())
    }

    fn lookup_by_entry_offset(&self, entry_offset: u64) -> anyhow::Result<Entry> {
        self.fd
            .slice(self.entries_start..self.entries_start + self.hdr.entries_size as u64)
            .with_buffering(|entry_reader| {
                entry_reader.seek(SeekFrom::Start(entry_offset))?;
                Entry::parse(entry_reader)
            })
    }

    pub fn lookup_by_path(&self, path: &[u8]) -> anyhow::Result<Entry> {
        const KEY_SIZE_BYTES: u64 = 4;
        const VAL_SIZE_BYTES: u64 = 4;
        const INITIAL_SEARCH_RADIUS: u64 = 32; // TODO: Tweak

        if self.hdr.idxtbl_size == 0 {
            bail!("No index table (or empty appdir)");
        }

        // Create constrained file slices
        let search_space = self
            .fd
            .slice(self.idxtbl_start..self.idxtbl_start + (self.hdr.idxtbl_size / 2) as u64);
        let mut value_space = self.fd.slice(
            self.idxtbl_start + (self.hdr.idxtbl_size / 2) as u64
                ..self.idxtbl_start + self.hdr.idxtbl_size as u64,
        );

        // These will contain the indices that all equal the desired key
        let mut first_key = None;
        let mut last_key = None;

        // Get the hash of the path
        let mut hasher = sha2::Sha256::new();
        hasher.update(path);
        let hash = &hasher.finalize()[..KEY_SIZE_BYTES as usize];
        let hash = u32::from_be_bytes(hash.try_into().unwrap());

        // Get approx position
        let total_items: u32 = (search_space.len() / KEY_SIZE_BYTES).try_into()?;
        let approx_pos = (hash as u64 * total_items as u64) >> 32;

        // Initial search
        let initial_search_start =
            approx_pos.saturating_sub(INITIAL_SEARCH_RADIUS) * KEY_SIZE_BYTES;
        let initial_search_end = min(
            (approx_pos + INITIAL_SEARCH_RADIUS) * KEY_SIZE_BYTES,
            (self.hdr.idxtbl_size / 2) as u64,
        );
        let mut initial_search_keys =
            vec![0u8; (initial_search_end - initial_search_start) as usize];
        search_space.read_at(&mut initial_search_keys, initial_search_start)?;

        let mut seen_lesser_key = false;
        let mut seen_higher_key = false;
        let mut seen_the_key = false;

        let mut initial_search_keys = initial_search_keys.as_slice_of::<u32>()?.to_vec();
        byteorder::BigEndian::from_slice_u32(initial_search_keys.as_mut_slice());

        // fixme: println!("{} {:?}", hash, initial_search_keys);
        for (i, key) in initial_search_keys.iter().enumerate() {
            if first_key.is_some() && last_key.is_some() {
                // Found, we're done!
                break;
            }

            if *key < hash {
                seen_lesser_key = true;
            } else if *key == hash {
                // First key, no need for lower
                if i == 0 && initial_search_start == 0 {
                    seen_lesser_key = true;
                }

                seen_the_key = true;
                if seen_lesser_key && first_key.is_none() {
                    first_key = Some(i as u64 + (initial_search_start / KEY_SIZE_BYTES));
                }

                // Last key, no need for higher
                if i as u64 * KEY_SIZE_BYTES + initial_search_start
                    == self.hdr.idxtbl_size as u64 / 2 - KEY_SIZE_BYTES
                {
                    seen_higher_key = true;
                    last_key = Some(i as u64 + (initial_search_start / KEY_SIZE_BYTES));
                }
            } else if *key > hash {
                seen_higher_key = true;
                if seen_the_key && last_key.is_none() {
                    last_key = Some(i as u64 + (initial_search_start / KEY_SIZE_BYTES) - 1);
                }
            }
        }

        // TODO: Extend search down
        // TODO: Extend search up

        if let (Some(first_key), Some(last_key)) = (first_key, last_key) {
            if first_key == last_key {
                // Only one key, no need to resolve full path
                value_space.seek(SeekFrom::Start(first_key * VAL_SIZE_BYTES))?;
                let entry_offset = value_space.read_u32::<LE>()?;
                return self.lookup_by_entry_offset(entry_offset as u64);
            } else {
                // TODO: Count this as a performance metric
                // Key collision, need to resolve full path of each entry
                for key in first_key..=last_key {
                    value_space.seek(SeekFrom::Start(key * VAL_SIZE_BYTES))?;
                    let entry_offset = value_space.read_u32::<LE>()?;
                    let entry = self.lookup_by_entry_offset(entry_offset as u64)?;

                    let mut full_path = vec![];
                    self.full_path_of(&entry, &mut full_path, 32)?;

                    if full_path == path {
                        return Ok(entry);
                    }
                }
            }
        } else {
            println!("{first_key:?} {last_key:?}");
        }
        bail!("todo");
    }

    pub fn file_slice(&self, entry: &Entry) -> anyhow::Result<FileSliceCursor<'a, F>> {
        // Make sure it's a file or symlink
        if entry.entry_type == 8 || entry.entry_type == 10 {
            let mut slice = self.fd.slice(
                self.data_start + entry.data_offset
                    ..self.data_start + entry.data_offset + entry.size,
            );
            slice.rewind()?;
            Ok(slice)
        } else {
            bail!("Tried to get file slice of directory")
        }
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
        format!("{size} B  ")
    }
}

pub fn get_info(info_params: InfoParams) {
    let mut file = File::open(info_params.appdir_path).unwrap();
    let file_slice = FileSliceCursor::from_file(&mut file);
    let parser = AppdirParser::open(file_slice).unwrap();
    if let Some(path_to_read) = info_params.read {
        let entry = parser.lookup_by_path(path_to_read.as_bytes()).unwrap();
        let mut file_slice = parser.file_slice(&entry).unwrap();

        while file_slice.stream_position().unwrap() < file_slice.stream_len().unwrap() {
            let mut buf = [0u8; 4096];
            let count = file_slice.read(&mut buf).unwrap();
            std::io::stdout().lock().write_all(&buf[..count]).unwrap();
        }
    } else {
        parser.entries().unwrap();
    }
}
