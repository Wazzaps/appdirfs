//! # Appdir Filesystem
//!
//! ## File structure
//!
//! ```text
//! AppSignatureHdr
//! AppTrustedHdr
//! $entries_start = .
//! Entry[]
//! $idxtbl_start = .
//! PathHash[n]
//! EntryOffset[n]
//! .align $block_size  # (Aligned for efficiency, so blocks can be mmap'd)
//! $data_start = .
//! (Data Pool)
//! # (Already aligned, needed so mmap-ing won't leak data)
//! (Symlink Pool)
//! # (No alignment is needed since this won't be mmap'd)
//! (Small Data Pool)
//! ```

#![feature(buf_read_has_data_left)]
#![feature(seek_stream_len)]
#![allow(clippy::comparison_chain)]

use crate::cli::{InfoParams, MountParams, Subcommands};
use fuser::MountOption;

mod cli;
mod cmd_info;
mod cmd_mount;
pub(crate) mod multi_cursor;

fn main() {
    env_logger::init();
    let params = cli::get_params();

    match params.nested {
        Subcommands::Mount(MountParams {
            appdir_path,
            mount_point,
        }) => {
            let options = vec![
                MountOption::RO,
                MountOption::FSName(
                    appdir_path
                        .canonicalize()
                        .unwrap_or(appdir_path)
                        .to_string_lossy()
                        .to_string(),
                ),
                MountOption::Subtype("appdir".to_string()),
            ];
            // if matches.is_present("auto_unmount") {
            //     options.push(MountOption::AutoUnmount);
            // }
            // if matches.is_present("allow-root") {
            //     options.push(MountOption::AllowRoot);
            // }
            fuser::mount2(cmd_mount::HelloFS, mount_point, &options).unwrap();
        }
        Subcommands::Info(info_params) => cmd_info::get_info(info_params),
    }
}
