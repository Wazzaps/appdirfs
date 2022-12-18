use argh::FromArgs;
use std::path::PathBuf;

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "mount")]
/// Mount the given Appdir
pub struct MountParams {
    /// appdir file
    #[argh(positional)]
    pub appdir_path: PathBuf,

    /// mount point
    #[argh(positional)]
    pub mount_point: PathBuf,
    // FIXME: Remove these comments:
    // /// i am a switch
    // #[argh(switch)]
    // pub switchable: bool,

    // /// i am an option
    // #[argh(option, short = 'u')]
    // pub an_option: Option<String>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "info")]
/// Get info about the given appdir
pub struct InfoParams {
    /// appdir file
    #[argh(positional)]
    pub appdir_path: PathBuf,

    /// read the given file inside the archive
    #[argh(option)]
    pub read: Option<String>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Subcommands {
    Mount(MountParams),
    Info(InfoParams),
}

/// Appdir utility
#[derive(FromArgs, Debug)]
pub struct Params {
    #[argh(subcommand)]
    pub nested: Subcommands,
}

pub fn get_params() -> Params {
    argh::from_env::<Params>()
}
