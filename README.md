# Appdir File System

This is a read-only filesystem intended to store applications' code and resources in a secure and efficient manner.

It has several important features, while remaining pretty simple:

- Optional integrity & authenticity verification (can be added to existing `.app` files after the fact)
    - Using a Merkle tree for on-the-fly hash verification (Or a flat hash)
    - Using SSH signatures to sign the Merkle tree
- Optional compression of the contents (can be added or removed from existing `.app` files after creation, without breaking the signature)
- Alignment of big files to a given block-size for direct memory-mapping support

## Usage

```shell
# Use the python implementation to create the appdir, this version doesn't support it yet
# It's available at: https://github.com/Wazzaps/appdirfs-python 

# List the appdir's files
cargo run -- info ./example.app 

# Read a file inside the appdir (Don't prepend "./" to the path, it must be exact)
cargo run -- info ./example.app --read "foo/bar"
```

# TODOs

- [ ] `mount` command (FUSE)
- [ ] `create` command
- [ ] `gvfs` command? (Support GNOME VFS) or `kio` command (KDE I/O)
