# idCryptRust
Command line utility to encrypt/decrypt DOOM's .bfile and .blang files.

## Usage
```
idCrypt [options] <file-path> <internal-file-path>
```
The tool will try to encrypt if the file ends in .dec, and decrypt otherwise. You can override this behavior with the `--encrypt` and `--decrypt` switches.

## Compiling
### Linux / macOS
To compile, you'll need a Rust environment set up with rustup. You can set it up by running:
```
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```
and following the given instructions.

Afterwards, clone this repo:
```
git clone https://github.com/PowerBall253/idCryptRust.git
```

Finally, cd into the directory and compile with cargo:
```
cd idCryptRust
cargo build --release
```
The compiled binary will be located at the ./target/release folder.

### Windows
To compile, you'll need a Rust environment set up with rustup and the Visual Studio C++ build tools. You can set it up by downloading rustup from [here](https://www.rust-lang.org/tools/install) and follow the given instructions, then downloading Visual Studio 2019 and selecting the C++ tools for download.

Afterwards, clone this repo using the Git Bash:
```
git clone https://github.com/PowerBall253/idCryptRust.git
```

Finally, cd into the directory and compile with cargo:
```
cd idCryptRust
cargo build --release
```
The compiled binary will be located at the .\target\release folder.

## Credits
* emoose: Creator of the original idCrypt tool.
