# unegg

Extract files from egg archive.

## Installation

### Using Homebrew

```
brew install blurfx/tap/unegg
```

### Using pre-built binary

See [Releases](https://github.com/blurfx/unegg/releases/latest)

## Usage

```
Usage: unegg [options] <archive.egg>
  -C string
        destination directory (default: archive base name)
  -j int
        number of parallel workers
  -l    list archive contents
  -p string
        password for encrypted archives
  -q    quiet mode (no progress output)
```

Example usage

```
unegg photos.egg
```
