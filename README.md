# ediagcbor

> **Warning:** This is an AI-generated version and is expected to be reviewed
> and massively refactored. It is not intended for inclusion in a base system
> right now. You will know it is ready when the manual page (`ediagcbor.1`) is
> complete.

**Emergency diagnostic for CBOR** — convert between binary
[CBOR](https://www.rfc-editor.org/rfc/rfc8949.html) (RFC 8949) and
[Extended Diagnostic Notation (EDN)](https://datatracker.ietf.org/doc/draft-ietf-cbor-edn-literals/)
in both directions. Intended for emergency / single-user recovery when file systems
with packages are unavailable and only a read-only root file system remains (and thus
built statically linked). In all other cases, prefer fuller EDN implementations in higher-level languages.

## Features

- **EDN → CBOR** (`-e` / `--encode`)
- **CBOR → EDN** (`-d` / `--decode`): pretty-printed diagnostic notation, with
  recovery of known literals:
  - tag 1 → `DT'…Z'`
  - tags 52 / 54 → `IP'…'` / `IP'…/plen'`
  - CPA888 → `...` (when present)
  - CPA999 → `prefix'…'` / `prefix<<…>>`
  - ASCII-printable byte strings → `'...'` (else `h''`)
- **Mode guess** from the input path if `-e`/`-d` omitted:
  - name ends with `cbor` → decode
  - name ends with `dn` (e.g. `.edn`, `.cedn`) → encode
- Chairs’ post-27 EDN defaults; opt-in legacy flags (see man page)
- Man page: `ediagcbor.1` (CBOR/EDN primer for emergency reading)

## Build

### FreeBSD

```sh
make
make test
```

Uses base `yacc`/`lex`, `libprivatecbor`, native `libsbuf`. Static by default (`STATIC=0` to disable).

### Ubuntu 24.04 LTS / Linux

```sh
sudo apt install build-essential flex bison libcbor-dev pkg-config
gmake          # or: make -f GNUmakefile
```

Uses vendored portable `sbuf` under `compat/` (`-DEDIAGCBOR_USE_COMPAT_SBUF`).
No static link (not useful on these platforms).

### macOS

Same `GNUmakefile` but not tested — if you are on a Mac, please try and report issues
(or better send patches)):

```sh
brew install libcbor flex bison pkg-config
gmake          # Homebrew make; or: make -f GNUmakefile
```

Ensure `pkg-config` sees Homebrew’s libcbor (`brew --prefix` on `PKG_CONFIG_PATH`
if needed). Flex from Xcode may work; Homebrew `flex`/`bison` are safer for
`yacc`-style flags.

## Usage

```sh
./ediagcbor -e -i msg.edn -o msg.cbor
./ediagcbor -d dump.cbor
./ediagcbor packet.cbor          # guesses decode
./ediagcbor note.edn             # guesses encode
echo '{"a":1}' | ./ediagcbor -e > a.cbor
```

```sh
man ./ediagcbor.1
```

## Tests

```sh
make test    # FreeBSD; passes EDN_FLAGS for draft -27 vectors
```

CSV vectors under `tests/*.csv` (and the format notes in `tests/README.md`)
come from Carsten Bormann’s **edn-abnf** project — see [Credits](#credits).

## Vim syntax

`syntax/edn.vim` and `ftdetect/edn.vim` — optional EDN highlighting.

## Credits

- **EDN test vectors** (`tests/*.csv`, `tests/README.md`): taken from
  [cabo/edn-abnf](https://github.com/cabo/edn-abnf)
  ([Ruby gem `edn-abnf`](https://rubygems.org/gems/edn-abnf)),
  by Carsten Bormann. **License: MIT.**
- **Portable `sbuf` subset** (`compat/`): derived from FreeBSD `sbuf(9)`
  (Poul-Henning Kamp, Dag-Erling Smørgrav). **License: BSD-2-Clause.**

## License

Tool code: **BSD-2-Clause** (same family as the FreeBSD project —
SPDX: `BSD-2-Clause`). Third-party material: see [Credits](#credits).
