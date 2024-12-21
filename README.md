# SecLang ANTLR based parser

This repo contains the ANTLR files for a SecLang parser.

It is still a Proof of Concept, not usable, and incomplete version.

## Why a new parser?

There has been efforts towards having parsers in different languages. Using ANTLR would allow us to have a common parser and generate parsing engines for different languages easily. 
This way we would consolidate efforts, and we can have a more robust parser.

## Features we (might) want

- Agnostic: no language dependent, parser should be independent of the destination language.
- High Level: writing low level dependent parsing rules is prone to error and makes the language more difficult.
- Can be used from native code, e.g, no dependencies or CGo (this might hurt Coraza, for example)
- Can generate in many languages, and be read and extended by everyone.
- We choose one base implementation language (Python/Go?) and anyone can contribute others.

## Usage

Right now this repo contains the ANTLR files and golang and python 3 basic tests.

To run the tests:

```bash
go generate ./...
go test ./...
```

Or for python 3:
```bash
cd parser
./generate.sh
cd ..
poetry install
poetry run parser -f testdata/crs-setup.conf
```

## Authors

Felipe Zipitria <felipe.zipitria@owasp.org>
