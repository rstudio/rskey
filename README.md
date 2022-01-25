# rskey

`rskey` is a command-line tool (and bundled Go package) that generates secret
keys interoperable with the format used by RStudio's Connect and Package Manager
products.

It can be used to help manage secrets without the need to install these products
first, and is designed for use in Infrastructure-as-Code and containerised
deployments of these products.

This tool can also serve as a drop-in replacement for RStudio Connect's
`rscadmin configure --encrypt-config-value`
[command](https://docs.rstudio.com/connect/admin/appendix/cli/#rscadmin) and for
Package Manager's `rspm encrypt`
[command](https://docs.rstudio.com/rspm/admin/appendix/encryption/#rspm-encrypt).

No local license keys are required, either.

**This is not a general-purpose encryption tool.**

## Installation

Binary releases for Windows, macOS, and Linux are available [on
GitHub](https://github.com/rstudio/rskey/releases).

If you have a local Go toolchain you can also install via `go install`:

``` shell
$ go install github.com/rstudio/rskey@latest
```

## Usage

You can generate keys with `rskey generate`. For example:

``` shell
$ rskey generate -o /var/lib/rstudio-pm/rstudio-pm.key
# Or, to simply echo the key to standard input:
$ rskey generate
```

You can then encrypt data (such as database passwords) interactively with `rskey
encrypt`. For example:

``` shell
$ rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
```

Line-separated entries can also be passed on standard input:

``` shell
$ cat passwords.txt | rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
```

An `rskey decrypt` command is also provided.

## Details

* Encryption uses the well-known [NaCl Secretbox
  algorithm](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox). This means
  that the secret key must be kept secret, and anyone in possession of that key
  can decrypt any data encrypted with it.

* Key files are a sequence of 512 hex-encoded, securely-generated random bytes.
  This means that `rskey generate` is analogous to `openssl rand -hex 512`.

## API Stability and Versioning

`rskey` and its packages follow strict semantic versioning.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for details.
