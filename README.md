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

## Usage

You can generate keys with `rskey generate`. For example:

``` shell
$ rskey generate > /var/lib/rstudio-pm/rstudio-pm.key
# Or, equivalently:
$ rskey generate -o /var/lib/rstudio-pm/rstudio-pm.key
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

## Details

* Encryption uses the well-known [NaCl Secretbox
  algorithm](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox). This means
  that the secret key must be kept secret, and anyone in possession of that key
  can decrypt any data encrypted with it.

* Key files are a sequence of 512 hex-encoded, securely-generated random bytes.
  This means that

``` shell
$ rskey generate
```

  is equivalent to

``` shell
$ openssl rand -hex 512
```

## API Stability and Versioning

`rskey` and its packages follow strict semantic versioning.

## License

TBD
