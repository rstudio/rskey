# rskey

`rskey` is a command-line tool (and bundled Go package) that generates secret
keys interoperable with the format used by RStudio's Connect and Package Manager
products.

It can be used to help manage secrets without the need to install these products
first, and is designed for use in Infrastructure-as-Code and containerised
deployments of these products.

**This is not a general-purpose encryption tool.**

## Usage

You can generate keys with `rskey generate`. For example:

``` shell
$ rskey generate > /var/lib/rstudio-pm/rstudio-pm.key
# Or, equivalently:
$ rskey generate -o /var/lib/rstudio-pm/rstudio-pm.key
```

You can then encrypt data (such as database passwords) supplied via standard
output with `rskey encrypt`. For example:

``` shell
$ echo "mypassword" | rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
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

## License

TBD
