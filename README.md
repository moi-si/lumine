# lumine

[简体中文](./README_zh.md)

A lightweight local proxy server that protects TLS connections over TCP, operating entirely without requiring system privileges.

## Installation

```
go install github.com/moi-si/lumine@latest
```

## Build

```
git clone https://github.com/moi-si/lumine
cd lumine
go build
```

## Document

[https://github.com/moi-si/lumine/wiki/Documentation](https://github.com/moi-si/lumine/wiki/Documentation)

# Acknowledgements

The technique in this project was originally taken from the Python tool [TlsFragment](https://github.com/maoist2009/TlsFragment).

We rewrote the whole implementation in Go, and ended up with a faster, more feature‑rich version whose configuration file looks similar to – but is not compatible with - the original.

# License

GPLv3