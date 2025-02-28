# `libunvmed` I/O engine

`unvme-cli` provides an exteranl `libunvmed` I/O engine for `fio`.  Device
configurations (e.g., controller enable, queue creations, ...) can be done by
CLI commands and I/O benchmarking cna be done with **unmodified** fio, but only
just built as a shared object.

To enable fio, provide `-Dwith-fio=</path/to/fio>` when meson setup.

# How to build fio
To build `fio` as a shared object, do the following:

```bash
LDFLAGS="-shared" ./configure --extra-cflags='-fPIC'
make -j`nproc`
```

Object file named `fio` will be generated and you will see it's a shared
object like:

```bash
$ file fio
fio: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked ...
```

# How to run `unvmed` with fio
To run unvmed daemon process with pre-built fio:

```bash
unvme start --with-fio=</path/to/fio.so>
```
