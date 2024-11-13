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

Here's an example to create a I/O SQ and CQ and run fio based on the
configuration.

```bash
#!/bin/bash

bdf="0000:01:00.0"
bdf_dot="0000.01.00.0"

unvme start --with-fio=</path/to/fio>

unvme add $bdf
unvme enable $bdf

# Create a I/O SQ and CQ with qid=1
unvme create-iocq $bdf --qid=1 --qsize=256 --vector=1
unvme create-iosq $bdf --qid=1 --qsize=256 --cqid=1

# Initialize namespace identify data structure
unvme id-ns $bdf --nsid=1 --init

# Run random read workloads on the specific queue
unvme fio --ioengine=libunvmed --thread \
	--filename=$bdf_dot --nsid=1 --sqid=1 \
	--name=job --rw=randread --bs=4k --iodepth=256 --norandommap
```
