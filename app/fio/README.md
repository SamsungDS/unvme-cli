# `libunvmed` I/O engine

`unvme-cli` provides an exteranl `libunvmed` I/O engine for `fio`.  Device
configurations (e.g., controller enable, queue creations, ...) can be done by
CLI commands and I/O benchmarking cna be done with **unmodified** fio, but only
just built as a shared object.

To enable fio, provide `-Dwith-fio=<fio.so>` when meson setup.

# How to build fio
To build `fio` as a shared object, do the following:

```bash
cd </src/to/fio>

LDFLAGS="-shared" ./configure --extra-cflags='-fPIC' \
	--disable-numa \
	--disable-rdma \
	--disable-rados \
	--disable-rbd \
	--disable-http \
	--disable-gfapi \
	--disable-libnfs \
	--disable-lex \
	--disable-pmem \
	--disable-native \
	--disable-xnvme \
	--disable-isal \
	--disable-libblkio \
	--disable-libzbc \
	--disable-tcmalloc \
	--dynamic-libengines \
	--disable-dfs \
	--disable-tls
make -j`nproc`
cp fio /usr/local/bin/unvme-fio
```
