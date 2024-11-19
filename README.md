# *unvme-cli*: Configure NVMe by CLI, and test it with *fio*!

`unvme-cli` is a command line interface to control NVMe controller without
kernel NVMe driver on the user-space.  It also provides I/O benchmarking test
by `fio` with `libunvmed` ioengine which is bundled within this program.

## Why unvme-cli?
- Users can setup user-defined configurations (e.g., IO queues) without kernel driver intervention
- Users can run *fio* with various testing features based on the
  user-defined configurations
- Users can introduce user-defined scenarios (e.g., doorbell update) to test NVMe controller
- Educational purpose to understand NVMe spec.
- Do all these with a simple portable program `unvme`

## How to build

**Requirements**
  - libvfn (>= 5.1.0)
  - libnvme (>= 1.8.0)
  - fio (optional)

Provide *fio* path with `-Dwith-fio=` option to enable `unvme fio` command,
otherwise, `unvme fio` command will not be bundled inside of `unvme` executable.

```bash
meson setup build -Dwith-fio=</path/to/fio/src>
meson install -C build
```

## How to run
`unvme` commands are handled in the `unvmed` daemon service.  To run the daemon
service in the background:

(*To enable fio, fio should be pre-built.  See details in app/fio/README.md*)

```bash
unvme start --with-fio=</path/to/fio.so>
```

To terminate the daemon service, do simply:

```bash
unvme stop
```

Please refer examples test cases under *examples/*.

## Example

Here's an example to create a I/O SQ and CQ and run fio based on the
configuration.

```bash
#!/bin/bash

bdf="0000:01:00.0"  # This can be shortend "1:0" or "0:1:0" or ...
bdf_dot=$(echo $bdf | sed 's/:/./g')  # Convert ':' to '.' for fio

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

## License
`unvme-cli` is licensed under the GNU General Public License v2.0 only.

Files under GPL-2.0-or-later can be used under terms of GPL-2.0 or any later
version, but when included in this project, they are subject to the
GPL-2.0-only license.

Files for `libunvmed` in the lib/ directory are dual-licensed under the
LGPL-2.1-or-later and the MIT license and they also can be used under their own
terms, but when it's in this project, they should be under GPL-2.0-only.  See
`lib/COPYING` and `lib/LICENSE`.

`unvme-cli` uses various libraries. ccan/ directory which has various libraries
of Comprehensive C Archive Network (CCAN) which have separated licenses.  See
`ccan/ccan/*/LICENSE` for each license used.  `argtable3/` directory contains
argtable3 library which is under BSD license, see the details in
argtable3/LICENSE.
