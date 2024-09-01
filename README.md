# *unvme-cli*

`unvme-cli` is a command line interface to control NVMe controller without
kernel NVMe driver on the user-space.  It's based on `libvfn` so that it requires
`libvfn` libraries to be installed.

## Why unvme-cli?
- Users can setup user-defined configurations (e.g., IO queues) without kernel driver intervention
- Users can introduce user-defined scenarios (e.g., doorbell update) to test NVMe controller
- Educational purpose to understand NVMe spec.
- Do all these with a simple portable program `unvme`

## How to run
`unvmed` is a daemon service process to handle requests by `unvme-cli`.  To
communicate with NVMe device in the system, you should run `unvmed` first by
`unvme start` command.  If you want to kill the running `unvmed` daemon process,
`unvme stop` is the one to run.

Please refer examples test cases under examples/.

## How to build

**Requirements**
  - libvfn (>= 5.1.0)
  - libnvme (>= 1.8.0)

```bash
meson setup build
ninja -C build
```

To install `unvme-cli` on your system,

```bash
cd build && meson install
```

## License
`unvme-cli` is licensed under the GNU General Public License v2.0 or later,
except for `libunvmed` files in the lib/ directory, which are dual-licensed
under the LGPL-2.1-or-later and the MIT License.

`unvme-cli` uses `libvfn` library. And also please note that `unvme-cli` uses
various libraries of Comprehensive C Archive Network (CCAN) which have separated
licenses.  See `ccan/ccan/*/LICENSE` for each license used.
