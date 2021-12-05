# FreeRTOS with _virtio_ Sockets for RTSS 2021

Paper: G. Schwäricke, R. Tabish, R. Pellizzoni, R. Mancuso, A. Bastoni, A. Züpke, M. Caccamo, "A Real-Time virtio-based Framework for Predictable Inter-VM Communication", Proc. of the 42nd IEEE Real-Time Systems Symposium (RTSS 2021), Dec. 2021.

The implementation is based on [freertos-over-bao](https://github.com/bao-project/freertos-over-bao), which is a FreeRTOS variant, adapted to run under [Bao hypervisor](https://github.com/bao-project/bao-hypervisor). We adapted it further to run under Jailhouse also.

Note: This is a collection of FreeRTOS related code that we used in our work. It will not run out of the box. Some includes are Linux header files that have not been included in this repo. The usage of the virtio sockets also requires the virtio device implementation by a Jailhouse variant that is currently still under development (contact Andrea Bastoni <andrea.bastoni at tum dot de> for more information).

Copyright Notice
----------------

* For all files in `src/freertos` that stem from the FreeRTOS project the respective [MIT license](./src/freertos/LICENSE.md) holds.
* For all files in `src/` that stem from the Bao project, the chosen License of the [Bao developers](https://github.com/bao-project) holds (presumably GNU General Public License version 2, but to be confirmed with the Bao authors before usage).
* For all other files of this repository, that are not covered by the two rules above, and which do not specify a different license in the file itself, the license will default to BSD Zero Clause License (see [DefaultLicense.txt](./DefaultLicense.txt))

If there are any issues where a file in this repository violates the license terms of a respective property right owner, please write an issue and the file will be labeled correctly or removed.

Build
-----

First build jailhouse for ZCU102, with the patches below.

Building FreeRTOS to use UART 1
```bash
make CROSS_COMPILE=/path/to/toolchain/bin/aarch64-none-elf- PLATFORM=zcu102 JAILHOUSE_PATH=/path/to/jailhouse/
```

Building FreeRTOS to use UART 2
```bash
make CROSS_COMPILE=/path/to/toolchain/bin/aarch64-none-elf- PLATFORM=zcu102 JAILHOUSE_PATH=/path/to/jailhouse/ USE_SECONDARY_UART=true
```

Requirements
------------

* This should support other ARMv8 platforms too, but it is only tested on Xilinx ZCU102.
* Some fixes in Jailhouse are necessary.
    * [Fix invalid access mask for unaligned accesses](./jailhouse_patches/0001-Fix-invalid-access-mask-for-unaligned-accesses.patch)
    * [Fix interrupt priorities for virtualized GIC not being set](./jailhouse_patches/0002-Fix-interrupt-priorities-for-virtualized-GIC-not-bei.patch)
    * [Disable definition of bool type if already defined](./jailhouse_patches/0003-Disable-definition-of-bool-type-if-already-defined.patch)
