# tcp-flow-cache

This repository contains source code of Linux Kernel modules impementing TCP-Flow-Cache algorythm.

TCP-Flow-Cache allows to cache TCP traffic between two Linux nodes. TCP-Flow-Cache approach caches TCP-flows using Netfilter Framework and TCP/IP headers.
The main idea is caching which doesn't depend of packets / segments fragmentation.

For more details, please, refer the [article](http://www.ndsl.kaist.edu/~kyoungsoo/papers/mobisys13_woo.pdf)

___

**Build**

Recommended Kernel version is 3.19.0-15.

Build can be done by the command:

`$ make –f Makefile all`

Build result is object files low_m.ko and hi_m.ko:
* hi_m.ko - module for node connected to Internet
* low_m.ko - module for node connected to User and node with hi_m.ko module

___

**Network topology**

Test stend can be configured like:

![1](https://photos-3.dropbox.com/t/2/AAC7PpegzVQ5CKvQuQGM56qyw-gleRB-sRa-Mlf2JgDJSg/12/241874014/png/32x32/3/1528203600/0/2/stend%20eng.png/EOzTu9cBGJy_ASACKAIoBA/QRdRCaB1QEhqQ70pK3CrqXdoO7NpMV-o8f9NuIul_rA?dl=0&preserve_transparency=1&size=1280x960&size_mode=3)

___

**Modules installation**

For node connected to Internet:

`$ sudo insmod hi_m.ko`

For node connected to User:

`$ sudo insmod low_m.ko`
