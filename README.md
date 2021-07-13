# ASAP: ASAP: Fast Mobile Application Switch via Adaptive Prepaging
This repo contains the code written for ASAP: Fast Mobile Application Switch via Adaptive Prepaging (published in
ATC'21). For more detail about the project, please refer to our [paper](https://www.usenix.org/conference/atc21/presentation/son).

## Usage
This code is a patch of Google Pixel 4's Linux kernel. To test this code, you should  
1. Dowload Pixel 4's kernel using repo 
2. Patch the code in this repo
3. Compile the patched kernel image, then flash it to Google Pixel 4.

### Dowloading Kernel
```console
$ mkdir $WD && cd $WD
$ repo init -u https://android.googlesource.com/kernel/manifest -b android-msm-coral-4.14-android10
$ repo sync -j4
```

### Patching ASAP
```console
$ git clone https://github.com/SNU-ARC/atc21-asap-kernel.git
```
Update app_table_init() function in atc21-asap-kernel/src/asap/sysctl.c to match applications installed on your device.

```console
$ cp atc21-asap-kernel/src/* $WD/private/msm-google/ -R 
$ cp atc21-asap-kernel/config/* $WD
```

### Compiling and flashing kernel
Please refer to Android official [guide](https://source.android.com/setup/build/building-kernels).

## Android Integration
To test ASAP, you need to write pid of the switching application to ```/proc/sys/vm/app_switch_start``` at the beginning of the switch, and ```/proc/sys/vm/app_switch_end``` at the end of the switch. To implement this, we added a few lines to ActivityManager code in AOSP. We'll open this code and test script if there is an interest. Please contact the project maintainer.

## Maintainer
Sam Son (sosson97@gmail.com)

## Paper
Please cite the following paper if you use this code.
```
@inproceedings {273883,
author = {Sam Son and Seung Yul Lee and Yunho Jin and Jonghyun Bae and Jinkyu Jeong and Tae Jun Ham and Jae W. Lee and Hongil Yoon},
title = {{ASAP}: Fast Mobile Application Switch via Adaptive Prepaging},
booktitle = {2021 {USENIX} Annual Technical Conference ({USENIX} {ATC} 21)},
year = {2021},
isbn = {978-1-939133-23-6},
pages = {365--380},
url = {https://www.usenix.org/conference/atc21/presentation/son},
publisher = {{USENIX} Association},
month = jul,
}
```
