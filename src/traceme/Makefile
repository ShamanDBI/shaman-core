ROOT_DIR=/local/mnt/workspace/qcom-dev/linux-syzkaller/src/camx_sdk_setup
CC=$(ROOT_DIR)/android-ndk-r22/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
CC=/local/mnt/workspace/qcom-dev/linux-syzkaller/tool/toolchain/bin/aarch64-linux-android-gcc

CFLAGS=-std=gnu11 -fPIE -pie
main:
	$(CC) -o bin/tracy $(CFLAGS) src/main.c

run:
	adb push bin/tracy /data/orange-candy
	adb shell /data/orange-candy/tracy /bin/ls