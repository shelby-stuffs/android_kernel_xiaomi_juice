#!/bin/bash
#
# Compile script for ? kernel
# Copyright (C) 2020-2021 Adithya R.

SECONDS=0 # builtin bash timer
ZIPNAME="/tmp/output/SunriseTestAdreno-juice_$(date +%Y%m%d-%H%M).zip"
AK3_DIR="$HOME/android/AnyKernel3"
DEFCONFIG="vendor/bengal-perf_defconfig"

mkdir -p /tmp/output

rel=0

env() {
export TELEGRAM_BOT_TOKEN=""
export TELEGRAM_CHAT_ID=""

TRIGGER_SHA="$(git rev-parse HEAD)"
LATEST_COMMIT="$(git log --pretty=format:'%s' -1)"
COMMIT_BY="$(git log --pretty=format:'by %an' -1)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
KERNEL_VERSION="$(cat out/.config | grep Linux/arm64 | cut -d " " -f3)"
export FILE_CAPTION="
Linux version: $KERNEL_VERSION
Branch: $BRANCH
Top commit: $LATEST_COMMIT
Commit author: $COMMIT_BY
Status: $STATUS"
}

############# Build status.
export RELEASE=$rel
if [ "${RELEASE}" == 1 ]; then
    export STATUS="Release"
else
    export STATUS="Bleeding-Edge"
fi
#############

############# Needed variables.
export KDIR=$(pwd)
export LINKER="ld"
export PATH="${KDIR}"/gcc32/bin:"${KDIR}"/gcc64/bin:/usr/bin/:${PATH}
export KBUILD_BUILD_USER=ShelbyHell
export KBUILD_BUILD_HOST=Instance
#############

if [ ! -d "${KDIR}/gcc64" ]; then
        curl -sL https://github.com/cyberknight777/gcc-arm64/archive/refs/heads/master.tar.gz | tar -xzf -
        mv "${KDIR}"/gcc-arm64-master "${KDIR}"/gcc64
fi

if [ ! -d "${KDIR}/gcc32" ]; then
	curl -sL https://github.com/cyberknight777/gcc-arm/archive/refs/heads/master.tar.gz | tar -xzf -
        mv "${KDIR}"/gcc-arm-master "${KDIR}"/gcc32
fi

if [[ $1 = "-r" || $1 = "--regen" ]]; then
make O=out ARCH=arm64 $DEFCONFIG savedefconfig
cp out/defconfig arch/arm64/configs/$DEFCONFIG
exit
fi

if [[ $1 = "-c" || $1 = "--clean" ]]; then
rm -rf out
fi

mkdir -p out
make O=out ARCH=arm64 $DEFCONFIG

env

curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendmessage" \
    -d "text=<code>Start build kernel for Redmi 9T/POCO M3</code>" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" -d "parse_mode=HTML"

echo -e "\nStarting compilation...\n"
make -j16 \
    ARCH=arm64 \
    O=out \
    CROSS_COMPILE=aarch64-elf- \
    CROSS_COMPILE_ARM32=arm-eabi- \
    LD="${KDIR}"/gcc64/bin/aarch64-elf-"${LINKER}" \
    AR=aarch64-elf-ar \
    AS=aarch64-elf-as \
    NM=aarch64-elf-nm \
    OBJDUMP=aarch64-elf-objdump \
    OBJCOPY=aarch64-elf-objcopy \
    CC=aarch64-elf-gcc Image dtbo.img 2>&1 | tee log.txt

if [ -f "out/arch/arm64/boot/Image" ]; then
echo -e "\nKernel compiled succesfully! Zipping up...\n"
if [ -d "$AK3_DIR" ]; then
cp -r $AK3_DIR AnyKernel3
elif ! git clone -q https://github.com/ShelbyHell/AnyKernel3; then
echo -e "\nAnyKernel3 repo not found locally and cloning failed! Aborting..."
exit 1
fi
cp out/arch/arm64/boot/Image AnyKernel3
cp out/arch/arm64/boot/dtbo.img AnyKernel3
rm -f *zip
cd AnyKernel3
git checkout master &> /dev/null
zip -r9 "$ZIPNAME" * -x '*.git*' README.md *placeholder
cd ..
rm -rf AnyKernel3
rm -rf out/arch/arm64/boot
echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s) !"
echo "Zip: $ZIPNAME"
if ! [[ $HOSTNAME = "enprytna" && $USER = "endi" ]]; then
curl -F document=@"${ZIPNAME}" -F "caption=${FILE_CAPTION}" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument?chat_id=${TELEGRAM_CHAT_ID}&parse_mode=Markdown"
curl -F document=@"log.txt" -F "caption=Nice work!" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument?chat_id=${TELEGRAM_CHAT_ID}&parse_mode=Markdown"
fi
else
echo -e "\nCompilation failed!"
curl -F document=@"log.txt" -F "caption=ERROR!" "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument?chat_id=${TELEGRAM_CHAT_ID}&parse_mode=Markdown"
exit 1
fi