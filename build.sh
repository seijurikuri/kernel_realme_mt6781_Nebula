#!/bin/env bash
{
  TANGGAL=$(date +"%Y%m%d-%H")
  export ARCH=arm64
  export KBUILD_BUILD_HOST=AstralKernel
  export KBUILD_BUILD_USER="seijurikuri"

}

function zupload()
{
zimage=out/arch/arm64/boot/Image.gz-dtb
if ! [ -a $zimage ];
then
echo  " Failed to compile zImage, fix the errors first "
else
echo -e " Build succesful, generating flashable zip now "
rm -rf AnyKernel
git clone --depth=1 https://github.com/HELLINFIX/AnyKernel3 AnyKernel
cp out/arch/arm64/boot/Image.gz-dtb AnyKernel
cd AnyKernel
zip -r9 Nebula-${TANGGAL}.zip *
curl -L bashupload.com -T Nebula-${TANGGAL}.zip
cd ../
fi
}
#Edited this because im compiling on an android device ( spaced )