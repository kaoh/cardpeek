#!/bin/bash

ARCH=32
DLL_CLASSIFIER=
CHECK_ARCH=`file cardpeek.exe`
if [[ $CHECK_ARCH == *"x86-64"* ]]; then
    ARCH=64
    DLL_CLASSIFIER=-x64
fi

DEST=cardpeek-win${ARCH}

rm -rf ${DEST}
mkdir ${DEST}
cp cardpeek.exe ${DEST}

if [ ${ARCH} -eq 32 ]
then
  cp /mingw${ARCH}/bin/lua53.dll ${DEST}
  cp /mingw${ARCH}/bin/libgcc_s_dw2-1.dll ${DEST}
else
  cp /mingw${ARCH}/bin/lua54.dll ${DEST}
  cp /mingw${ARCH}/bin/libgcc_s_seh-1.dll ${DEST}
fi

cp /mingw${ARCH}/bin/libcairo-2.dll ${DEST}
cp /mingw${ARCH}/bin/libcrypto-1_1${DLL_CLASSIFIER}.dll  ${DEST}
cp /mingw${ARCH}/bin/libcurl-4.dll ${DEST}
cp /mingw${ARCH}/bin/libgdk-3-0.dll ${DEST}
cp /mingw${ARCH}/bin/libgdk_pixbuf-2.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libgio-2.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libglib-2.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libgobject-2.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libgtk-3-0.dll ${DEST}
cp /mingw${ARCH}/bin/libiconv-2.dll ${DEST}
cp /mingw${ARCH}/bin/libpango-1.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libreadline8.dll ${DEST}
cp /mingw${ARCH}/bin/libfontconfig-1.dll ${DEST}
cp /mingw${ARCH}/bin/libfreetype-6.dll ${DEST}
cp /mingw${ARCH}/bin/libpixman-1-0.dll ${DEST}
cp /mingw${ARCH}/bin/libpng16-16.dll ${DEST}
cp /mingw${ARCH}/bin/zlib1.dll ${DEST}
cp /mingw${ARCH}/bin/libgmodule-2.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libintl-8.dll ${DEST}
cp /mingw${ARCH}/bin/libwinpthread-1.dll ${DEST}
cp /mingw${ARCH}/bin/libbrotlidec.dll ${DEST}
cp /mingw${ARCH}/bin/libidn2-0.dll ${DEST}
cp /mingw${ARCH}/bin/libnghttp2-14.dll ${DEST}
cp /mingw${ARCH}/bin/libpsl-5.dll ${DEST}
cp /mingw${ARCH}/bin/libssh2-1.dll ${DEST}
cp /mingw${ARCH}/bin/libssl-1_1${DLL_CLASSIFIER}.dll ${DEST}
cp /mingw${ARCH}/bin/libzstd.dll ${DEST}
cp /mingw${ARCH}/bin/libcairo-gobject-2.dll ${DEST}
cp /mingw${ARCH}/bin/libepoxy-0.dll ${DEST}
cp /mingw${ARCH}/bin/libfribidi-0.dll ${DEST}
cp /mingw${ARCH}/bin/libpangocairo-1.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libffi-7.dll ${DEST}
cp /mingw${ARCH}/bin/libpangowin32-1.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libpcre-1.dll ${DEST}
cp /mingw${ARCH}/bin/libharfbuzz-0.dll ${DEST}
cp /mingw${ARCH}/bin/libatk-1.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libbrotlicommon.dll ${DEST}
cp /mingw${ARCH}/bin/libbz2-1.dll ${DEST}
cp /mingw${ARCH}/bin/libpangoft2-1.0-0.dll ${DEST}
cp /mingw${ARCH}/bin/libtermcap-0.dll ${DEST}
cp /mingw${ARCH}/bin/libthai-0.dll ${DEST}
cp /mingw${ARCH}/bin/libunistring-2.dll ${DEST}
cp /mingw${ARCH}/bin/libexpat-1.dll ${DEST}
cp /mingw${ARCH}/bin/libdatrie-1.dll ${DEST}
cp /mingw${ARCH}/bin/libstdc++-6.dll ${DEST}
cp /mingw${ARCH}/bin/libgraphite2.dll ${DEST}
cp AUTHORS ${DEST}
cp COPYING ${DEST}
cp ChangeLog ${DEST}
cp doc/cardpeek_ref.en.pdf ${DEST}

# icons for gdk
mkdir ${DEST}/share
declare -a icons=("icon-theme.cache" "index.theme" "dialog-question" "edit-redo" "edit-clear" "document-open" "application-exit" "document-save-as" "help-about" "system-run" "pan-down")
for img in "${icons[@]}"; do
  for file in `find /mingw${ARCH}/share/icons -name "*${img}*"`; do 
    PART=`echo $(dirname ${file}) | cut -d'/' -f4-`
    mkdir -p ${DEST}/share/${PART}
    cp $file ${DEST}/share/${PART}
  done
done
rm -rf ${DEST}/share/icons/hicolor


# image loaders needed for gdk
mkdir ${DEST}/lib
cp -R /mingw${ARCH}/lib/gdk-pixbuf-2.0 ${DEST}/lib/
find ${DEST}/lib/gdk-pixbuf-2.0 -name "*.a" | xargs rm
# schemas for GLib
mkdir ${DEST}/share/glib-2.0
cp -R /mingw${ARCH}/share/glib-2.0/schemas ${DEST}/share/glib-2.0

powershell Compress-Archive -Force ${DEST} ${DEST}.zip

