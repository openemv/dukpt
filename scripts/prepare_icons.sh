#!/bin/bash

# Let script show exact commands
set -x

# NOTE: this script depends on Imagemagick. Given that Imagemagick may
# delegate processing of SVGs to various different backends that may have
# different behaviour regarding the alpha channel, it's best to use a PNG icon
# with the correct alpha channel as the input icon.

function help {
	printf "Usage: %s [icons-dir] [input-icon]\n" "$(basename "$0")"
	exit 1
}

if [ $# -ne 2 ]; then
	help
fi

icons_dir="$1"
input_icon="$2"

if [ ! -f "${input_icon}" ]; then
	printf "${icons_dir}/${icon_src} does not exist!\n"
	exit 1
fi

# Trim the input icon before creating the various resized outputs
magick "${input_icon}" -trim "${icons_dir}/openemv_dukpt_trimmed.png"

# Output various icon sizes for use in the menu, app window, taskbar and installer
magick "${icons_dir}/openemv_dukpt_trimmed.png" -resize 512x512 -background none -gravity center -extent 512x512 "${icons_dir}/openemv_dukpt_512x512.png"
magick "${icons_dir}/openemv_dukpt_trimmed.png" -resize 256x256 -background none -gravity center -extent 256x256 "${icons_dir}/openemv_dukpt_256x256.png"
magick convert "${icons_dir}/openemv_dukpt_256x256.png" "${icons_dir}/openemv_dukpt.ico"
magick "${icons_dir}/openemv_dukpt_trimmed.png" -resize 150x57 -background white -gravity center -extent 150x57 "${icons_dir}/openemv_dukpt_150x57.png"
magick convert "${icons_dir}/openemv_dukpt_150x57.png" "BMP3:${icons_dir}/openemv_dukpt.bmp"
