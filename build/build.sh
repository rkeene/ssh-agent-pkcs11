#! /bin/sh

./autogen.sh || exit 1

if [ ! -x configure ]; then
	exit 1
fi
