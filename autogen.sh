#! /usr/bin/env bash

set -e

update='0'
if [ "$1" = '-update' ]; then
	update='1'
fi

commands=(
	curl diff cat mkdir rm mv automake autoconf
)

urls=(
	http://chiselapp.com/user/rkeene/repository/autoconf/doc/trunk/shobj.m4
	http://chiselapp.com/user/rkeene/repository/autoconf/doc/trunk/versionscript.m4
	'http://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/ax_pthread.m4'
)

localFiles=(
)

failed='0'
for command in "${commands[@]}"; do
	if [ ! -f "$(which "${command}" 2>/dev/null)" ]; then
		echo "error: Unable to locate ${command}" >&2
		failed='1'
	fi
done
if [ "${failed}" = '1' ]; then
	exit 1
fi

cd "$(dirname "$(which "$0")")" || exit 1

mkdir aclocal >/dev/null 2>/dev/null || :

files=()

for url in "${urls[@]}"; do
	file="aclocal/$(echo "${url}" | sed 's@^.*/@@')"

	if [ -f "${file}" ]; then
		if [ "${update}" = '0' ]; then
			files=("${files[@]}" "${file}")

			continue
		fi
	fi

	curl -lsS "${url}" > "${file}.new" || exit 1
	if diff "${file}.new" "${file}" >/dev/null 2>/dev/null; then
		rm -f "${file}.new"
	else
		mv "${file}.new" "${file}"
	fi

	files=("${files[@]}" "${file}")
done

for file in "${files[@]}" "${localFiles[@]}"; do
	cat "${file}"
done > aclocal.m4.new

if diff aclocal.m4.new aclocal.m4 >/dev/null 2>/dev/null; then
	rm -f aclocal.m4.new
else
	mv aclocal.m4.new aclocal.m4
fi

automake --add-missing --copy --force-missing >/dev/null 2>/dev/null || :
if ! [ -f install-sh -o -f install.sh -o -f shtool ]; then
	echo "automake failed" >&2
	exit 1
fi

autoconf
autoheader

rm -rf autom4te.cache
