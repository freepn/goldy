#! /bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

THEDIR="`pwd`"
cd "$srcdir"
DIE=0

abort () {
    echo "$1 not found or command failed. Aborting!"
    exit 1
}

set -x

autoreconf -v -f -i || abort
