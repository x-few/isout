#!/bin/sh

basepath=$(cd `dirname $0`; pwd)
cd $basepath

# TODO: git clone lib

echo "must install autoconf automake libtool"

autoreconf --install

$basepath/configure
