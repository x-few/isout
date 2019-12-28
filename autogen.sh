#!/bin/sh

basepath=$(cd `dirname $0`; pwd)
cd $basepath

# TODO: git clone lib

autoreconf --install
$basepath/configure