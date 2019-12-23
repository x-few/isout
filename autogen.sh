#!/bin/sh

basepath=$(cd `dirname $0`; pwd)
cd $basepath

autoreconf --install
$basepath/configure