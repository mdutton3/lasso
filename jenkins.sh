#!/bin/bash -e
./autogen.sh
./configure --enable-gtk-doc --enable-gtk-doc-html --enable-gtk-doc-pdf
make all check
make distcheck
