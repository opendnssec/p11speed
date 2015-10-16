#!/bin/sh
#
# build p11speed

sh autogen.sh && \
./configure && \
make all
