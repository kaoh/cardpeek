Build instructions for MacOS X
==============================

## Prerequisites

~~~shell
brew install autoconf make glib gtk+3 lua curl openssl automake pcsc-lite
~~~

## Build

~~~shell
autoreconf --install
./configure --with-openssl=`brew --prefix openssl`
make
~~~

## Install

(use sudo if necessary):

~~~shell
make install
~~~
