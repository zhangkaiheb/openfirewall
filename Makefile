



all:build

build:
	./make.sh build


prefetch:
	./make.sh prefetch

# base system

base:
	./make.sh base
getbase:
	./make.sh getbase

# toolchain

gettoolchain:
	./make.sh gettoolchain


help:
	./make.sh help



clean:
	./make.sh clean

