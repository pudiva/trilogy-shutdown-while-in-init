# Copyright (C) 2023 Satana de Sant'Ana <satana@skylittlesystem.org>
.POSIX:

CC		= gcc

COPTS		= \
		  -O0 \
		  -ggdb \
		  -DDEBUG \
		  -Wall \
		  #-fsanitize=address \

LDOPTS		= \
		  #-static

CFLAGS		= \
		  -I. \
		  -I trilogy/inc \
		  -std=c99 \
		  -pipe \
		  `pkg-config openssl --cflags` \
		  $(COPTS) \

LDFLAGS		= \
		  `pkg-config openssl --libs` \
		  $(LDOPTS) \

all: cert.pem key.pem client server

clean:
	rm -f *.o cert.pem key.pem client server
	cd trilogy && make clean

test:
	docker-compose up --build --scale client=8

tcpflow:
	sudo tcpflow -i lo -cDg port 3306

key.pem:
cert.pem:
	openssl req \
		-newkey rsa:4096 \
		-x509 \
		-sha256 \
		-days 666 \
		-nodes \
		-subj "/CN=localhost" \
		-out cert.pem \
		-keyout key.pem

trilogy:
	git clone git@github.com:trilogy-libraries/trilogy.git

trilogy_make: trilogy
	cd trilogy && make libtrilogy.a

client: client.c trilogy_make trilogy/libtrilogy.a
	$(CC) -o $@ client.c trilogy/libtrilogy.a $(CFLAGS) $(LDFLAGS)

server: server.c
	$(CC) -o $@ server.c $(CFLAGS) $(LDFLAGS)

#client-debian-stretch: client.c common.c common.h Dockerfile.debian-stretch
#	docker build -t . -f Dockerfile.debian-stretch
#	docker run github-exe cat client > client-debian-stretch
#
#client-ubuntu-focal: client.c common.c common.h Dockerfile.debian-stretch
#	docker build -t  .
#	docker run github-exe cat client > client-ubuntu-focal
