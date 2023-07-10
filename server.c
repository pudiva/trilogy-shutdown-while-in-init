/* Copyright (C) 2023 Satana de Sant'Ana <satana@skylittlesystem.org> */
#define _XOPEN_SOURCE 700

#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>

/* error reporting */
int errorc = 0;
char errorv[1024][1024];
#define error_push(...) snprintf(errorv[errorc++], sizeof (errorv[0]), __VA_ARGS__)
#define error_pop() (errorc <= 0 ? NULL : errorv[--errorc])

void error_print(const char* file, int line)
{
	fprintf(stderr, "%s:%d: error\n", file, line);

	if (0 < errorc)
	{
		fputs("Errors:\n", stderr);
		const char* desc;
		while ((desc = error_pop()))
			fputs(desc, stderr);
		fputc('\n', stderr);
	}

	if (ERR_peek_error() != 0)
	{
		fputs("SSL errors:\n", stderr);
		ERR_print_errors_fp(stderr);
		fputc('\n', stderr);
	}

	if (errno != 0)
	{
		fputs("System error:\n", stderr);
		perror(NULL);
		fputc('\n', stderr);
		errno = 0;
	}
}

#define FAIL(label) \
	do { \
		error_print(__FILE__, __LINE__); \
		ret = -1; \
		goto label; \
	} while (0)

int slurp(BIO* bio, void* buf, int len)
{
	fflush(stdout);
	int n_read = 0;
	int n_total = 0;
	int n_left = len;
	void* p = buf;

	while (0 < n_left)
	{
		n_read = BIO_read(bio, p, n_left);

		if (n_read < 0)
		{
			if (BIO_should_retry(bio))
				continue;
			else
				break;
		}

		else
		{
			n_total += n_read;
			n_left -= n_read;
			p += n_read;
		}
	}

	if (n_total != len)
	{
		error_push("slurped %d out of %d bytes (%d left)", len, n_total, n_left);
		return -1;
	}

	return n_total;
}

int spit(BIO* bio, const void* buf, int len)
{
	int n_write = 0;
	int n_total = 0;
	int n_left = len;
	const void* p = buf;

	while (0 < n_left)
	{
		n_write = BIO_write(bio, p, n_left);

		if (n_write <= 0)
		{
			if (BIO_should_retry(bio))
				continue;
			else
				break;
		}

		else
		{
			n_total += n_write;
			n_left -= n_write;
			p += n_write;
		}
	}

	if (n_total != len)
	{
		error_push("spat %d out of %d bytes (%d left)", len, n_total, n_left);
		return -1;
	}

	return n_total;
}

/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html */
void read_int(const unsigned char* s, int n_bytes, unsigned long* x)
{
	(*x) = 0;
	for (int i = 0; i < n_bytes; ++i)
		(*x) |= ((unsigned long) s[i]) << (8*i);
}

void write_int(unsigned char* s, int n_bytes, unsigned long x)
{
	for (int i = 0; i < n_bytes; ++i)
		s[i] = x & (255 << (8*i));
}

struct packet
{
	unsigned long len, seq;
	unsigned char payload[1024];
};

/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html */
int packet_recv(BIO* bio, struct packet* p)
{
	unsigned char header[4];
	if (slurp(bio, header, sizeof (header)) < 0)
		return -1;

	read_int(&header[0], 3, &p->len);
	read_int(&header[3], 1, &p->seq);
	if (sizeof (p->payload) < p->len)
	{
		error_push("payload too big: len = %lu, max = %lu", p->len, sizeof (p->payload));
		return -1;
	}

	if (slurp(bio, p->payload, p->len) < 0)
		return -1;

	return 0;
}

int packet_send(BIO* bio, struct packet* p)
{
	unsigned char header[4];
	write_int(&header[0], 3, p->len);
	write_int(&header[3], 1, p->seq);
	if (spit(bio, header, sizeof (header)) < 0)
		return -1;

	if (spit(bio, p->payload, p->len) < 0)
		return -1;

	return 0;
}


/* signal handlers */
bool running;
void handle_signal(int signum)
{
	running = 0;
}

/* teh server */
int main(int argc, char* argv[])
{
	/* install signal handlers ASAP */
	signal(SIGINT,  handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGHUP,  handle_signal);
	signal(SIGQUIT, handle_signal);

	/* FAIL() macro */
	int ret = EXIT_SUCCESS;

	SSL_CTX* ssl_ctx = NULL;

	if (argc != 3)
	{
		fprintf(stderr, "Usage: server SSL HOST PORT\n");
		return EXIT_FAILURE;
	}

	const char* host = argv[1];
	const char* port = argv[2];

	char host_port[256];
	sprintf(host_port, "%s:%s", host, port);

	BIO* abio = BIO_new_accept(host_port);
	if (abio == NULL)
		FAIL(main_exit);

	/* make it nonblocking */
	//BIO_set_nbio_accept(abio, 1);

	/* Setup server side SSL bio */
	ssl_ctx = SSL_CTX_new(TLS_server_method());
	//ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, "cert.pem"))
		FAIL(main_exit);
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM))
		FAIL(main_exit);
	if (!SSL_CTX_check_private_key(ssl_ctx))
		FAIL(main_exit);

#if 0
	/* ssl filter */
	BIO* ssl_bio = BIO_new_ssl(ssl_ctx, 0);
	if (ssl_bio == NULL)
		FAIL(main_exit);

	/*
	 * This means that when a new connection is accepted on 'in', The
	 * ssl_bio will be 'duplicated' and have the new socket BIO push into
	 * it. Basically it means the SSL BIO will be automatically setup
	 */
	if (BIO_set_accept_bios(abio, ssl_bio) != 1)
		FAIL(main_exit);
#endif

	/*
	 * The first call will setup the accept socket, and the second will get
	 * a socket.
	 */
	if (BIO_do_accept(abio) <= 0)
		FAIL(main_exit);

	puts("Listening...");
	fflush(stdout);

	running = true;
	while (running)
	{
		BIO* in = NULL;

		if (BIO_do_accept(abio) != 1)
		{
			if (BIO_should_retry(abio))
				continue;
			else
				FAIL(req_exit);
		}

		puts("\nClient accepted");

		in = BIO_pop(abio);
		if (in == NULL)
			FAIL(req_exit);

		/* handshake */
		struct packet handshake = {
			.len = 74,
			.seq = 0,
			.payload = {
				0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x34, 0x32, 0x00,
				0x11, 0x00, 0x00, 0x00, 0x4c, 0x63, 0x0f, 0x48,
				0x44, 0x64, 0x65, 0x3d, 0x00, 0xff, 0xff, 0x08,
				0x02, 0x00, 0xff, 0xc1, 0x15, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7a,
				0x2f, 0x48, 0x4d, 0x2a, 0x3d, 0x13, 0x68, 0x72,
				0x2d, 0x63, 0x19, 0x00, 0x6d, 0x79, 0x73, 0x71,
				0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65,
				0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
				0x64, 0x00
			}
		};
		puts("server: handshake");
		if (packet_send(in, &handshake) != 0)
			FAIL(req_exit);

		/* authentication or SSL */
		struct packet auth_or_ssl = {0};
		if (packet_recv(in, &auth_or_ssl) != 0)
			FAIL(req_exit);

		unsigned long client_flags;
		read_int(auth_or_ssl.payload, 4, &client_flags);

#define CLIENT_SSL 2048
		if (client_flags & CLIENT_SSL)
		{
			puts("client: SSL please");

			/* SSL magic */
			BIO* ssl_bio = BIO_new_ssl(ssl_ctx, 0);
			in = BIO_push(ssl_bio, in);

			/* receive the auth again, reuse the same packet */
			if (packet_recv(in, &auth_or_ssl) != 0)
				FAIL(req_exit);
			puts("client: auth");
		}

		else
		{
			puts("client: auth");
		}


		/* auth ok */
		struct packet ok = {
			.len = 7,
			.seq = auth_or_ssl.seq + 1,
			.payload = {
				0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
			}
		};
		puts("server: auth ok");
		if (packet_send(in, &ok) != 0)
			FAIL(req_exit);

		/* ping */
		struct packet ping = {0};
		if (packet_recv(in, &ping) != 0)
			FAIL(req_exit);
		puts("client: ping");

		/* pong */
		struct packet pong = ok;
		pong.seq = ping.seq + 1;
		puts("server: pong");
		if (packet_send(in, &pong) != 0)
			FAIL(req_exit);

req_exit:
		BIO_free_all(in);
		//break;
	}

main_exit:
	BIO_free_all(abio);
	SSL_CTX_free(ssl_ctx);
	return ret;
}
