/* Copyright (C) 2023 Satana de Sant'Ana <satana@skylittlesystem.org> */
#define _XOPEN_SOURCE 700

#include "trilogy.h"
#include <signal.h>
#include <stdio.h>

#if 1
#define VERBOSE(...) ((void) 0)
#else
#define VERBOSE(...) fprintf(stderr, __VA_ARGS__)
#endif

void error_print(const char* file, int line, trilogy_conn_t* conn, int err)
{
	if (err < 0)
	{
		fprintf(stderr, "%s:%d: error %d: %s\n", __FILE__, line, err, trilogy_error(err));

		switch (err)
		{
		case TRILOGY_ERR:
			fprintf(stderr, "%d %.*s\n", conn->error_code, (int) conn->error_message_len, conn->error_message);
			break;

		case TRILOGY_OPENSSL_ERR:
			ERR_print_errors_fp(stderr);
			break;

		case TRILOGY_SYSERR:
			perror("");
			break;
		}
	}
}

#define FAIL(label) \
	do { \
		error_print(__FILE__, __LINE__, &conn, err); \
		goto label; \
	} while (0)

#define FAIL_IF_ERR(label) \
	do { \
		if (err != TRILOGY_OK) \
			FAIL(label); \
	} while (0)

#define RETRY(expr) \
		do { \
			err = (expr); \
			if (err == TRILOGY_AGAIN) \
			{ \
				VERBOSE("%s:%d: RETRY(): TRILOGY_AGAIN\n", __FILE__, __LINE__); \
				err = trilogy_sock_wait_read(conn.socket); \
				if (err == TRILOGY_OK) \
					continue; \
			} \
			else \
			{ \
				break; \
			} \
		} while (1)

#define FLUSH() \
		do { \
			if (err == TRILOGY_AGAIN) \
			{ \
				VERBOSE("%s:%d: FLUSH(): TRILOGY_AGAIN\n", __FILE__, __LINE__); \
				err = trilogy_sock_wait_write(conn.socket); \
				if (err == TRILOGY_OK) \
					err = trilogy_flush_writes(&conn); \
				continue; \
			} \
			else \
			{ \
				break; \
			} \
		} while (1)

/* signal handlers */
bool running;
void handle_signal(int signum)
{
	running = 0;
}

/* teh client */
int main(int argc, char *argv[])
{
	/* install signal handlers ASAP */
	signal(SIGINT,  handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGHUP,  handle_signal);
	signal(SIGQUIT, handle_signal);

	/* ignore SIGPIPE so that server can continue running when client pipe
	 * closes abruptly */
	signal(SIGPIPE, SIG_IGN);

	if (argc != 8)
	{
		fprintf(stderr, "Usage: %s SSL HOST PORT USER PASS DB SQL\n", argv[0]);
		return EXIT_FAILURE;
	}

	trilogy_sockopt_t connopt = {0};
	bool use_ssl		= argv[1][0] != '0';
	connopt.hostname	= argv[2];
	connopt.port		= atoi(argv[3]);
	connopt.username	= argv[4];
	connopt.password	= argv[5];
	connopt.database	= argv[6];
	char* sql		= argv[7];
	connopt.password_len	= strlen(connopt.password);

	running = true;
	while (running)
	{
		int err;
		trilogy_conn_t conn;
		trilogy_handshake_t handshake;

		VERBOSE("client: trilogy_init\n");
		err = trilogy_init(&conn);
		FAIL_IF_ERR(req_exit);

		VERBOSE("client: trilogy_connect_send\n");
		err = trilogy_connect_send(&conn, &connopt);
		FAIL_IF_ERR(req_exit);

		VERBOSE("client: trilogy_connect_recv\n");
		RETRY(trilogy_connect_recv(&conn, &handshake));
		FAIL_IF_ERR(req_exit);

		if (use_ssl)
		{
			VERBOSE("client: trilogy_ssl_request_send\n");
			err = trilogy_ssl_request_send(&conn);
			FLUSH();
			FAIL_IF_ERR(req_exit);

			VERBOSE("client: trilogy_sock_upgrade_ssl\n");
			err = trilogy_sock_upgrade_ssl(conn.socket);
			FAIL_IF_ERR(req_exit);
		}

		VERBOSE("client: trilogy_auth_send\n");
		err = trilogy_auth_send(&conn, &handshake);
		FLUSH();
		FAIL_IF_ERR(req_exit);

		VERBOSE("client: trilogy_auth_recv\n");
		RETRY(trilogy_auth_recv(&conn, &handshake));
		if (err == TRILOGY_AUTH_SWITCH)
		{
			VERBOSE("client: trilogy_auth_switch_send\n");
			err = trilogy_auth_switch_send(&conn, &handshake);
			FLUSH();
			FAIL_IF_ERR(req_exit);

			VERBOSE("client: trilogy_auth_recv\n");
			RETRY(trilogy_auth_recv(&conn, &handshake));
			FAIL_IF_ERR(req_exit);
		}
		FAIL_IF_ERR(req_exit);

		VERBOSE("client: trilogy_ping\n");
		err = trilogy_ping(&conn);
		FAIL_IF_ERR(req_exit);

		if (connopt.database != NULL)
		{
			VERBOSE(stderr, "client: trilogy_change_db: %s\n", connopt.database);
			err = trilogy_change_db(&conn, connopt.database, strlen(connopt.database));
			FAIL_IF_ERR(req_exit);
		}

		uint64_t column_count = 0;
		uint64_t row_count = 0;
		VERBOSE(stderr, "client: trilogy_query: %s\n", sql);
		err = trilogy_query(&conn, sql, strlen(sql), &column_count);
		VERBOSE(stderr, "client: trilogy_query: got %lu columns\n", column_count);
		if (err == TRILOGY_HAVE_RESULTS)
		{
			for (uint64_t i = 0; i < column_count; i++)
			{
				trilogy_column_packet_t column;
				err = trilogy_read_full_column(&conn, &column);
			}

			trilogy_value_t values[1024];
			while ((err = trilogy_read_full_row(&conn, values)) == TRILOGY_OK)
				++row_count;
			if (!(err == TRILOGY_OK || err == TRILOGY_EOF))
				FAIL(req_exit);
		}
		else if (err != TRILOGY_OK)
		{
			FAIL(req_exit);
		}
		VERBOSE(stderr, "client: trilogy_query: got %lu rows\n", row_count);

		VERBOSE("client: trilogy_close\n");
		err = trilogy_close(&conn);
		FAIL_IF_ERR(req_exit);

req_exit:
		trilogy_free(&conn);
		//sleep(1);
		VERBOSE("\n");
		//fflush(stdout);
	}

	return EXIT_SUCCESS;
}
