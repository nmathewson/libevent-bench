#include <sys/queue.h>
#include <stdio.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "ssl-utils.h"

#define DEFAULT_PLAIN_ADDR "127.0.0.1:5501"
#define DEFAULT_SSL_ADDR "127.0.0.1:5502"

// components:
// 	Client
//	Server

struct ssl_listener_info {
	SSL_CTX *ctx;
	X509 *cert;
	EVP_PKEY *key;
};

struct conn {
	unsigned long id;
	struct event_base *base;
	struct bufferevent *bev;
	TAILQ_ENTRY(conn) next;
};

TAILQ_HEAD(conn_list, conn);

static unsigned long id_count = 0;
// XXX should this be a vector instead?
static struct conn_list active_conns;
static struct sockaddr_storage listener_plain_addr;
static struct sockaddr_storage listener_ssl_addr;
static struct evconnlistener *listener_plain = NULL;
static struct evconnlistener *listener_ssl = NULL;

static void
conn_read_cb(struct bufferevent *bev, void *_conn)
{
	struct conn *conn = _conn;
}

static void
conn_write_cb(struct bufferevent *bev, void *_conn)
{
	struct conn *conn = _conn;
}

static void
conn_event_cb(struct bufferevent *bev, short what, void *_conn)
{
	struct conn *conn = _conn;
}

static struct conn *
conn_new(struct event_base *base, struct bufferevent *cbev)
{
	struct conn *conn;

	conn = calloc(1, sizeof(*conn));
	conn->bev = cbev;
	conn->id = id_count++;
	conn->base = base;

	bufferevent_setcb(cbev, conn_read_cb, conn_write_cb,
			  conn_event_cb, conn);

	return conn;
}

static void
listener_plain_cb(struct evconnlistener *listener, evutil_socket_t s,
		  struct sockaddr *addr, int socklen, void *arg)
{
	struct event_base *base;
	struct bufferevent *bev;
	struct conn *conn;

	base = evconnlistener_get_base(listener);
	bev = bufferevent_socket_new(base, s, BEV_OPT_CLOSE_ON_FREE);
	conn = conn_new(base, bev);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
listener_ssl_cb(struct evconnlistener *listener, evutil_socket_t s,
		struct sockaddr *addr, int socklen, void *arg)
{
	struct ssl_listener_info *info = arg;
	struct event_base *base;
	struct bufferevent *bev;
	SSL *ssl;
	struct conn *conn;

	base = evconnlistener_get_base(listener);

	ssl = SSL_new(info->ctx);
	SSL_use_certificate(ssl, info->cert);
	SSL_use_PrivateKey(ssl, info->key);

	bev = bufferevent_openssl_socket_new(base, s, ssl,
			BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

	conn = conn_new(base, bev);
	//TAILQ_INSERT_TAIL(&active_conns, conn, next);

	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct ssl_listener_info info;
	int len = sizeof(struct sockaddr_storage);

	evutil_parse_sockaddr_port(DEFAULT_PLAIN_ADDR,
				(struct sockaddr *)&listener_plain_addr, &len);
	evutil_parse_sockaddr_port(DEFAULT_SSL_ADDR,
				(struct sockaddr *)&listener_ssl_addr, &len);
	ssl_init();

	// XXX parse cmd line args

	info.key = ssl_build_key();
	info.cert = ssl_build_cert(info.key);
	info.ctx = SSL_CTX_new(SSLv23_method());

	base = event_base_new();

	listener_plain = evconnlistener_new_bind(base, listener_plain_cb, NULL,
			LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
			(struct sockaddr *)&listener_plain_addr,
			sizeof(listener_plain_addr));

	listener_ssl = evconnlistener_new_bind(base, listener_ssl_cb, &info,
			LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
			(struct sockaddr *)&listener_ssl_addr,
			sizeof(listener_ssl_addr));

	event_base_dispatch(base);

	return 0;
}
