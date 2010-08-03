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
#define DEFAULT_BASE_PATH "./"

static void conn_read_cb(struct bufferevent *bev, void *_conn);
static void conn_write_cb(struct bufferevent *bev, void *_conn);
static void conn_event_cb(struct bufferevent *bev, short what, void *_conn);

// components:
// 	Client
//	Server

struct ssl_listener_info {
	SSL_CTX *ctx;
	X509 *cert;
	EVP_PKEY *key;
};

struct conn {
	ev_uint32_t id;
	struct event_base *base;
	struct bufferevent *bev;
	struct message *inmsg;
	struct message *outmsg;
	struct property_list properties;
};

/* valid client id's start at one. if a client has an id of zero, the
   connection hasn't finished handshaking yet. */
static ev_uint32_t id_count = 1;
static size_t active_conns_allocated = 0;
static struct conn **active_conns = NULL;
static struct sockaddr_storage listener_plain_addr;
static struct sockaddr_storage listener_ssl_addr;
static struct evconnlistener *listener_plain = NULL;
static struct evconnlistener *listener_ssl = NULL;
static const char *server_base_path = DEFAULT_BASE_PATH;
static struct file_list server_files;

static int
active_conns_add(struct conn *conn)
{
	struct conn **newconns;
	size_t amt = active_conns_allocated;

	assert(conn->id == 0);
	conn->id = id_count++;

	while (conn->id >= amt) {
		if (amt < 16)
			amt = 16;
		else
			amt <<= 1;
		newconns = realloc(active_conns, amt);
		if (!newconns)
			return -1;
		memset(newconns + active_conns_allocated, 0,
		       amt - active_conns_allocated);
		active_conns_allocated = amt;
		active_conns = newconns;
	}

	assert(active_conns[conns->id] == NULL);
	active_conns[conn->id] = conn;
}

static void
active_conns_del(struct conn *conn)
{
	assert(active_conns[conn->id] == conn);
	active_conns[conn->id] = NULL;
}

static inline struct conn *
active_conns_get(ev_uint32_t id)
{
	if (id >= active_conns_allocated)
		return NULL;
	return active_conns[id];
}

static struct conn *
conn_new(struct event_base *base, struct bufferevent *cbev)
{
	struct message *inmsg, outmsg;
	struct conn *conn;

	inmsg = message_new();
	if (!inmsg)
		return NULL;
	outmsg = message_new();
	if (!outmsg) {
		message_destroy(inmsg)
		return NULL;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	conn->bev = cbev;
	conn->id = 0;
	conn->base = base;
	conn->inmsg = inmsg;
	conn->outmsg = outmsg;
	conn->inbuf = evbuffer_get_input(cbev);
	conn->outbuf = evbuffer_get_output(cbev);
	TAILQ_INIT(&conn->properties);

	return conn;
}

static void
conn_destroy(struct conn *conn)
{
	message_destroy(conn->inmsg);
	message_destroy(conn->outmsg);
	bufferevent_free(conn->bev);
	free(conn);
}

static void
conn_create(struct event_base *base, struct bufferevent *bev)
{
	size_t i;
	struct conn *conn;
	struct message *msg;

	conn = conn_new(base, bev);
	if (!conn) {
		log_error("server: unable to create connection.");
		return;
	}

	bufferevent_setcb(bev, conn_read_cb, conn_write_cb,
			  conn_event_cb, conn);

	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
conn_send_error(struct conn *conn, const char *what)
{
	message_encode_error(conn->outmsg, what, conn->outbuf);
	message_reset(conn->inmsg);
	message_reset(conn->outmsg);
}

static inline int
conn_has_handshaked(struct conn *conn)
{
	return conn->id != 0;
}

static int
conn_process_input(struct conn *conn)
{
	if (message_parse_payload(conn->inmsg) != MSGST_OK)
		return -1;
}

static int
conn_finish_setup(struct conn *conn)
{
	ev_uint32_t i;

	if (conn_process_input(conn) < 0) {
		log_warn("server: handshake with client failed");
		return -1;
	}

	property_list_move(&conn->properties,
			   message_payload_get_properties(conn->inmsg));

	active_conns_add(conn);

	/* Let everyone know about this new peer */
	message_encode_greeting_rsp(conn->outmsg, conn->id, conn->outbuf);

	for (i = 0; i < id_count; ++i) {
		struct conn *ac = active_conns[i];
		if (ac == conn)
			continue;
		message_encode_peer_notice(ac->outmsg, conn->id,
					   &conn->properties,
					   ac->outbuf);
		message_encode_peer_notice(conn->outmsg, ac->id,
					   &ac->properties,
					   ac->outbuf);
	}

	return 0;
}

static int
conn_relay_chat(struct conn *conn)
{
	struct conn *dest_conn;

	dest_conn = active_conns_get(message_get_destination(conn->outmsg));
	if (!dest_conn) {
		conn_send_error(conn, "unknown destination");
		return -1;
	}

	message_encode(conn->inmsg, dest_conn->outbuf);
		
	return 0;
}

static int
conn_send_file(struct conn *conn)
{
	struct conn *dest_conn;
	struct file_ent *fe;
	const char *fname;
	int found;
	FILE *fp;
	char buf[1024];
	size_t amt;

	if (conn_process_input(conn) < 0)
		return -1;

	dest_conn = active_conns_get(message_get_destination(conn->inmsg));
	if (!dest_conn) {
		conn_send_error(conn, "destination unknown");
		return -1;
	}

	fname = message_payload_get_file_name(conn->inmsg);
	assert(fname != NULL);

	found = 0;
	TAILQ_FOREACH(fe, &server_files, next) {
		if (!strcmp(fe->name, fname)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		conn_send_error(conn, "unknown file");
		return -1;
	}

	fp = fopen(fname, "rb");
	if (!fp) {
		log_error("server: unable to open %s!", fname);
		conn_send_error(conn, "unable to open file");
		return -1;
	}

	/* XXX this isn't very efficient */
	while ((amt = fread(buf, 1, sizeof(buf), fp)))
		evbuffer_add(message_get_payload(conn->outmsg), buf, amt);

	fclose(fp);

	message_encode_file_contents(dest_conn->outmsg,
		message_get_origin(conn->inmsg), dest_conn->id,
		dest_conn->outbuf);

	return 0;
}

static void
conn_read_cb(struct bufferevent *bev, void *_conn)
{
	struct conn *conn = _conn;
	int rv = MSGST_OK;

	if (message_get_type(conn->inmsg) == MSG_UNKNOWN) {
		rv = message_parse_header(conn->inmsg, conn->inbuf);
		if (rv <= MSGST_CONT) {
			if (rv == MSGST_FAIL) {
				log_warn("server: received malformed message");
				conn_destroy(conn);
			}
			return;
		}
	} else if (message_read_payload(conn->inmsg, conn->inbuf) != MSGST_OK)
		return;

	if (conn_has_handshaked(conn) &&
	    message_get_type(conn->inmsg) != MSG_GREETING_REQ) {
		conn_send_error(conn, "first message must be greeting");
		return;
	}

	switch (message_get_type(conn->inmsg)) {
	case MSG_GREETING_REQ:
		if (conn_finish_setup(conn) < 0)
			return;
		break;
	case MSG_SEND_CHAT:
	case MSG_ECHO_REQ:
	case MSG_ECHO_RSP:
		/* Forward a chat message to another client. */
		if (conn_relay_chat(conn) < 0)
			return;
		break;
	case MSG_FILE_LIST_REQ:
		message_encode_file_list_rsp(conn->outmsg, &server_files,
					     conn->outbuf);
		break;
	case MSG_SEND_FILE:
		if (conn_send_file(conn) < 0)
			return;
		break;

	/* These messages shouldn't be sent to the server. */
	case MSG_PEER_NOTICE:
	case MSG_FILE_CONTENTS:
	case MSG_OK:
	case MSG_ERROR:
	case MSG_FILE_LIST_RSP:
	case MSG_GREETING_RSP:
		conn_send_error(conn, "server received invalid message");
		return;
	}

	message_reset(conn->inmsg);
}

static void
conn_write_cb(struct bufferevent *bev, void *_conn)
{
	struct conn *conn = _conn;
	// XXX if conn is in flush-and-close mode, close it here
}

static void
conn_event_cb(struct bufferevent *bev, short what, void *_conn)
{
	struct conn *conn = _conn;
}

static void
listener_plain_cb(struct evconnlistener *listener, evutil_socket_t s,
		  struct sockaddr *addr, int socklen, void *arg)
{
	struct event_base *base;
	struct bufferevent *bev;

	base = evconnlistener_get_base(listener);
	bev = bufferevent_socket_new(base, s, BEV_OPT_CLOSE_ON_FREE);
	conn_create(base, bev);
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
			BEV_OPT_CLOSE_ON_FREE);
	conn_create(base, bev);
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

	chdir(server_base_path);

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
