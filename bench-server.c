#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "log.h"
#include "bench-messages.h"
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
	struct bufferevent *bev;
	struct message *inmsg;
	struct message *outmsg;
	struct evbuffer *inbuf;
	struct evbuffer *outbuf;
	struct property_list properties;
	long notifications;
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
		newconns = realloc(active_conns, amt * sizeof(struct conn *));
		if (!newconns)
			return -1;
		memset(newconns + active_conns_allocated, 0,
		       (amt - active_conns_allocated) * sizeof(struct conn *));
		active_conns_allocated = amt;
		active_conns = newconns;
	}

	assert(active_conns[conn->id] == NULL);
	active_conns[conn->id] = conn;

	return 0;
}

static inline int
conn_has_handshaked(struct conn *conn)
{
	return conn->id != 0;
}

static void
active_conns_del(struct conn *conn)
{
	if (!conn_has_handshaked(conn))
		return;
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

static void
conn_destroy(struct conn *conn)
{
	active_conns_del(conn);
	if (conn->inmsg)
		message_destroy(conn->inmsg);
	if (conn->outmsg)
		message_destroy(conn->outmsg);
	if (conn->bev)
		bufferevent_free(conn->bev);
	free(conn);
}

static struct conn *
conn_new(struct event_base *base, struct bufferevent *cbev)
{
	struct conn *conn;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	conn->bev = cbev;
	conn->inmsg = message_new();
	if (!conn->inmsg)
		goto out;
	conn->outmsg = message_new();
	if (!conn->outmsg)
		goto out;
	conn->inbuf = bufferevent_get_input(cbev);
	conn->outbuf = bufferevent_get_output(cbev);
	TAILQ_INIT(&conn->properties);

	return conn;

out:
	conn_destroy(conn);

	return NULL;
}

static void
conn_create(struct event_base *base, struct bufferevent *bev)
{
	struct conn *conn;

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
	log_warn("server: error: %s", what);
	message_encode_error(conn->outmsg, what, conn->outbuf);
}

static inline void
conn_send_peer_notice(struct conn *conn, struct conn *peer)
{
	if (!conn->notifications)
		return;
	message_encode_peer_notice(conn->outmsg, peer->id,
			&peer->properties, conn->outbuf);
	conn->notifications--;
}

static int
conn_finish_setup(struct conn *conn)
{
	ev_uint32_t i;

	if (message_parse_payload(conn->inmsg) != MSGST_OK) {
		log_warn("server: handshake with client failed");
		return -1;
	}

	property_list_move(&conn->properties,
			   message_payload_get_properties(conn->inmsg));

	conn->notifications = 0;
	property_list_find_long(&conn->properties, "max_peer_notifications",
				&conn->notifications);
	if (conn->notifications) {
		log_debug("server: client %u can recv %ld peer notifications",
			  (unsigned)conn->id, conn->notifications);
	}

	active_conns_add(conn);

	/* Let everyone know about this new peer */
	message_encode_greeting_rsp(conn->outmsg, conn->id, conn->outbuf);

	for (i = 0; i < id_count; ++i) {
		struct conn *ac = active_conns[i];
		if (!ac)
			continue;
		conn_send_peer_notice(ac, conn);
		conn_send_peer_notice(conn, ac);
	}

	return 0;
}

static int
conn_relay_chat(struct conn *conn)
{
	struct conn *dest_conn;

	dest_conn = active_conns_get(message_get_destination(conn->inmsg));
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
	struct file_entry *fe;
	const char *fname;
	int found;
	FILE *fp;
	char buf[1024];
	size_t amt;

	if (message_parse_payload(conn->inmsg) != MSGST_OK) {
		log_warn("server: invalid file request");
		return -1;
	}

	dest_conn = active_conns_get(message_get_destination(conn->inmsg));
	if (!dest_conn) {
		conn_send_error(conn, "destination unknown");
		return 0;
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
		return 0;
	}

	fp = fopen(fname, "rb");
	if (!fp) {
		log_error("server: unable to open %s!", fname);
		conn_send_error(conn, "unable to open file");
		return 0;
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

static int
conn_read_message(struct conn *conn)
{
	int rv;

	rv = message_read(conn->inmsg, conn->inbuf);
	if (rv <= MSGST_CONT) {
		if (rv == MSGST_FAIL) {
			log_warn("server: received malformed message");
			conn_destroy(conn);
		}
		return -1;
	}

	if (!conn_has_handshaked(conn) &&
	    message_get_type(conn->inmsg) != MSG_GREETING_REQ) {
		log_warn("server: client messaging without greeting first");
		conn_destroy(conn);
		return -1;
	}

	rv = 0;

	switch (message_get_type(conn->inmsg)) {
	case MSG_GREETING_REQ:
		rv = conn_finish_setup(conn);
		break;
	case MSG_SEND_CHAT:
	case MSG_ECHO_REQ:
	case MSG_ECHO_RSP:
		/* Forward a chat message to another client. */
		rv = conn_relay_chat(conn);
		break;
	case MSG_FILE_LIST_REQ:
		message_encode_file_list_rsp(conn->outmsg, &server_files,
					     conn->outbuf);
		break;
	case MSG_SEND_FILE:
		rv = conn_send_file(conn);
		break;

	/* These messages shouldn't be sent to the server. */
	case MSG_PEER_NOTICE:
	case MSG_FILE_CONTENTS:
	case MSG_OK:
	case MSG_ERROR:
	case MSG_FILE_LIST_RSP:
	case MSG_GREETING_RSP:
		conn_send_error(conn, "server received invalid message");
		break;
	}

	message_reset(conn->inmsg);
	message_reset(conn->outmsg);

	if (rv < 0)
		conn_destroy(conn);

	return rv;
}

static void
conn_read_cb(struct bufferevent *bev, void *_conn)
{
	struct conn *conn = _conn;

	while (evbuffer_get_length(conn->inbuf) &&
	       !conn_read_message(conn))
		;
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

	/* SSL */
	if (what & BEV_EVENT_CONNECTED)
		return;

	if (what & BEV_EVENT_ERROR) {
		log_warn("server: socket error: %s",
			 evutil_socket_error_to_string(
				evutil_socket_geterror(-1)));
	} else {
		log_debug("server: connection %u closed", (unsigned)conn->id);
	}

	conn_destroy(conn);
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

	signal(SIGPIPE, SIG_IGN);

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
	log_set_file(NULL);

	base = event_base_new();

	listener_plain = evconnlistener_new_bind(base, listener_plain_cb, NULL,
			LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
			(struct sockaddr *)&listener_plain_addr, len);

	listener_ssl = evconnlistener_new_bind(base, listener_ssl_cb, &info,
			LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
			(struct sockaddr *)&listener_ssl_addr, len);

	evconnlistener_enable(listener_plain);
	evconnlistener_enable(listener_ssl);

	event_base_dispatch(base);

	return 0;
}
