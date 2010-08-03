#include "bench-mesages.h"

static char *
pop_string(struct evbuffer *buf, ev_ssize_t n)
{
	char *str;
	size_t len;

	len = evbuffer_get_length(buf);
	if (n >= 0 && n < len)
		len = n;

	str = malloc(len + 1);
	if (!str)
		return NULL;
	str[len] = '\0';
	evbuffer_remove(buf, str, len);

	return str;
}

static ev_uint32_t
pop_uint32(struct evbuffer *buf)
{
	ev_uint32_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	
	return ntohl(n);
}

static void
push_uint32(struct evbuffer *buf, ev_uint32_t n)
{
	n = htonl(n);
	evbuffer_add(buf, &n, sizeof(n));
}

static int
property_list_add(property_list *props, const char *k, const char *v)
{
	struct property *prop;

	prop = calloc(1, sizeof(*prop));
	if (!prop)
		return MSGST_FAIL;

	prop->name = strdup(k);
	prop->value = strdup(v);
	if (!prop->name || !prop->value) {
		free(prop);
		return MSGST_FAIL;
	}

	TAILQ_INSERT(props, prop, next);

	return MSGST_OK;
}

static int
property_list_parse(property_list *props, struct evbuffer *buf)
{
	char *ln = NULL;
	char *p;

	while ((ln = evbuffer_readln(buf, NULL, EVBUFFER_EOL_ANY))) {
		p = strchr(ln, ' ');
		if (!sp)
			goto out;
		*p = '\0';
		p++;
		if (property_list_add(props, ln, p) != MSGST_OK)
			goto out;
		free(ln);
	}

	return MSGST_OK;

out:
	if (ln)
		free(ln);
	return MSGST_FAIL;
}

static void
property_list_encode(struct property_list *props, struct evbuffer *buf)
{
	struct property *prop;
	
	TAILQ_FOREACH(prop, props, next)
		evbuffer_add_printf(buf, "%s %s\n", prop->name, prop->value);
}

static void
property_list_clear(struct property_list *props)
{
	struct property *prop;

	while ((prop = TAILQ_FIRST(props))) {
		TAILQ_REMOVE(props, prop, next);
		free(prop->name);
		free(prop->value);
		free(prop);
	}
}

static void
property_list_move(struct property_list *to, struct property_list *from)
{
	struct property *prop;

	while ((prop = TAILQ_FIRST(from))) {
		TAILQ_REMOVE(from, prop, next);
		TAILQ_INSERT_TAIL(to, prop, next);
	}
}

static int
file_list_parse(struct file_list *files, struct evbuffer *buf)
{
	char *ln = NULL;
	struct file_entry *fe;

	while ((ln = evbuffer_readln(buf, NULL, EVBUFFER_EOL_ANY))) {
		fe = calloc(1, sizeof(*fe));
		if (!fe)
			goto out;
		fe->name = strdup(ln);
		if (!fe->name)
			goto out;
		free(ln);

		TAILQ_INSERT_TAIL(files, fe, next);
	}

	return MSGST_OK;

out:
	if (ln)
		free(ln);
	return MSGST_FAIL;
}

static void
file_list_encode(struct file_list *files, struct evbuffer *buf)
{
	struct file_entry *fe;

	TAILQ_FOREACH(fe, files, next)
		evbuffer_add_printf(buf, "%s\n", fe->name);
}

static void
file_list_clear(struct file_list *files)
{
	struct file_entry *fe;

	while ((fe = TAILQ_FIRST(files))) {
		free(fe->name);
		free(fe);
	}
}

struct message *
message_new(void)
{
	struct message *msg;

	msg = calloc(1, sizeof(*msg));
	if (!msg)
		return NULL;

	msg->payload = evbuffer_new();
	if (!msg->payload) {
		free(msg);
		return NULL;
	}

	return msg;
}

void
message_reset(struct message *msg)
{
	/* clear parsed payload */
	switch (msg->type) {
	case MSG_PEER_NOTICE:
	case MSG_GREETING_REQ:
		property_list_clear(&msg->pl.properties);
		break;
	case MSG_FILE_LIST_RSP:
		file_list_clear(&msg->pl.files);
		break;
	case MSG_ERROR:
		if (msg->pl.error_msg)
			free(msg->pl.error_msg);
		msg->pl.error_msg = NULL;
		break;
	case MSG_SEND_FILE:
		if (msg->pl.file_name)
			free(msg->pl.file_name);
		msg->pl.file_name = NULL;
		break;
	}

	msg->type = MSG_UNKNOWN;
	msg->destination_id = 0;
	msg->length = 0;
	msg->length_remaining = 0;
	evbuffer_drain(msg->payload, evbuffer_get_length(msg->payload));
}

void
message_destroy(struct message *msg)
{
	message_reset(msg);
	evbuffer_free(msg->payload);
	free(msg);
}

int
message_parse_header(struct message *msg, struct evbuffer *buf)
{
	assert(msg->type == MSG_UNKNOWN);
	if (evbuffer_get_length(buf) < 16)
		return MSGST_CONT;

	msg->type = pop_uint32(buf);
	msg->length = pop_uint32(buf);
	msg->origin_id = pop_uint32(buf);
	msg->destination_id = pop_uint32(buf);
	msg->length_remaining = msg->length;

	if (msg->type <= MSG_TYPE_MIN ||
	    msg->type >= MSG_TYPE_MAX)
		return MSGST_FAIL;

	return MSGST_OK;
}

int
message_read_payload(struct message *msg, struct evbuffer *buf)
{
	amt = evbuffer_remove_buffer(buf, msg->payload, msg->length_remaining);
	assert(amt <= msg->length_remaining);
	msg->length_remaining -= amt;
	if (msg->length_remaining)
		return MSGST_CONT;

	return MSGST_OK;
}

int
message_parse_payload(struct message *msg)
{
	int amt;

	assert(msg->type != MSG_UNKNOWN);

	switch (msg->type) {
	case MSG_GREETING_REQ:
		TAILQ_INIT(&msg->pl.properties);
		return property_list_parse(&msg->pl.properties, msg->payload);
	case MSG_GREETING_RSP:
		break;

	case MSG_PEER_NOTICE:
		TAILQ_INIT(&msg->pl.properties);
		return property_list_parse(&msg->pl.properties, msg->payload);
		
	case MSG_FILE_LIST_REQ:
		break;
	case MSG_FILE_LIST_RSP:
		TAILQ_INIT(&msg->pl.files);
		return file_list_parse(&msg->pl.files, msg->payload);

	case MSG_SEND_CHAT:
		break;

	case MSG_ECHO_REQ:
		break;
	case MSG_ECHO_RSP:
		break;

	case MSG_SEND_FILE:
		msg->pl.file_name = pop_string(msg->payload, -1);
		if (!msg->pl.file_name)
			return MSGST_FAIL;
		break;
	case MSG_FILE_CONTENTS:
		break;
	
	case MSG_OK:
		break;

	case MSG_ERROR:
		msg->pl.error_msg = pop_string(msg->payload, -1);
		if (!msg->pl.error_msg)
			return MSGST_FAIL;
		break;

	default:
		abort();
	}

	return MSGST_OK;
}

void
message_encode(struct message *msg, struct evbuffer *outbuf)
{
	msg->length = evbuffer_get_length(msg->payload);
	evbuffer_expand(outbuf, 16);
	push_uint32(outbuf, msg->type);
	push_uint32(outbuf, msg->length);
	push_uint32(outbuf, msg->origin_id);
	push_uint32(outbuf, msg->destination_id);
	evbuffer_add_buffer(outbuf, msg->payload);
}

void
message_encode_greeting_req(struct message *msg, struct property_list *props, struct evbuffer *outbuf)
{
	msg->type = MSG_GREETING_REQ;
	msg->origin_id = 0;
	msg->destination_id = 0;
	property_list_encode(props, msg->payload);
	message_encode(msg, outbuf);
}

void
message_encode_greeting_rsp(struct message *msg, ev_uint32_t client_id, struct evbuffer *outbuf)
{
	msg->type = MSG_GREETING_RSP;
	msg->origin_id = 0;
	msg->destination_id = client_id;
	message_encode(msg, outbuf);
}

void
message_encode_peer_notice(struct message *msg, ev_uint32_t peer_id,
			   const struct property_list *props,
			   struct evbuffer *outbuf)
{
	msg->type = MSG_PEER_NOTICE;
	msg->origin_id = peer_id;
	msg->destination_id = 0;
	property_list_encode(props, msg->payload);
	message_encode(msg, outbuf);
}

void
message_encode_file_list_req(struct message *msg, struct evbuffer *outbuf)
{
	msg->type = MSG_FILE_LIST_REQ;
	msg->origin_id = 0;
	msg->destination_id = 0;
	message_encode(msg, outbuf);
}

void
message_encode_file_list_rsp(struct message *msg, struct file_list *files, struct evbuffer *outbuf)
{
	msg->type = MSG_FILE_LIST_RSP;
	msg->origin_id = 0;
	msg->destination_id = 0;
	file_list_encode(files, msg->payload);
	message_encode(msg, outbuf);
}

void
message_encode_send_chat(struct message *msg, ev_uint32_t origin, ev_uint32_t dest,
			 const void *chat, size_t len, struct evbuffer *outbuf)
{
	msg->type = MSG_SEND_CHAT;
	msg->origin_id = origin;
	msg->destination_id = dest;
	evbuffer_add(msg->payload, chat, len);
	message_encode(msg, outbuf);
}

void
message_encode_echo_req(struct message *msg, ev_uint32_t origin, ev_uint32_t dest,
			const void *echo, size_t len, struct evbuffer *outbuf)
{
	msg->type = MSG_ECHO_REQ;
	msg->origin_id = origin;
	msg->destination_id = dest;
	evbuffer_add(msg->payload, chat, len);
	message_encode(msg, outbuf);
}

void
message_encode_echo_rsp(struct message *msg, struct message *echo, struct evbuffer *outbuf)
{
	msg->type = MSG_ECHO_RSP;
	msg->origin_id = echo->destination_id;
	msg->destination_id = echo->origin_id;
	evbuffer_add_buffer(msg->payload, echo->payload);
	message_encode(msg, outbuf);
}

void
message_encode_send_file(struct message *msg, ev_uint32_t origin,
			 ev_uint32_t dest, const char *fn,
			 struct evbuffer *outbuf)
{
	msg->type = MSG_SEND_FILE;
	msg->origin_id = origin;
	msg->destination_id = dest;
	evbuffer_add(msg->payload, fn, strlen(fn));
	message_encode(msg, outbuf);
}

void
message_encode_file_contents(struct message *msg, ev_uint32_t origin,
			     ev_uint32_t dest, struct evbuffer *outbuf)
{
	msg->type = MSG_FILE_CONTENTS;
	msg->origin_id = origin;
	msg->destination_id = dest;
	message_encode(msg, outbuf);
}

void
message_encode_ok(struct message *msg, struct evbuffer *outbuf)
{
	msg->type = MSG_OK;
	msg->origin_id = 0;
	msg->destination_id = 0;
	message_encode(msg, outbuf);
}

void
message_encode_error(struct message *msg, const char *errmsg, struct evbuffer *outbuf)
{
	msg->type = MSG_ERROR;
	msg->origin_id = 0;
	msg->destination_id = 0;
	evbuffer_add(msg->payload, errmsg, strlen(errmsg));
	message_encode(msg, outbuf);
}
