#ifndef _BENCH_MESSAGES_H_
#define _BENCH_MESSAGES_H_

#include <sys/queue.h>
#include <event2/util.h>
#include <event2/buffer.h>

// messages are variable length of the basic format:
// header:
//   4 bytes -- message type
//   4 bytes -- message length
//   4 bytes -- origin id
//   4 bytes -- destination id
// message payload:
//   bytes equal to the message length
//
// all header fields are in network byte order
//

enum message_status {
	MSGST_FAIL = -1,
	MSGST_CONT = 0,
	MSGST_OK = 1
};

enum message_type {
	MSG_UNKNOWN,

	MSG_TYPE_MIN,

	MSG_GREETING_REQ,
	MSG_GREETING_RSP,

	MSG_PEER_NOTICE,

	MSG_FILE_LIST_REQ,
	MSG_FILE_LIST_RSP,

	MSG_SEND_CHAT,

	MSG_ECHO_REQ,
	MSG_ECHO_RSP,

	MSG_SEND_FILE,
	MSG_FILE_CONTENTS,
	
	MSG_OK,
	MSG_ERROR,

	MSG_TYPE_MAX,
};

// message types:
// * (client -> server) client greeting
//    payload contains a list of client properties in the form:
//      property_name <SP> property value <NL>
// * (server -> client) greeting response
//    response contains the new client's ID in the destination_id field
//    payload is empty
// * (server <-> client) error
//    payload contains an ascii description of the error
// * (server <-> client) OK
//    empty payload
// * (server -> client) peer notice
//    origin_id is the ID of the new peer.
//    payload contains its prop list
//    NOTE: peer notices are sent out to all other peers when a new peer connects
// * (client -> server) list files
//    payload is empty
// * (server -> client) file list
//    payload contains a list of file names, one per line
// * (client <-> server) send chat
//    payload contains chat contents
// * (client <-> server) echo request
//    payload contains data to be echoed by the peer
// * (client <-> server) echo response
//    payload contains the original data in the echo req
// * (client -> server) send file
//    payload contains the name of the file to send
// * (server -> client) file contents
//    payload contains the file contents

// 1. create message
// 2. parse message
// 3. property table

// initial communication/handshaking:
// 1. client connects to bench server
// 2. client sends a greeting to server with its properties
// 3. server sends the client its ID

// client properties
// 1. do i have a listener for direct connections? is it ssl or plain?
//    spec: listener ssl|plain ip:port
// 2. do reply to echo requests?
//    spec: echo_enabled yes|no

struct property {
	char *name;
	char *value;
	TAILQ_ENTRY(property) next;
};
TAILQ_HEAD(property_list, property);

struct file_entry {
	char *name;
	// XXX need more file meta data?
	TAILQ_ENTRY(file_entry) next;
};
TAILQ_HEAD(file_list, file_entry);

struct message;

int property_list_add(struct property_list *props, const char *k,
		      const char *v);
int property_list_add_long(struct property_list *props, const char *k, long v);
void property_list_clear(struct property_list *props);
void property_list_move(struct property_list *to, struct property_list *from);
const char *property_list_find(struct property_list *props, const char *name);
int property_list_find_long(struct property_list *props,
		        const char *name, long *lv);

int file_list_add(struct file_list *files, const char *name);
void file_list_clear(struct file_list *files);
void file_list_move(struct file_list *to, struct file_list *from);

struct message *message_new(void);
void message_reset(struct message *msg);
void message_destroy(struct message *msg);
int message_parse_header(struct message *msg, struct evbuffer *buf);
int message_read_payload(struct message *msg, struct evbuffer *buf);
int message_read(struct message *msg, struct evbuffer *buf);
int message_parse_payload(struct message *msg);
size_t message_encode(struct message *msg, struct evbuffer *outbuf);
size_t message_encode_ref(struct message *msg, const void *data, size_t len,
		   struct evbuffer *outbuf);
size_t message_encode_greeting_req(struct message *msg,
				struct property_list *props,
				struct evbuffer *outbuf);
size_t message_encode_greeting_rsp(struct message *msg, ev_uint32_t client_id,
			    struct evbuffer *outbuf);
size_t message_encode_peer_notice(struct message *msg, ev_uint32_t peer_id,
			   const struct property_list *props,
			   struct evbuffer *outbuf);
size_t message_encode_file_list_req(struct message *msg,
			struct evbuffer *outbuf);
size_t message_encode_file_list_rsp(struct message *msg,
		struct file_list *files, struct evbuffer *outbuf);
size_t message_encode_send_chat(struct message *msg, ev_uint32_t origin,
			 ev_uint32_t dest, const void *chat, size_t len,
			 struct evbuffer *outbuf);
size_t message_encode_echo_req(struct message *msg, ev_uint32_t origin,
			ev_uint32_t dest, const void *echo, size_t len,
			struct evbuffer *outbuf);
size_t message_encode_echo_rsp(struct message *msg, struct message *echo,
			struct evbuffer *outbuf);
size_t message_encode_send_file(struct message *msg, ev_uint32_t origin,
			 ev_uint32_t dest, const char *fn,
			 struct evbuffer *outbuf);
size_t message_encode_file_contents(struct message *msg, ev_uint32_t origin,
			     ev_uint32_t dest, struct evbuffer *outbuf);
size_t message_encode_ok(struct message *msg, struct evbuffer *outbuf);
size_t message_encode_error(struct message *msg, const char *errmsg,
		     struct evbuffer *outbuf);

struct evbuffer *message_get_payload(struct message *msg);
size_t message_get_total_length(const struct message *msg);
ev_uint32_t message_get_type(const struct message *msg);
ev_uint32_t message_get_length(const struct message *msg);
ev_uint32_t message_get_origin(const struct message *msg);
ev_uint32_t message_get_destination(const struct message *msg);
const char *message_payload_get_error_msg(const struct message *msg);
const char *message_payload_get_file_name(const struct message *msg);
struct property_list *message_payload_get_properties(struct message *msg);
struct file_list *message_payload_get_files(struct message *msg);

#endif
