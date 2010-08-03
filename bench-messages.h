#ifndef _BENCH_MESSAGES_H_
#define _BENCH_MESSAGES_H_

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
	MSG_FILE_CONTENTS
	
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

struct message {
	ev_uint32_t type;
	ev_uint32_t length;
	ev_uint32_t origin_id;
	ev_uint32_t destination_id;
	ev_uint32_t length_remaining;
	struct evbuffer *payload;
	
	union {
		struct property_list properties;
		struct file_list files;
		char *error_msg;
		char *file_name;
	} pl;
};

inline struct evbuffer *
message_get_payload(struct message *msg)
{
	return msg->payload;
}

inline ev_uint32_t
message_get_type(const struct message *msg)
{
	return msg->type;
}

inline ev_uint32_t
message_get_length(const struct message *msg)
{
	return msg->length;
}

inline ev_uint32_t
message_get_origin(const struct message *msg)
{
	return msg->origin_id;
}

inline ev_uint32_t
message_get_destination(const struct message *msg)
{
	return msg->destination_id;
}

inline const char *
message_payload_get_error_msg(const struct message *msg)
{
	return msg->pl.error_msg;
}

inline const char *
message_payload_get_file_name(const struct message *msg)
{
	return msg->pl.file_name;
}

inline property_list *
message_payload_get_properties(const struct message *msg)
{
	return &msg->pl.properties;
}

inline file_list *
message_payload_get_files(const struct message *msg)
{
	return &msg->pl.files;
}
#endif
