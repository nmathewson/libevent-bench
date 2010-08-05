
/*
	1. multiple clients / process
	2. probability of using SSL

	3. client process:
		a. connect to server
		b. handshake
		c. wait for a threshold of peers
		d. select a random subset of those peers to associate with
		e. run benchmarking operations

	notes:
		- there is one list of peers per process
*/

struct peer {
	ev_uint32_t id;
	struct property_list properties;
};

struct client {
	ev_uint32_t id;
	int use_ssl;
	struct peer **friends;
	struct property_list properties;
	struct bufferevent *bev;
	struct evbuffer *inbuf;
	struct evbuffer *outbuf;
};

static float use_ssl_prob = 0.0;
static size_t max_peers = 256;
static size_t num_clients = 256;
static struct peer *peers = NULL;
static struct sockaddr_storage server_plain_addr;
static struct sockaddr_storage server_ssl_addr;

int
main(int argc, char **argv)
{
	peers = calloc(max_peers, sizeof(struct peer));
	if (!peers)
		log_fatal("client: can't allocate peer list!");
		
	return 0;
}
