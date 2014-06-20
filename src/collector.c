#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <marquise.h>

/* Max time to wait between batching up frames to send to voltaire */
#define BATCH_PERIOD	0.1
#define DEFAULT_LIBMARQUISE_ORIGIN	"BENHUR"


#define __STRINGIZE(x) #x
#define _STRINGIZE(x) __STRINGIZE(x)
#define __FILEPOS__ __FILE__ ":" _STRINGIZE(__LINE__)

#ifdef DEBUG
#define DEBUG_PRINTF(formatstr, ...) fprintf(stderr, __FILEPOS__ ", %s() - " formatstr, __func__,  __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

#if _POSIX_C_SOURCE >= 200809L
#define SCANF_ALLOCATE_STRING_FLAG "m"
#elif defined(__GLIBC__) && (__GLIBC__ >= 2)
#define SCANF_ALLOCATE_STRING_FLAG "s"
#else
#error "Please let us have POSIX.1-2008, glibc, or a puppy"
#endif
#define SCANF_ALLOCATE_STRING "%" SCANF_ALLOCATE_STRING_FLAG "s"

#define SOURCE_KEY_COLLECTION_POINT "collection_point"
#define SOURCE_KEY_IP "ip"
#define SOURCE_KEY_BYTES "bytes"


/**
 * This is only going to fly if we are getting data in on the fly
 * and we have no other timestamp source
 */
uint64_t timestamp_now() {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts)) { perror("clock_gettime"); exit(2); }
	return (ts.tv_sec*1000000000) + ts.tv_nsec;
}

typedef struct {
	in_addr_t network;
	in_addr_t netmask;
	void * next;
} networkaddr_ll_t;

/* returns 1 if it is in the whitelist, 0 if it is not, or -1
 * if it is not a well-formed address
 */
static inline int is_address_in_whitelist(char *ipaddr , networkaddr_ll_t *whitelist) {
	struct in_addr addr;
	if (inet_aton(ipaddr, &addr) == 0) return -1;
	/* everything is whitelisted by default if there is no whitelist */
	if (whitelist == NULL) return 1;
	for (; whitelist != NULL; whitelist = whitelist->next) {
		if ((addr.s_addr & whitelist->netmask) == whitelist->network)
			return 1;
	}
	return 0;
}
static void free_whitelist(networkaddr_ll_t *whitelist) {
	while (whitelist != NULL) {
		networkaddr_ll_t *next = whitelist->next;
		free(whitelist);
		whitelist = next;
	}
}

networkaddr_ll_t * read_ip_whitelist(char *pathname) {
	char *network = NULL;
	char *netmask = NULL;
	networkaddr_ll_t *head = NULL;

	FILE *infile = fopen(pathname, "r");
	if (infile == NULL)
		return perror(pathname), NULL;

	while (fscanf(infile,
			" %" SCANF_ALLOCATE_STRING_FLAG "[0123456789.]"
			"/" SCANF_ALLOCATE_STRING, &network,&netmask) == 2) {
		networkaddr_ll_t * entry = malloc(sizeof(networkaddr_ll_t));
		if (entry == NULL)
			return perror("malloc"),NULL;
		struct in_addr a;
		if (inet_aton(network, &a) == 0) {
			fprintf(stderr,"Invalid whitelisted network '%s'. Skipping\n",network);
			free(entry); free(network); free(netmask); continue;
		}
		entry->network = a.s_addr;
		struct in_addr b;
		if (inet_aton(netmask, &b) == 0) {
			fprintf(stderr,"Invalid whitelisted network '%s'. Skipping\n",network);
			free(entry); free(network); free(netmask); continue;
		}
		entry->netmask = b.s_addr;
		if (ntohl( entry->netmask ) <= 24) {
			/* Prefix length not netmask */
			entry->netmask = ntohl(entry->netmask);
			entry->netmask = ~((1<<(32- entry->netmask )) - 1);
			entry->netmask = htonl(entry->netmask);
		}
		a.s_addr = entry->network;
		b.s_addr = entry->netmask;
		fprintf(stderr,"Added to whitelist: %s/",
				inet_ntoa(a));
		fprintf(stderr,"%s\n",inet_ntoa(b));

		entry->next = head;
		head = entry;
		free(network); free(netmask);
	}
	fclose(infile);
	return head;
}

/*K
 * parse a pmacct record line.
 *
 * *source_ip and *dest_ip are allocated by libc
 * caller must free() *source_ip and *dest_ip iff the call was successful
 * (as per sscanf)
 *
 * pre: instring is zero terminated
 *
 * returns >= 1 on success
 */
int parse_pmacct_record(char *cs, char **source_ip, char **dest_ip, uint64_t *bytes) {
	/* Format (with more whitespace in actual input):
	 *
	 * ID CLASS SRC_MAC DST_MAC VLAN SRC_AS DST_AS SRC_IP DST_IP SRC_PORT DST_PORT TCP_FLAGS PROTOCOL TOS PACKETS FLOWS BYTES
	 * 0 unknown 00:00:00:00:00:00 00:00:00:00:00:00 0 0 0 202.4.228.250 180.76.5.15 0 0 0 ip 0 24 0 34954
	 *
	 * We ignore everything other than source IP, destination IP, and bytes
	 */
	*source_ip = NULL;
	*dest_ip = NULL;
	return sscanf(cs,
		"%*s%*s%*s%*s%*s%*s%*s"
		SCANF_ALLOCATE_STRING
		SCANF_ALLOCATE_STRING
		"%*s%*s%*s%*s%*s%*s%*s"
		"%lu",
		source_ip, dest_ip, bytes
		) == 3;
}

char *build_source(char *collection_point, char *ip, const char *bytes) {
	/* order matters */
	size_t source_len = sizeof(SOURCE_KEY_BYTES) +
	                    sizeof(SOURCE_KEY_COLLECTION_POINT) +
	                    sizeof(SOURCE_KEY_IP); 
	size_t bytes_len = strlen(bytes);
	size_t collection_point_len = strlen(collection_point);
	size_t ip_len = strlen(ip);
	/* the +2 is for the ',' and ':' */
	source_len += bytes_len + 2;
	source_len += collection_point_len + 2;
	source_len += ip_len + 2;
	source_len += 1; // NULL
	char *source = malloc(source_len);
	strcpy(source, SOURCE_KEY_BYTES);
	int idx = sizeof(SOURCE_KEY_BYTES);
	source[idx++] = ':';
	strcpy(source + idx, bytes);
	idx += bytes_len;
	source[idx++] = ',';
	strcpy(source + idx, SOURCE_KEY_COLLECTION_POINT);
	idx += sizeof(SOURCE_KEY_COLLECTION_POINT);
	source[idx++] = ':';
	strcpy(source + idx, collection_point);
	idx += collection_point_len;
	source[idx++] = ',';
	strcpy(source + idx, SOURCE_KEY_IP);
	idx += sizeof(SOURCE_KEY_IP);
	source[idx++] = ':';
	strcpy(source + idx, ip);
	idx += ip_len;
	source[idx++] = ',';
	source[idx++] = '\0';
	return source;
}

static inline int emit_bytes(marquise_ctx *ctx, char *source, 
                             uint64_t timestamp, uint64_t bytes) {
	uint64_t address = marquise_hash_identifier(source, strlen(source));
	int ret;
	ret = marquise_send_simple(ctx, address, timestamp, bytes);
	if (ret != 0) {
		DEBUG_PRINTF("successfully queued packet\n");
	} else {
		DEBUG_PRINTF("failed to send packet\n");
	}	
	return ret;
}

static inline int emit_tx_bytes(marquise_ctx *ctx,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	char *source = build_source(collection_point, ip, "tx");
	return emit_bytes(ctx, source, timestamp, bytes);
}

static inline int emit_rx_bytes(marquise_ctx *ctx,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	char *source = build_source(collection_point, ip, "rx");
	return emit_bytes(ctx, source, timestamp, bytes);
}

int main(int argc, char **argv) {
	FILE *infile;
	char buf[BUFSIZ];
	char *source_ip;
	char *dest_ip;
	uint64_t bytes;
	uint64_t timestamp;
	uint64_t last_timestamp;
	char *collection_point;
	marquise_ctx *ctx;
	networkaddr_ll_t * ip_whitelist = NULL;

	if (argc < 3) {
		fprintf(stderr,"%s <collection point> <vaultaire endpoint> [<filename of ip networks to track>]\n\n"
				"e.g.\n\t%s syd1 tcp://vaultaire-broker:5560\n",
				argv[0], argv[0]);
		return 1;
	}
	collection_point = argv[1];
	if (argc > 3) {
		ip_whitelist = read_ip_whitelist(argv[3]);
		if (ip_whitelist == NULL) {
			if (errno == 0)
				fprintf(stderr, "invalid or empty ip whitelist file\n");
			return 1;
		}
	}

	/* libmarquise currently requires the origin to be set by environment
	 * variable. Set iff it is currently not in the environment
	 */
	setenv("LIBMARQUISE_ORIGIN",  DEFAULT_LIBMARQUISE_ORIGIN, 0);

	/* get a new consumer we can send frames to
	 */
	ctx = marquise_init("pmacct");
	if (ctx == NULL) {
		perror("marquise_init"); return 1;
	}

	last_timestamp = timestamp_now();

	infile = stdin; /* slack */

	int retcode = 0;
	while ( fgets(buf, BUFSIZ, infile) == buf ) {
		/* Ignore any line that doesn't start with a numeric
		 * ID. This gets around pmacct's stupid logging of
		 * totally unimportant warnings to stdout
		 */
		if (buf[0] < '0' || buf[0] > '9')  continue;

		/* Keep timestamp the same for all items based on the same entry
		 * in case we need to cross correlate them later
		 */
		timestamp = timestamp_now();

		/* the 2tuple of source,timestamp must be unique for each frame
		 *
		 * Check to make sure that if we have a really course clock that we
		 * are still maintaining that invariant
		 */
		if (timestamp < last_timestamp)
			timestamp = last_timestamp + 1;   /* Great. NTP skew. My lucky day */
		if (timestamp == last_timestamp)
			timestamp++;
		last_timestamp = timestamp;

		buf[BUFSIZ-1] = 0;
		if (! parse_pmacct_record(buf, &source_ip, &dest_ip, &bytes))
			continue; /* Doesn't look like it's actually a record */

		/* emit a frame for both parties (if the ip is whitelisted) */
		if (is_address_in_whitelist(source_ip, ip_whitelist) == 1) {
			if ( emit_tx_bytes(ctx, collection_point, source_ip, timestamp, bytes) <= 0 ) {
				perror(__FILEPOS__ ": marquise_send_int"); retcode=1; break;
			}
		}
		if (is_address_in_whitelist(dest_ip, ip_whitelist) == 1) {
			if ( emit_rx_bytes(ctx, collection_point, dest_ip, timestamp, bytes) <= 0 ) {
				perror(__FILEPOS__ ": marquise_send_int"); retcode=1; break;
			}
		}

		free(source_ip);
		free(dest_ip);
	}

	marquise_shutdown(ctx);
	free_whitelist(ip_whitelist);

	return retcode;
}
