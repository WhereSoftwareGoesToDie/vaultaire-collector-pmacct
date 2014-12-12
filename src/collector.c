#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

/* Max time to wait between batching up frames to send to Vaultaire */
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
#define SCANF_ALLOCATE_STRING_FLAG "a"
#else
#error "Please let us have POSIX.1-2008, glibc, or a puppy"
#endif
#define SCANF_ALLOCATE_STRING "%" SCANF_ALLOCATE_STRING_FLAG "s"

#define SOURCE_KEY_COLLECTION_POINT "collection_point"
#define SOURCE_KEY_IP "ip"
#define SOURCE_KEY_BYTES "bytes"

/*
 * This is only going to fly if we are getting data in on the fly
 * and we have no other timestamp source.
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

/* Returns 1 if it is in the whitelist, 0 if it is not, or -1
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

/*
 * parse a pmacct record line. (version 0.11.6-cvs on fishhook)
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
	 * ID CLASS   SRC_MAC           DST_MAC           VLAN SRC_AS DST_AS SRC_IP        DST_IP      SRC_PORT DST_PORT TCP_FLAGS PROTOCOL TOS PACKETS FLOWS BYTES
	 * 0  unknown 00:00:00:00:00:00 00:00:00:00:00:00 0    0      0      202.4.228.250 180.76.5.15 0        0        0         ip       0   24      0     34954
	 *
	 * We ignore everything other than source IP, destination IP, and bytes.
	 */
	*source_ip = NULL;
	*dest_ip = NULL;
	return sscanf(cs,
		"%*s%*s%*s%*s%*s%*s%*s" /* Seven! Seven fields! HA HA HAAA! (ID -> DST_AS) */
		SCANF_ALLOCATE_STRING   /* SRC_IP */
		SCANF_ALLOCATE_STRING   /* DST_IP */
		"%*s%*s%*s%*s%*s%*s%*s" /* Seven more fields, SRC_PORT -> FLOWS */
		"%lu",                  /* BYTES */
		source_ip, dest_ip, bytes
		) == 3;
}

/*
 * parse an sfacct record line. (version 0.12.5 on acct1)
 *
 * *source_ip and *dest_ip are allocated by libc
 * caller must free() *source_ip and *dest_ip iff the call was successful
 * (as per sscanf)
 *
 * pre: instring is zero terminated
 *
 * returns >= 1 on success
 */
int parse_sfacct_record(char *cs, char **source_ip, char **dest_ip, uint64_t *bytes) {
	/* Format (with even more whitespace in actual input):
	 *
	 * TAG TAG2 CLASS   IN_IFACE OUT_IFACE SRC_MAC            DST_MAC            VLAN COS SRC_AS DST_AS BGP_COMMS AS_PATH PREF MED PEER_SRC_AS PEER_DST_AS PEER_SRC_IP      PEER_DST_IP SRC_IP           DST_IP          SRC_MASK DST_MASK SRC_PORT DST_PORT TCP_FLAGS PROTOCOL TOS PACKETS FLOWS BYTES
	 * 0   0    unknown 0        0         00:00:00:00:00:00  00:00:00:00:00:00  0    0   0      0                ^$      0    0   0           0                                        110.173.143.36   204.246.163.76  0        0        0        0        0         ip       0   19250   0     20520500
	 *
	 * We ignore everything other than source IP, destination IP, and bytes.
	 */
	*source_ip = NULL;
	*dest_ip = NULL;
	return sscanf(cs,
		"%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s" /* 16 fields that we don't care about (TAG -> PEER_DST_IP), PEER_SRC_IP and PEER_DST_IP don't have any output */
		SCANF_ALLOCATE_STRING         /* SRC_IP */
		SCANF_ALLOCATE_STRING         /* DST_IP */
		"%*s%*s%*s%*s%*s%*s%*s%*s%*s" /* Nine more fields, SRC_MASK -> FLOWS */
		"%lu",                        /* BYTES */
		source_ip, dest_ip, bytes
		) == 3;
}

static inline int emit_bytes(marquise_ctx *ctx, const unsigned char *address_string,
		marquise_source *marq_source, uint64_t timestamp, uint64_t bytes) {
	uint64_t address = marquise_hash_identifier(address_string, strlen((char*)address_string));
	int success;
	success = marquise_send_simple(ctx, address, timestamp, bytes);
	if (success == 0) {
		DEBUG_PRINTF("successfully queued datapoint:  %s with %lu bytes\n", address_string, bytes);
	} else {
		DEBUG_PRINTF("failed to enqueue datapoint:    %s with %lu bytes\n\n", address_string, bytes);
		return success;
	}
	success = marquise_update_source(ctx, address, marq_source);
	if (success == 0) {
		DEBUG_PRINTF("successfully queued sourcedict: address %lu for %s\n", address, address_string);
	} else {
		DEBUG_PRINTF("failed to enqueue sourcedict:   address %lu for %s\n\n", address, address_string);
		return success;
	}
	DEBUG_PRINTF("%s", "\n");
	return 0;
}

static inline int emit_tx_bytes(marquise_ctx *ctx,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	unsigned char *address_string = build_address_string(collection_point, ip, "tx");
	char* source_fields[] = { SOURCE_KEY_BYTES, SOURCE_KEY_COLLECTION_POINT, SOURCE_KEY_IP };
	char* source_values[] = { "tx", collection_point, ip };
	marquise_source *marq_source = marquise_new_source(source_fields, source_values, SOURCE_NUM_TAGS);
	// XXX: should check for NULL before use
	int ret = emit_bytes(ctx, address_string, marq_source, timestamp, bytes);
	marquise_free_source(marq_source);
	free(address_string);
	return ret;
}

static inline int emit_rx_bytes(marquise_ctx *ctx,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	unsigned char *address_string = build_address_string(collection_point, ip, "rx");
	char* source_fields[] = { SOURCE_KEY_BYTES, SOURCE_KEY_COLLECTION_POINT, SOURCE_KEY_IP };
	char* source_values[] = { "rx", collection_point, ip };
	marquise_source *marq_source = marquise_new_source(source_fields, source_values, SOURCE_NUM_TAGS);
	// XXX: should check for NULL before use
	int ret = emit_bytes(ctx, address_string, marq_source, timestamp, bytes);
	marquise_free_source(marq_source);
	free(address_string);
	return ret;
}

int main(int argc, char **argv) {
	extern char *optarg;
	extern int optind;
	int sfacct_flag = 0;
	int c;
	int remaining_args;
	static char usage[] = "%s [-s] <collection point> <marquise namespace> [<filename of ip networks to track>]\n\n"
				"    eg.\n"
				"\t%s    syd1 pmacct\n"
				"\t%s -s lax1 sfacct\n"
				;

	FILE *infile;
	char buf[BUFSIZ];
	char *source_ip;
	char *dest_ip;
	uint64_t bytes;
	uint64_t timestamp;
	uint64_t last_timestamp;
	char *collection_point;
	char *namespace;
	marquise_ctx *ctx;
	networkaddr_ll_t * ip_whitelist = NULL;


	while ((c = getopt(argc, argv, "s")) != -1)
		switch(c) {
			case 's':
				sfacct_flag = 1;
				break;
		}
	DEBUG_PRINTF("sfacct_flag = %d\n", sfacct_flag);

	remaining_args = argc - optind;
	DEBUG_PRINTF("optind = %d\n", optind);
	DEBUG_PRINTF("argc   = %d\n", argc);
	DEBUG_PRINTF("Remaining args: %d\n", remaining_args);

	/* We require at least (collection point, marquise namespace), and optionally (ip_space.txt) */
	if ((remaining_args < 2) || (remaining_args > 3)) {
		fprintf(stderr, usage, argv[0], argv[0], argv[0]);
		return 1;
	}

	collection_point = argv[optind++];
	namespace        = argv[optind++];
	if (remaining_args == 3) {
		ip_whitelist = read_ip_whitelist(argv[optind]);
		if (ip_whitelist == NULL) {
			if (errno == 0)
				fprintf(stderr, "invalid or empty ip whitelist file\n");
			return 1;
		}
	}

	/* Get a new context we can send frames to */
	ctx = marquise_init(namespace);
	if (ctx == NULL) {
		perror("marquise_init"); return 1;
	}

	last_timestamp = timestamp_now();

	infile = stdin; /* slack */

	/* Select a parser function depending on our mode. */
	int (*parser)(char *cs, char **source_ip, char **dest_ip, uint64_t *bytes);
	if (sfacct_flag) {
		parser = parse_sfacct_record;
		DEBUG_PRINTF("%s\n", "We're parsing sfacct records");
	} else {
		parser = parse_pmacct_record;
		DEBUG_PRINTF("%s\n", "We're parsing pmacct records");
	}


	int retcode = 0;
	while ( fgets(buf, BUFSIZ, infile) == buf ) {
		/* Ignore any line that doesn't start with a numeric
		 * ID. This gets around pmacct's stupid logging of
		 * totally unimportant warnings to stdout.
		 */
		if (buf[0] < '0' || buf[0] > '9') continue;

		/* Keep timestamp the same for all items based on the same entry
		 * in case we need to cross correlate them later.
		 */
		timestamp = timestamp_now();

		/* The 2tuple of source,timestamp must be unique for each frame.
		 *
		 * Check to make sure that if we have a really course clock that we
		 * are still maintaining that invariant.
		 */
		if (timestamp < last_timestamp)
			timestamp = last_timestamp + 1; /* Great. NTP skew. My lucky day */
		if (timestamp == last_timestamp)
			timestamp++;
		last_timestamp = timestamp;

		buf[BUFSIZ-1] = 0;
		if (! parser(buf, &source_ip, &dest_ip, &bytes))
			continue; /* Doesn't look like it's actually a record */

		/* Emit a frame for both parties (if the ip is whitelisted) */
		if (is_address_in_whitelist(source_ip, ip_whitelist) == 1) {
			if ( emit_tx_bytes(ctx, collection_point, source_ip, timestamp, bytes) != 0 ) {
				perror(__FILEPOS__ ": marquise_send_simple"); retcode=1; break;
			}
		}
		if (is_address_in_whitelist(dest_ip, ip_whitelist) == 1) {
			if ( emit_rx_bytes(ctx, collection_point, dest_ip, timestamp, bytes) != 0 ) {
				perror(__FILEPOS__ ": marquise_send_simple"); retcode=1; break;
			}
		}

		free(source_ip);
		free(dest_ip);
	}

	marquise_shutdown(ctx);
	free_whitelist(ip_whitelist);

	return retcode;
}
