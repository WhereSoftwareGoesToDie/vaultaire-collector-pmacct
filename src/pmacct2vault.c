
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <marquise.h>

#define __STRINGIZE(x) #x
#define _STRINGIZE(x) __STRINGIZE(x)
#define __FILEPOS__ __FILE__ ":" _STRINGIZE(__LINE__)

#ifdef DEBUG
#define DEBUG_PRINTF(formatstr, ...) fprintf(stderr, __FILEPOS__ ", %s() - " formatstr, __func__,  __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

/* Max time to wait between batching up frames to send to voltaire */
#define BATCH_PERIOD	0.1

#define DEFAULT_LIBMARQUISE_ORIGIN	"pmacct2vault"

/**
 * This is only going to fly if we are getting data in on the fly
 * and we have no other timestamp source
 */
uint64_t timestamp_now() {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts)) { perror("clock_gettime"); exit(2); }
	return (ts.tv_sec*1000000000) + ts.tv_nsec;
}

/*
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
#if _POSIX_C_SOURCE >= 200809L
		"%ms%ms"
#elif defined(__GLIBC__) && (__GLIBC__ >= 2)
		"%as%as"
#else
#error "Please let us have POSIX.1-2008, glibc, or a puppy"
#endif
		"%*s%*s%*s%*s%*s%*s%*s"
		"%lu",
		source_ip, dest_ip, bytes
		) == 3;
}

static inline int emit_tx_bytes(marquise_connection connection,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	char * source_fields[] = { "collection_point", "ip", "bytes" };
	char * source_values[] = { collection_point, ip, "tx" };
	int bytes_sent;
	bytes_sent = marquise_send_int(connection,
			source_fields, source_values, 3, bytes, timestamp);
	DEBUG_PRINTF("sent %d bytes\n", bytes_sent);
	return bytes_sent;
}
static inline int emit_rx_bytes(marquise_connection connection,
		char *collection_point, char *ip, uint64_t timestamp,
		uint64_t bytes) {
	char * source_fields[] = { "collection_point", "ip", "bytes" };
	char * source_values[] = { collection_point, ip, "rx" };
	int bytes_sent;
	bytes_sent = marquise_send_int(connection,
			source_fields, source_values, 3, bytes, timestamp);
	DEBUG_PRINTF("sent %d bytes\n", bytes_sent);
	return bytes_sent;
}
#undef LINK_SRC_DEST_FLOWS
#ifdef LINK_SRC_DEST_FLOWS
static inline int emit_dest_ip(marquise_connection connection,
		char *collection_point, char *ip, uint64_t timestamp,
		char *dest_ip) {
	char * source_fields[] = { "type", "collection_point", "ip", "field" };
	char * source_values[] = { "ip_traffic", "syd1", ip, "dest_ip" };
	int bytes_sent;
	bytes_sent = marquise_send_text(connection,
			source_fields, source_values, 4, 
			dest_ip, strlen(dest_ip), timestamp);
	DEBUG_PRINTF("sent %d bytes\n", bytes_sent);
	return bytes_sent;
}

static inline int emit_src_ip(marquise_connection connection,
		char *collection_point, char *ip, uint64_t timestamp,
		char *src_ip) {
	char * source_fields[] = { "type", "collection_point", "ip", "field" };
	char * source_values[] = { "ip_traffic", "syd1", ip, "src_ip" };
	int bytes_sent;
	bytes_sent = marquise_send_text(connection,
			source_fields, source_values, 4,
			src_ip, strlen(src_ip), timestamp);
	DEBUG_PRINTF("sent %d bytes\n", bytes_sent);
	return bytes_sent;
}
#endif

int main(int argc, char **argv) {
	FILE *infile;
	char buf[BUFSIZ];
	char *source_ip;
	char *dest_ip;
	uint64_t bytes;
	uint64_t timestamp;
	uint64_t last_timestamp;
	char *collection_point;
	marquise_consumer consumer;
	marquise_connection vaultc;

	if (argc < 3) {
		fprintf(stderr,"%s <collection point> <vaultaire endpoint>\n\n"
				"e.g.\n\t%s syd1 tcp://localhost:1234\n",
				argv[0], argv[0]);
		return 1;
	}
	collection_point = argv[1];

	/* libmarquise currently requires the origin to be set by environment
	 * variable. Set iff it is currently not in the environment
	 */
	setenv("LIBMARQUISE_ORIGIN",  DEFAULT_LIBMARQUISE_ORIGIN, 0);

	/* get a new consumer we can send frames to 
	 */
	consumer = marquise_consumer_new(argv[2], BATCH_PERIOD);
	if (consumer == NULL) {
		perror("marquise_consumer_new"); return 1;
	}
	vaultc = marquise_connect(consumer);
	if (vaultc == NULL) {
		perror("marquise_connect");
		marquise_consumer_shutdown(consumer);
		return 1;
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

		/* emit a frame for both parties */
		if ( emit_tx_bytes(vaultc, collection_point, source_ip, timestamp, bytes) <= 0 ) {
			perror(__FILEPOS__ ": marquise_send_int"); retcode=1; break;
		}
		if ( emit_rx_bytes(vaultc, collection_point, dest_ip, timestamp, bytes) <= 0 ) {
			perror(__FILEPOS__ ": marquise_send_int"); retcode=1; break;
		}
#ifdef LINK_SRC_DEST_FLOWS
		if ( emit_dest_ip(vaultc, collection_point, source_ip, timestamp, dest_ip) <= 0 ) {
			perror(__FILEPOS__ ": marquise_send_text"); retcode=1; break;
		}
		if ( emit_src_ip(vaultc, collection_point, dest_ip, timestamp, source_ip) <= 0 ) {
			perror(__FILEPOS__ ": marquise_send_text"); retcode=1; break;
		}
#endif

		free(source_ip);
		free(dest_ip);
	}

	marquise_close(vaultc);
	marquise_consumer_shutdown(consumer);

	return retcode;
}
