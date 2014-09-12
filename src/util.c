#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

/* This is a specialised version of libmarquise's serialise_marquise_source
 * function.  The intent is that this builds a unique serialisation for a given
 * primary key 3-tuple. We don't want to use libmarquise's
 * serialise_marquise_source because it may potentially change, and include
 * extra fields, etc.  This here locks us in to (tx/rx, collection_point,
 * ip_address) explicitly.
 *
 * This is what build_address_string() output looks like:
 *     bytes:rx,collection_point:syd1,ip:202.4.224.53,
 */
unsigned char *build_address_string(char *collection_point, char *ip, const char *bytes) {
	/* Always do things in this order to ensure
	 * consistent results from siphash
	 */
	size_t source_len = 	sizeof(SOURCE_KEY_BYTES) +
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
	int idx = sizeof(SOURCE_KEY_BYTES) - 1;
	source[idx++] = ':';
	strcpy(source + idx, bytes);
	idx += bytes_len;
	source[idx++] = ',';
	strcpy(source + idx, SOURCE_KEY_COLLECTION_POINT);
	idx += sizeof(SOURCE_KEY_COLLECTION_POINT) - 1;
	source[idx++] = ':';
	strcpy(source + idx, collection_point);
	idx += collection_point_len;
	source[idx++] = ',';
	strcpy(source + idx, SOURCE_KEY_IP);
	idx += sizeof(SOURCE_KEY_IP) - 1;
	source[idx++] = ':';
	strcpy(source + idx, ip);
	idx += ip_len;
	source[idx++] = ',';
	source[idx++] = '\0';
	return (unsigned char*)source;
}
