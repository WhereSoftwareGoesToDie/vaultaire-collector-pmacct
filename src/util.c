#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SOURCE_KEY_COLLECTION_POINT "collection_point"
#define SOURCE_KEY_IP "ip"
#define SOURCE_KEY_BYTES "bytes"


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
