#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <marquise.h>

#define SOURCE_KEY_COLLECTION_POINT "collection_point"
#define SOURCE_KEY_IP "ip"
#define SOURCE_KEY_BYTES "bytes"
#define SOURCE_NUM_TAGS 3

marquise_source *build_marquise_source(char *collection_point, char *ip, const char *bytes);
unsigned char *build_address_string(char *collection_point, char *ip, const char *bytes);
