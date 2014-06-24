#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define SOURCE_KEY_COLLECTION_POINT "collection_point"
#define SOURCE_KEY_IP "ip"
#define SOURCE_KEY_BYTES "bytes"

char *build_source(char *collection_point, char *ip, const char *bytes);
