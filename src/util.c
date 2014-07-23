#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

marquise_source *build_marquise_source(char *collection_point, char *ip, const char *bytes) {
    size_t n_tags = SOURCE_NUM_TAGS;
    char **fields = malloc(sizeof(char *) * n_tags);
    char **values = malloc(sizeof(char *) * n_tags);
    fields[0] = strdup(SOURCE_KEY_BYTES);
    values[0]   = strdup(bytes);
    fields[1] = strdup(SOURCE_KEY_COLLECTION_POINT);
    values[1]   = strdup(collection_point);
    fields[2] = strdup(SOURCE_KEY_IP);
    values[2]   = strdup(ip);
    return marquise_new_source(fields, values, n_tags);
}

char *serialise_marquise_source(marquise_source *marq_source) {
    char **fields = marq_source->fields;
    char **values = marq_source->values;
    int n = marq_source->n_tags;
    int length = 1; //NULL byte at end
    unsigned int i;
    for (i = 0; i < n; i++) {
        length += strlen(fields[i]);
        length += strlen(values[i]);
    }
    char *str = malloc(sizeof(char) * length);
    i = 0;
    while (i < length) {
        strcpy(str + i, fields[i]);
        i += strlen(fields[i]);
        strcpy(str + i, values[i]);
        i += strlen(values[i]);
    } 
    str[i] = '\0';
    return str;
}

char *build_address_string(char *collection_point, char *ip, const char *bytes) {
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
    return source;
}
