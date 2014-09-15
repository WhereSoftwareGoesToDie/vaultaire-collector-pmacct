#ifdef FISHHOOK_IS_CRAP
/* FIXME: Use a real ifdef */
/* This is needed for stpncpy() on RHEL/CentOS 5.x, it's in string.h */
#define _GNU_SOURCE
#endif /* FISHHOOK_IS_CRAP */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

#define COLON ":"
#define COMMA ","

/* This is a specialised version of libmarquise's serialise_marquise_source
 * function. The intent is that this builds a unique serialisation for a given
 * (collectionPoint,IP,bytes) 3-tuple. We don't want to use libmarquise's
 * serialise_marquise_source because it may change in time, and it includes
 * extra fields, etc. This here locks us in to (tx/rx, collection_point,
 * ip_address) explicitly, in a fixed order for siphash to consume.
 *
 * This is what build_address_string() output looks like:
 *     bytes:rx,collection_point:syd1,ip:202.4.224.53,
 */
unsigned char *build_address_string(char *collection_point, char *ip, const char *bytes) {
	size_t address_len =	strlen(SOURCE_KEY_BYTES) +		//  bytes
				1 +					//  :
				strlen(bytes) +				//  rx
				1 +					//  ,
				strlen(SOURCE_KEY_COLLECTION_POINT) +	//  collection_point
				1 +					//  :
				strlen(collection_point) +		//  syd1
				1 +					//  ,
				strlen(SOURCE_KEY_IP) +			//  ip
				1 +					//  :
				strlen(ip) +				//  202.4.224.53
				1 +					//  ,
				1;					//  \0

	char* address_string = malloc(address_len);
	if (address_string == NULL) {
		// XXX: Ensure that all callers know to check for NULL return
		return NULL;
	}
	char* end_p = address_string;

	/* Ensure the string is always null-terminated. */
	memset(address_string, '\0', address_len);

	end_p = stpncpy(end_p, SOURCE_KEY_BYTES, strlen(SOURCE_KEY_BYTES));
	end_p = stpncpy(end_p, COLON, 1);
	end_p = stpncpy(end_p, bytes, strlen(bytes));
	end_p = stpncpy(end_p, COMMA, 1);

	end_p = stpncpy(end_p, SOURCE_KEY_COLLECTION_POINT, strlen(SOURCE_KEY_COLLECTION_POINT));
	end_p = stpncpy(end_p, COLON, 1);
	end_p = stpncpy(end_p, collection_point, strlen(collection_point));
	end_p = stpncpy(end_p, COMMA, 1);

	end_p = stpncpy(end_p, SOURCE_KEY_IP, strlen(SOURCE_KEY_IP));
	end_p = stpncpy(end_p, COLON, 1);
	end_p = stpncpy(end_p, ip, strlen(ip));
	end_p = stpncpy(end_p, COMMA, 1);

	return (unsigned char*)address_string;
}
