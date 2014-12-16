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

#include <netinet/in.h>


typedef struct {
	in_addr_t network;
	in_addr_t netmask;
	void * next;
} networkaddr_ll_t;


/*
 * This is only going to fly if we are getting data in on the fly
 * and we have no other timestamp source.
 */
uint64_t timestamp_now();

networkaddr_ll_t * read_ip_whitelist(char *pathname);

/*
 * parse a pmacct record line. (version 0.11.6-cvs on fishhook)
 *
 * source_ip and dest_ip are allocated by libc, caller must
 * free them iff the call was successful, as per sscanf(3).
 *
 * pre: instring is zero terminated
 *
 * returns >= 1 on success
 */
int parse_pmacct_record(char *cs, char **source_ip, char **dest_ip, uint64_t *bytes);

/*
 * parse an sfacct record line. (version 0.12.5 on acct1)
 *
 * source_ip and dest_ip are allocated by libc, caller must
 * free them iff the call was successful, as per sscanf(3).
 *
 * pre: instring is zero terminated
 *
 * returns >= 1 on success
 */
int parse_sfacct_record(char *cs, char **source_ip, char **dest_ip, uint64_t *bytes);
