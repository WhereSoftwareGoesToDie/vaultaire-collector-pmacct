#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "collector.h"
#include "util.h"

#define PMACCT_SAMPLE_DATAFILE "sample_pmacct.data"
#define SFACCT_SAMPLE_DATAFILE "sample_sfacct.data"

void test_parse_pmacct_record() {
	FILE* f;
	char buf[BUFSIZ];
	char *source_ip;
	char *dest_ip;
	uint64_t bytes;

	f = fopen(PMACCT_SAMPLE_DATAFILE, "r");
        if (f == NULL) {
		perror("Couldn't open sample data file " PMACCT_SAMPLE_DATAFILE);
		g_test_fail();
                return;
	}

	while ( fgets(buf, BUFSIZ, f) == buf ) {
		/* Ignore any line that doesn't start with a numeric ID. */
		if (buf[0] < '0' || buf[0] > '9') continue;

		if (! parse_pmacct_record(buf, &source_ip, &dest_ip, &bytes)) {
			/* Doesn't look like a record. */
			continue;
		}

		printf("Bytes from %s to %s\n", source_ip, dest_ip);

		free(source_ip);
		free(dest_ip);
	}

}


int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/parse_pmacct_record/parse_pmacct_record", test_parse_pmacct_record);

	return g_test_run();
}
