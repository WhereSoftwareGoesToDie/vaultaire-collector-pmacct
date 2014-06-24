#include <glib.h>
#include <stdlib.h>
#include <string.h>

extern char *build_source(char *collection_point, char *ip, const char *bytes);

void test_build_source() {
	return;
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/build_source/build_source", test_build_source);
	return g_test_run();
}
