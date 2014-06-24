#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <util.h>

void test_build_source() {
	char *collection_point = "syd1";
	char *ip = "127.0.0.1";
	const char *bytes = "tx";
	char *res = build_source(collection_point, ip, bytes);
	g_assert_cmpstr(res, ==, "bytes:tx,collection_point:syd1,ip:127.0.0.1,");
	return;
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/build_source/build_source", test_build_source);
	return g_test_run();
}
