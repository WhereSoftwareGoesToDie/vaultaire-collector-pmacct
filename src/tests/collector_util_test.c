#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <util.h>

void test_build_address_string() {
	char *collection_point = "syd1";
	char *ip = "127.0.0.1";
	const char *bytes = "tx";
	unsigned char *res = build_address_string(collection_point, ip, bytes);
	g_assert_cmpstr((char*)res, ==, "bytes:tx,collection_point:syd1,ip:127.0.0.1,");
	return;
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/build_address_string/build_address_string", test_build_address_string);
	return g_test_run();
}
