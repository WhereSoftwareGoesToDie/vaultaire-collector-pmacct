TESTS=$(check_PROGRAMS)
check_PROGRAMS=collector_util_test collector_parser_test
bin_PROGRAMS = vaultaire_collector_pmacct

dist_noinst_HEADERS = util.h collector.h


collector_util_test_SOURCES = util.c tests/collector_util_test.c
collector_util_test_CFLAGS  = -Wall -g $(GLIB_2_CFLAGS)
collector_util_test_LDFLAGS = -lmarquise -lrt $(GLIB_2_LIBS)

collector_parser_test_SOURCES = util.c tests/collector_parser_test.c
collector_parser_test_CFLAGS  = -Wall -g $(GLIB_2_CFLAGS)
collector_parser_test_LDFLAGS = -lmarquise -lrt $(GLIB_2_LIBS)

vaultaire_collector_pmacct_SOURCES = util.c collector.c
vaultaire_collector_pmacct_CFLAGS  = -Wall -g $(GLIB_2_CFLAGS)
vaultaire_collector_pmacct_LDFLAGS = -lmarquise -lrt


test: check

indent: *.c *.h
	indent -linux $^
	rm $(foreach input,$^,$(input)~)
