AM_CFLAGS = -Wall -g $(GLIB_2_CFLAGS)
AM_LDFLAGS = -lmarquise -lrt $(GLIB_2_LIBS)

TESTS=$(check_PROGRAMS)
check_PROGRAMS=collector_util_test

collector_util_test_SOURCES = util.c tests/collector_util_test.c
dist_noinst_HEADERS = util.h

bin_PROGRAMS = vaultaire_collector_pmacct

vaultaire_collector_pmacct_SOURCES = util.c collector.c

test: check

indent: *.c *.h
	indent -linux $^
	rm $(foreach input,$^,$(input)~)
