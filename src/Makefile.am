AM_CFLAGS  = -Wall -g
AM_LDFLAGS = -lmarquise 

bin_PROGRAMS = vaultaire_collector_pmacct

vaultaire_collector_pmacct_SOURCES = collector.c

indent: *.c *.h
	indent -linux $^
	rm $(foreach input,$^,$(input)~)

test: check
