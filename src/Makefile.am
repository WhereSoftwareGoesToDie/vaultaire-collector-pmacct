AM_CFLAGS  = -Wall -g
AM_LDFLAGS = -lmarquise 

bin_PROGRAMS = pmacct2vault

pmacct2vault_SOURCES = pmacct2vault.c

indent: *.c *.h
	indent -linux $^
	rm $(foreach input,$^,$(input)~)

test: check
