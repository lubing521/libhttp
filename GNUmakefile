# Common
prefix= /usr/local
libdir= $(prefix)/lib
incdir= $(prefix)/include

CC=   clang

CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function

LDFLAGS=

PANDOC_OPTS= -s --toc --email-obfuscation=none

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DHTTP_PLATFORM_LINUX
	CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
endif

# Debug
debug=0
ifeq ($(debug), 1)
	CFLAGS+= -g -ggdb
else
	CFLAGS+= -O2
endif

# Coverage
coverage?= 0
ifeq ($(coverage), 1)
	CC= gcc
	CFLAGS+= -fprofile-arcs -ftest-coverage
	LDFLAGS+= --coverage
endif

# Target: libhttp
libhttp_LIB= libhttp.a
libhttp_SRC= $(wildcard libhttp/*.c)
libhttp_PUBINC= libhttp/http.h
libhttp_INC= $(wildcard libhttp/*.h)
libhttp_OBJ= $(subst .c,.o,$(libhttp_SRC))

$(libhttp_LIB): CFLAGS+=

# Target: tests
tests_SRC= $(wildcard tests/*.c)
tests_INC= $(wildcard tests/*.h)
tests_OBJ= $(subst .c,.o,$(tests_SRC))
tests_BIN= $(subst .o,,$(tests_OBJ))

$(tests_BIN): CFLAGS+= -Ilibhttp -Itests
$(tests_BIN): LDFLAGS+= -L.
$(tests_BIN): LDLIBS+= -lhttp -lhashtable -lbuffer -levent

# Target: utils
utils_SRC= $(wildcard utils/*.c)
utils_OBJ= $(subst .c,.o,$(utils_SRC))
utils_BIN= $(subst .o,,$(utils_OBJ))

$(utils_BIN): CFLAGS+= -Ilibhttp
$(utils_BIN): LDFLAGS+= -L.
$(utils_BIN): LDLIBS+= -lhttp -lhashtable -lbuffer -levent

# Target: doc
doc_SRC= $(wildcard doc/*.mkd)
doc_HTML= $(subst .mkd,.html,$(doc_SRC))

# Rules
all: $(libhttp_LIB) $(tests_BIN) $(utils_BIN) $(doc_HTML)

$(libhttp_OBJ): $(libhttp_INC)
$(libhttp_LIB): $(libhttp_OBJ)
	$(AR) cr $@ $(libhttp_OBJ)

$(tests_OBJ): $(libhttp_LIB) $(libhttp_INC) $(tests_INC)
tests/%: tests/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(utils_OBJ): $(libhttp_LIB) $(libhttp_INC)
utils/%: utils/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

doc/%.html: doc/*.mkd
	pandoc $(PANDOC_OPTS) -t html5 -o $@ $<

clean:
	$(RM) $(libhttp_LIB) $(wildcard libhttp/*.o)
	$(RM) $(utils_BIN) $(wildcard utils/*.o)
	$(RM) $(tests_BIN) $(wildcard tests/*.o)
	$(RM) $(wildcard **/*.gc??)
	$(RM) -r coverage
	$(RM) -r $(doc_HTML)

coverage:
	lcov -o /tmp/libhttp.info -c -d . -b .
	genhtml -o coverage -t libhttp /tmp/libhttp.info
	rm /tmp/libhttp.info

install: lib
	mkdir -p $(libdir) $(incdir)
	install -m 644 $(libhttp_LIB) $(libdir)
	install -m 644 $(libhttp_PUBINC) $(incdir)

uninstall:
	$(RM) $(addprefix $(libdir)/,$(libhttp_LIB))
	$(RM) $(addprefix $(incdir)/,$(libhttp_PUBINC))

tags:
	ctags -o .tags -a $(wildcard libhttp/*.[hc])

.PHONY: all clean coverage install uninstall tags
