bin_PROGRAMS = medusa
medusa_SOURCES = listModules.c medusa.c medusa-thread-pool.c medusa-thread-ssl.c medusa-net.c medusa-trace.c medusa-utils.c

# set the include path found by configure
AM_CPPFLAGS = -I$(top_srcdir)/src $(all_includes)


# the library search path.
#medusa_LDFLAGS = -rdynamic -ldl -lpthread -lssl
noinst_HEADERS = medusa.h medusa-thread-pool.h medusa-thread-ssl.h medusa-net.h medusa-trace.h medusa-utils.h uthash.h
#AM_CFLAGS = -DLIBOPENSSL
SUBDIRS = modsrc
