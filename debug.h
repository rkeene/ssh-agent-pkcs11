#ifndef DEBUG_H_45D5B4D29FDD9360A50683AAECE02B20F52AAE02
#ifdef LIBSSH_AGENT_CLIENT_DEBUG
#  ifdef HAVE_STDIO_H
#    include <stdio.h>
#  endif

#  define LIBSSH_AGENT_CLIENT_DEBUG_PRINTF(x...) { fprintf(stderr, "%s(): ", __func__); fprintf(stderr, x); fprintf(stderr, "\n"); }
#  define LIBSSH_AGENT_CLIENT_DEBUG_PRINTBUF(f, x, y) { unsigned char *buf; unsigned long idx; buf = (unsigned char *) (x); fprintf(stderr, "%s(): %s  (%s/%lu = {%02x", __func__, f, #x, (unsigned long) (y), buf[0]); for (idx = 1; idx < (y); idx++) { fprintf(stderr, ", %02x", buf[idx]); }; fprintf(stderr, "})\n"); }
#  define LIBSSH_AGENT_CLIENT_DEBUG_PERROR(x) { fprintf(stderr, "%s(): ", __func__); perror(x); }
#  define free(x) { LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("FREE(%p) (%s)", x, #x); free(x); }

static void *LIBSSH_AGENT_CLIENT_DEBUG_FUNC_MALLOC(size_t size, const char *func) {
	void *retval;

	retval = malloc(size);

	fprintf(stderr, "%s(): ", func);
	fprintf(stderr, "MALLOC() = %p", retval);
	fprintf(stderr, "\n");

	return(retval);
}

static void *LIBSSH_AGENT_CLIENT_DEBUG_FUNC_REALLOC(void *ptr, size_t size, const char *func) {
	void *retval;

	retval = realloc(ptr, size);

	if (retval != ptr) {
		fprintf(stderr, "%s(): ", func);
		fprintf(stderr, "REALLOC(%p) = %p", ptr, retval);
		fprintf(stderr, "\n");
	}

	return(retval);
}

#  define malloc(x) LIBSSH_AGENT_CLIENT_DEBUG_FUNC_MALLOC(x, __func__)
#  define realloc(x, y) LIBSSH_AGENT_CLIENT_DEBUG_FUNC_REALLOC(x, y, __func__)
#else
#  define LIBSSH_AGENT_CLIENT_DEBUG_PRINTF(x...) /**/
#  define LIBSSH_AGENT_CLIENT_DEBUG_PRINTBUF(f, x, y) /**/
#  define LIBSSH_AGENT_CLIENT_DEBUG_PERROR(x) /**/
#endif
#endif
