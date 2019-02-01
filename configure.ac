AC_INIT(ssh-agent-pkcs11, 0.1.5) 
AC_CONFIG_HEADERS(config.h)

dnl Locate standard tools
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_AIX

dnl Determine this platform
DC_CHK_OS_INFO

dnl Determine how to create shared objects on this platform
DC_GET_SHOBJFLAGS

dnl Determine how to enable pthreads
AX_PTHREAD(, [
	AC_MSG_WARN([Cannot figure out how to compile with pthreads support, run-time will likely fail.])
])

dnl Determine how to create static archives on this platform
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib)

dnl Check for all required headers
AC_CHECK_HEADERS(arpa/inet.h inttypes.h stdarg.h stdint.h stdio.h stdlib.h string.h sys/socket.h sys/types.h sys/un.h unistd.h pthread.h,,[
	AC_MSG_WARN([Required header missing, compilation will likely fail.])
], [
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef HAVE_STDARG_H
#  include <stdarg.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif
#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_PTHREAD_H
#  include <pthread.h>
#endif
])

dnl Determine what libraries are required to get BSD socket functions
AC_SEARCH_LIBS(socket, [socket nsl])
AC_SEARCH_LIBS(connect, [socket nsl])
AC_SEARCH_LIBS(send, [socket nsl])
AC_SEARCH_LIBS(recv, [socket nsl])

dnl Upate LDFLAGS to include setting the run-time linker path to the same as our compile-time linker
DC_SYNC_RPATH

dnl If we updated LIBOBJS, update SHLIBOBJS -- must be last.
DC_SYNC_SHLIBOBJS

dnl Produce Makefile
AC_CONFIG_FILES([Makefile])
AC_OUTPUT()
