#ifndef USACE_LIBSSH_AGENT_CLIENT_H
#define USACE_LIBSSH_AGENT_CLIENT_H 1

#ifdef HAVE_CONFIG_H
#  include "config.h"
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#  ifdef HAVE_STDINT_H
#    include <stdint.h>
#  endif
#else
#  include <sys/types.h>
#  include <unistd.h>
#  include <stdint.h>
#endif

#ifndef SSH_AGENT_MAX_IDENTITIES
#  define SSH_AGENT_MAX_IDENTITIES 127
#endif

struct ssh_agent_identity {
	uint32_t bloblen;
	unsigned char *blob;

	char *comment;
};

/* Returns: File descriptor refering to connection to SSH Agent socket */
/* PATH -- if NULL, defaults to determining it from the environment */
int ssh_agent_connect_socket(const char *path);

/* Returns: array of struct ssh_agent_identity, NULL terminated */
struct ssh_agent_identity *ssh_agent_getidentities(int fd);

/* Returns: Nothing */
void ssh_agent_freeidentities(struct ssh_agent_identity *identities);

/* Returns: Size of signed (encrypted) data written to "retbuf", or -1 on error */
ssize_t ssh_agent_sign(int fd, unsigned char *databuf, size_t databuflen, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity, int doHash);

/* Returns: Size of decrypted data written to "retbuf", or -1 on error */
ssize_t ssh_agent_decrypt(int fd, unsigned char *databuf, size_t databuflen, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity);

/* Returns: Size of DER encoded X.509 certificate stored in "retbuf", or -1 on error */
ssize_t ssh_agent_getcert(int fd, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity);

#endif
