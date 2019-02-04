#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#  include <string.h>
#endif
#include <stdbool.h>

#include "debug.h"

#ifndef SSH_AGENT_MAX_IDENTITIES
#  define SSH_AGENT_MAX_IDENTITIES 127
#endif

/* From the unix(7) man page. */
#ifndef UNIX_PATH_MAX
#  define UNIX_PATH_MAX    108
#endif

/* From OpenSSH 4.5p1 authfd.h */
/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES       1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER         2
#define SSH_AGENTC_RSA_CHALLENGE                3
#define SSH_AGENT_RSA_RESPONSE                  4
#define SSH_AGENT_FAILURE                       5
#define SSH_AGENT_SUCCESS                       6
#define SSH_AGENTC_ADD_RSA_IDENTITY             7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY          8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES    9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES          11
#define SSH2_AGENT_IDENTITIES_ANSWER            12
#define SSH2_AGENTC_SIGN_REQUEST                13
#define SSH2_AGENT_SIGN_RESPONSE                14
#define SSH2_AGENTC_ADD_IDENTITY                17
#define SSH2_AGENTC_REMOVE_IDENTITY             18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES       19

/* extended failure messages */
#define SSH2_AGENT_FAILURE                      30

/* Extended sign flags */
#define SSH2_AGENT_SIGNFLAGS_RSA_RAW            0x40000000LLU
#define SSH2_AGENT_SIGNFLAGS_RSA_DECRYPT        0x80000000LLU

struct ssh_agent_identity {
	uint32_t bloblen;
	unsigned char *blob;

	char *comment;
};

static char *ssh_agent_getsockpath(void) {
	char *authsock = NULL;

	authsock = getenv("SSH_AUTH_SOCK");
	if (!authsock) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Unable to determine SSH authorization socket.");
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("ssh-agent not running, or ssh agent forwarding disabled ?");

		return(NULL);
	}

	return(authsock);
}

int ssh_agent_connect_socket(const char *path) {
	struct sockaddr_un addr;
	int fd;
	int conn_ret;

	if (!path) {
		path = ssh_agent_getsockpath();

		if (!path) {
			return(-1);
		}
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("socket");

		return(fd);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	conn_ret = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (conn_ret < 0) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("connect");

		return(conn_ret);
	}

	return(fd);
}

/* If fakebuflen == 0, send buffer length as buflen; if fakebuflen < 0, don't send buffer length at all -- just data */
static ssize_t ssh_agent_send(int fd, unsigned char *buf, size_t buflen, ssize_t fakebuflen) {
	uint32_t sendsize;
	ssize_t send_ret;

	if (fd < 0) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("fd is invalid (fd = %i)", fd);

		return(-1);
	}

	if (!buf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("buf is NULL");

		return(-1);
	}

	if (fakebuflen >= 0) {
		if (fakebuflen == 0) {
			fakebuflen = buflen;
		}

		sendsize = htonl(fakebuflen);

		send_ret = send(fd, &sendsize, sizeof(sendsize), 0);
		if (send_ret != sizeof(sendsize)) {
			LIBSSH_AGENT_CLIENT_DEBUG_PERROR("send");

			return(-1);
		}
	}

	send_ret = send(fd, buf, buflen, 0);
	if (send_ret != -1 && (size_t) send_ret != buflen) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("send");

		return(-1);
	}

	return(buflen);
}

static ssize_t ssh_agent_recv(int fd, unsigned char *buf, size_t buflen) {
	uint32_t recvsize;
	ssize_t recv_ret;

	if (fd < 0) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("fd is invalid (fd = %i)", fd);

		return(-1);
	}

	if (!buf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("buf is NULL");

		return(-1);
	}

	recv_ret = recv(fd, &recvsize, sizeof(recvsize), 0);
	if (recv_ret != sizeof(recvsize)) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("recv");

		return(-1);
	}

	recvsize = ntohl(recvsize);

	if (recvsize > buflen) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Requested larger than available buffer space, failing.");

		return(-1);
	}

	recv_ret = recv(fd, buf, recvsize, 0);
	if (recv_ret != -1 && (size_t) recv_ret != recvsize) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("recv");

		return(-1);
	}

	return(recvsize);
}

static int32_t ssh_agent_buffer_getint(unsigned char *basebuf, size_t buflen, unsigned char **buf_p) {
	unsigned char *buf_end;
	uint32_t retval;

	buf_end = basebuf + buflen;

	if ((*buf_p + sizeof(retval)) > buf_end) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Buffer too small, tried to read %i bytes, but only %i were available.", sizeof(retval), buf_end - *buf_p);

		return(-1);
	}

	memcpy(&retval, *buf_p, sizeof(retval));
	*buf_p += sizeof(retval);
	retval = ntohl(retval);

	return(retval);
}

static ssize_t ssh_agent_buffer_getstr(unsigned char *basebuf, size_t buflen, unsigned char **buf_p, unsigned char **bufret, size_t bytestoread, int retmode) {
	unsigned char *buf_end;
	int32_t msglen;

	buf_end = basebuf + buflen;

	if (bytestoread == 0) {
		msglen = ssh_agent_buffer_getint(basebuf, buflen, buf_p);
		if (msglen < 0) {
			return(-1);
		}
	} else {
		msglen = bytestoread;
	}

	if ((*buf_p + msglen) > buf_end) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Buffer too small, tried to read %i bytes, but only %i were available.", msglen, buf_end - *buf_p);

		return(-1);
	}

	switch (retmode) {
		case 0:
			/* Copy to new buffer */
			memcpy(*bufret, *buf_p, msglen);
			break;
		case 1:
			/* Malloc and copy to new buffer */
			*bufret = malloc(msglen + 1);
			if (!*bufret) {
				LIBSSH_AGENT_CLIENT_DEBUG_PERROR("malloc");

				return(-1);
			}

			(*bufret)[msglen] = '\0';

			memcpy(*bufret, *buf_p, msglen);
			break;
		case 2:
			/* Just return the new buffer */
			*bufret = *buf_p;
			break;
	}

	*buf_p += msglen;

	return(msglen);
}

/* Returns: array of struct ssh_agent_identity, NULL terminated */
struct ssh_agent_identity *ssh_agent_getidentities(int fd) {
	struct ssh_agent_identity *identities = NULL;
	unsigned char buf[16384], *buf_p, *buf_end;
	unsigned char *bufInternalTmp, *bufInternal;
	uint32_t numIds, currId, i;
	ssize_t send_ret, recv_ret, currIdLen, bufInternalLen, currCommentLen;
	bool validIdentity;

	buf[0] = SSH2_AGENTC_REQUEST_IDENTITIES;
	send_ret = ssh_agent_send(fd, buf, 1, 0);
	if (send_ret != 1) {
		return(NULL);
	}

	recv_ret = ssh_agent_recv(fd, buf, sizeof(buf));
	if (recv_ret <= 5) {
		return(NULL);
	}

	buf_p = buf;
	buf_end = buf + recv_ret;

	if (*buf_p != SSH2_AGENT_IDENTITIES_ANSWER) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Invalid response, expected %i got %i", SSH2_AGENT_IDENTITIES_ANSWER, buf[0]);

		return(NULL);
	}
	buf_p++;

	numIds = ssh_agent_buffer_getint(buf, sizeof(buf), &buf_p);

	LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Number of Identities: %i", numIds);

	if (numIds >= SSH_AGENT_MAX_IDENTITIES) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Too many identities!");

		return(NULL);
	}

	/* Create a NULL-terminated array of identities (struct ssh_agent_identity) */
	identities = malloc(sizeof(*identities) * (numIds + 1));
	if (!identities) {
		LIBSSH_AGENT_CLIENT_DEBUG_PERROR("malloc");

		return(NULL);
	}

	for (currId = 0; currId < (numIds + 1); currId++) {
		identities[currId].blob = NULL;
		identities[currId].comment = NULL;
	}

	for (currId = 0; currId < numIds; currId++) {
		currIdLen = ssh_agent_buffer_getstr(buf, sizeof(buf), &buf_p, &identities[currId].blob, 0, 1);
		identities[currId].bloblen = currIdLen;
		if (currIdLen < 0) {
			goto ssh_agent_getidentities_failure;
		}

		currCommentLen = ssh_agent_buffer_getstr(buf, sizeof(buf), &buf_p, (unsigned char **) &identities[currId].comment, 0, 1);
		if (currCommentLen < 0) {
			goto ssh_agent_getidentities_failure;
		}

		/*
		 * Filter out items that are not x509v3-*
		 */
		bufInternalTmp = identities[currId].blob;
		bufInternalLen = ssh_agent_buffer_getstr(identities[currId].blob, currIdLen, &bufInternalTmp, &bufInternal, 0, 2);
		validIdentity = false;
		if (bufInternalLen >= 7 && memcmp(bufInternal, "x509v3-", 7) == 0) {
			validIdentity = true;
		} else {
			if (bufInternalLen > 0 && bufInternalLen < 65536) {
				LIBSSH_AGENT_CLIENT_DEBUG_PRINTBUF("Ignored:", bufInternal, bufInternalLen);
			}
		}

		if (!validIdentity) {
			free(identities[currId].blob);
			free(identities[currId].comment);
			identities[currId].blob = NULL;
			identities[currId].comment = NULL;
			currId--;
			numIds--;
			continue;
		}

		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("ID#%i: %s", currId, identities[currId].comment);
	}

	return(identities);

ssh_agent_getidentities_failure:
	if (identities) {
		for (i = 0; i < currId; i++) {
			if (identities[currId].blob) {
				free(identities[currId].blob);
			}

			if (identities[currId].comment) {
				free(identities[currId].comment);
			}
		}

		free(identities);
	}

	return(NULL);
}

void ssh_agent_freeidentities(struct ssh_agent_identity *identities) {
	struct ssh_agent_identity *currid;

	if (identities) {
		for (currid = identities; currid->blob != NULL && currid->comment != NULL; currid++) {
			if (currid->blob) {
				free(currid->blob);
			}

			if (currid->comment) {
				free(currid->comment);
			}
		}

		free(identities);
	}

	return;
}

/* Returns: Size of signed (encrypted) data written to "retbuf", or -1 on error */
ssize_t ssh_agent_sign(int fd, unsigned char *databuf, size_t databuflen, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity, int doHash) {
	unsigned char buf[4096], *buf_p;
	char *msgtype;
	uint32_t flags = 0, bloblen, datalen;
	ssize_t recv_ret, send_ret, msgtypelen, msglen;

	if (!databuf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("databuf is NULL");

		return(-1);
	}

	if (!retbuf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("retbuf is NULL");

		return(-1);
	}

	if (!identity) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("identity is NULL");

		return(-1);
	}

	if ((1 + sizeof(bloblen) + sizeof(datalen) + sizeof(flags) + identity->bloblen + databuflen) > sizeof(buf)) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Buffer too small to hold outgoing data (need atleast %i, have only %i)", (1 + sizeof(bloblen) + sizeof(datalen) + sizeof(flags) + identity->bloblen + databuflen), sizeof(buf));

		return(-1);
	}

	if (doHash == 1) {
		flags = 0;
	} else {
		flags = SSH2_AGENT_SIGNFLAGS_RSA_RAW; 
	}

	buf_p = buf;

	*buf_p = SSH2_AGENTC_SIGN_REQUEST;
	buf_p++;

	bloblen = htonl(identity->bloblen);
	memcpy(buf_p, &bloblen, sizeof(bloblen));
	buf_p += sizeof(bloblen);

	memcpy(buf_p, identity->blob, identity->bloblen);
	buf_p += identity->bloblen;

	datalen = htonl(databuflen);
	memcpy(buf_p, &datalen, sizeof(datalen));
	buf_p += sizeof(datalen);

	memcpy(buf_p, databuf, databuflen);
	buf_p += databuflen;

	flags = htonl(flags);
	memcpy(buf_p, &flags, sizeof(flags));
	buf_p += sizeof(flags);

	send_ret = ssh_agent_send(fd, buf, buf_p - buf, 0);
	if (send_ret != (buf_p - buf)) {
		return(-1);
	}

	recv_ret = ssh_agent_recv(fd, buf, sizeof(buf));
	if (recv_ret < 1) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Received too little data. Got %i, expected atleast 1", recv_ret);

		return(-1);
	}

	buf_p = buf;

	if (*buf_p != SSH2_AGENT_SIGN_RESPONSE) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Did not get acceptable signing response.  Got %i, expected %i.", *buf_p, SSH2_AGENT_SIGN_RESPONSE);

		return(-1);
	}
	buf_p++;

	/* Skip total message size... XXX */
	buf_p += 4;

	msgtypelen = ssh_agent_buffer_getstr(buf, sizeof(buf), &buf_p, (unsigned char **) &msgtype, 0, 1);
	free(msgtype);

	msglen = ssh_agent_buffer_getint(buf, sizeof(buf), &buf_p);

	if (msglen < 0) {
		return(-1);
	}

	if (msglen > ((ssize_t) retbuflen)) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Return buffer too small.");

		return(-1);
	}

	msglen = ssh_agent_buffer_getstr(buf, sizeof(buf), &buf_p, &retbuf, msglen, 0);

	return(msglen);
}

/* Returns: Size of decrypted data written to "retbuf", or -1 on error */
ssize_t ssh_agent_decrypt(int fd, unsigned char *databuf, size_t databuflen, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity) {
	unsigned char buf[4096], *buf_p;
	uint32_t flags = 0, bloblen, datalen;
	ssize_t recv_ret, send_ret, msglen;

	if (!databuf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("databuf is NULL");

		return(-1);
	}

	if (!retbuf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("retbuf is NULL");

		return(-1);
	}

	if (!identity) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("identity is NULL");

		return(-1);
	}

	if ((1 + sizeof(bloblen) + sizeof(datalen) + sizeof(flags) + identity->bloblen + databuflen) > sizeof(buf)) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Buffer too small to hold outgoing data (need atleast %i, have only %i)", (1 + sizeof(bloblen) + sizeof(datalen) + sizeof(flags) + identity->bloblen + databuflen), sizeof(buf));

		return(-1);
	}

	flags = SSH2_AGENT_SIGNFLAGS_RSA_RAW | SSH2_AGENT_SIGNFLAGS_RSA_DECRYPT; 

	buf_p = buf;

	*buf_p = SSH2_AGENTC_SIGN_REQUEST;
	buf_p++;

	bloblen = htonl(identity->bloblen);
	memcpy(buf_p, &bloblen, sizeof(bloblen));
	buf_p += sizeof(bloblen);

	memcpy(buf_p, identity->blob, identity->bloblen);
	buf_p += identity->bloblen;

	datalen = htonl(databuflen);
	memcpy(buf_p, &datalen, sizeof(datalen));
	buf_p += sizeof(datalen);

	memcpy(buf_p, databuf, databuflen);
	buf_p += databuflen;

	flags = htonl(flags);
	memcpy(buf_p, &flags, sizeof(flags));
	buf_p += sizeof(flags);

	send_ret = ssh_agent_send(fd, buf, buf_p - buf, 0);
	if (send_ret != (buf_p - buf)) {
		return(-1);
	}

	recv_ret = ssh_agent_recv(fd, buf, sizeof(buf));
	if (recv_ret < 1) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Received too little data. Got %i, expected atleast 1", recv_ret);
		return(-1);
	}

	buf_p = buf;

	if (*buf_p != SSH2_AGENT_SIGN_RESPONSE) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Did not get acceptable decrypting response.  Got %i, expected %i.", *buf_p, SSH2_AGENT_SIGN_RESPONSE);

		return(-1);
	}
	buf_p++;

	/* Skip total message size... XXX */
	buf_p += 4;

	msglen = ssh_agent_buffer_getint(buf, sizeof(buf), &buf_p);

	if (msglen < 0) {
		return(-1);
	}

	if (msglen > ((ssize_t) retbuflen)) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Return buffer too small.");

		return(-1);
	}

	msglen = ssh_agent_buffer_getstr(buf, sizeof(buf), &buf_p, &retbuf, msglen, 0);

	return(msglen);
}

/* Returns: Size of DER encoded X.509 certificate stored in "retbuf", or -1 on error */
ssize_t ssh_agent_getcert(int fd, unsigned char *retbuf, size_t retbuflen, struct ssh_agent_identity *identity) {
	unsigned char *buf, *buf_p, *idType;
	uint32_t bufLen, numCerts;
	ssize_t idTypeLen, certLen;
	bool validIdentity;

	if (!retbuf) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("retbuf is NULL");

		return(-1);
	}

	if (!identity) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("identity is NULL");

		return(-1);
	}

	buf = identity->blob;
	bufLen = identity->bloblen;

	if (retbuflen < bufLen) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("retbuflen is too small (should be atleast %llu, is %llu)",
		    (unsigned long long) bufLen,
		    (unsigned long long) retbuflen
		);

		return(-1);
	}

	buf_p = buf;

	idTypeLen = ssh_agent_buffer_getstr(buf, bufLen, &buf_p, &idType, 0, 2);
	validIdentity = false;
	if (idTypeLen >= 7 && memcmp(idType, "x509v3-", 7) == 0) {
		validIdentity = true;
	}

	if (!validIdentity) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("identity is invalid");

		return(-1);
	}

	numCerts = ssh_agent_buffer_getint(buf, bufLen, &buf_p);
	if (numCerts < 1) {
		LIBSSH_AGENT_CLIENT_DEBUG_PRINTF("Too few certifificates in chain (%llu, should be atleast 1)",
			(unsigned long long) numCerts
		);
	}

	certLen = ssh_agent_buffer_getstr(buf, bufLen, &buf_p, &retbuf, 0, 0);
	LIBSSH_AGENT_CLIENT_DEBUG_PRINTBUF("cert", retbuf, certLen);

	return(certLen);
}

