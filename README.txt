LIBSSH-AGENT-PKCS11-PROVIDER
----------------------------

This library is a PKCS#11 (v2.30) compatible library.  It works by
tunneling requeusts for PKCS#11 actions over an SSH Agent socket.
It requires a modified SSH Agent.

For usage information see the PKCS#11 Cryptoki documentation.

See LICENSE for licensing information.


###########################################################################

LIBSSH-AGENT-CLIENT
-------------------

This library provides an interface to the cryptographic functions of the
SSH Agent via a socket.  It requires a modified SSH Agent to be fully
functional.  Functional parts without a modified SSH Agent are:

	ssh_agent_connect_socket(...);
	ssize_t ssh_agent_sign(..., ..., ..., ..., ..., ..., 1);

Example of usage:

	#include <libssh-agent-client.h>

	int main(int argc, char **argv) {
		struct ssh_agent_identity *identities = NULL
		unsigned char buf[16384];
		ssize_t buflen;
		int fd, i;

		fd = ssh_agent_connect_socket(NULL);
		if (fd < 0) {
			return(1);
		}

		identities = ssh_agent_getidentities(fd);
		if (!identities) {
			close(fd);

			return(2);
		}

		buflen = ssh_agent_sign(fd, (unsigned char *) "Test", 4, buf, sizeof(buf), &identities[0], 0);
		if (buflen < 0) {
			ssh_agent_freeidentities(identities);

			close(fd);

			return(3);
		}

		printf("Signed(\"Test\"): ");
		for (i = 0; i < buflen; i++) {
			printf("%02x ", buf[i]);
		}
		printf("\n");

		ssh_agent_freeidentities(identities);

		close(fd);

		return(0);
	}

See LICENSE for licensing information.
