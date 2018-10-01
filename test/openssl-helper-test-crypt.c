#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "openssl-helper.h"

int main(int argc, char **argv)
{
	#define READ_SIZE 65536
	int fd;
	ssize_t r;
	int i;
	unsigned char out[32];
	unsigned char *filebuf;

	openssl_helper_initialize();

	if (argc != 2) {
		puts("Need filename");
		return 1;
	} else {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) {
			exit(EXIT_FAILURE);
		}

		filebuf = malloc(READ_SIZE);

		while ((r = read(fd, filebuf, READ_SIZE)) > 0) {
			(void) openssl_helper_pbkdf2_256_out("12345", 5, "salt", 4, 1000, out, sizeof(out));
		}

		close(fd);
		free(filebuf);
	}

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	openssl_helper_random_out(out, sizeof(out));

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	(void)openssl_helper_ofb_kuznyechik_out(OPENSSL_HELPER_ENCRYPTION, "12345678901234567890123456789012", 32, "1234567890123456", 16, "12345678901234567890123456789012", 32, out, sizeof(out));

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	void *buf;
	buf = "\x29\xec\x84\xa2\xed\x68\xc1\x4d\x1a\x01\x54\x6d\x99\xa3\x10\x32\x1f\x0e\xed\x00\x8c\x56\x7c\x9d\x8e\xf8\x7a\x29\xa2\x48\x30\x4c";
	(void)openssl_helper_ofb_kuznyechik_out(OPENSSL_HELPER_DECRYPTION, "12345678901234567890123456789012", 32, "1234567890123456", 16, buf, 32, out, sizeof(out));

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	printf("%.32s", out);
	printf("\n");

	(void)openssl_helper_ecb_kuznyechik_out(OPENSSL_HELPER_ENCRYPTION, "12345678901234567890123456789012", 32, "12345678901234567890123456789012", 32, out, sizeof(out));

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	buf = "\x18\xde\xb7\x96\xd8\x5e\xf6\x75\x23\x31\x65\x5f\xaa\x97\x25\x04\xa4\x5e\xcd\x68\xb1\x13\x7a\xfe\x15\x35\xcf\xbf\x96\xc4\x3f\xf2";
	(void)openssl_helper_ecb_kuznyechik_out(OPENSSL_HELPER_DECRYPTION, "12345678901234567890123456789012", 32, buf, 32, out, sizeof(out));

	for (i = 0; i < 32; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");

	printf("%.32s", out);
	printf("\n");

	return 0;
}
