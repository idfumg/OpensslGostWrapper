#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "openssl-helper.h"

int main()
{
	unsigned char out[32] = "iRHr2os1j0PXz65gVf9kmnwEW2SX3hu6";
	unsigned char sig[64];

	openssl_helper_initialize();

	unsigned char key[32];
	openssl_helper_keygen_256_out(key, sizeof(key));

    printf("private key: ");
    for (int i = 0; i < 32; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");

    uint8_t publicKey[32] = {0};
    if (openssl_helper_compute_public_256_out(
            key,
            sizeof(key),
            publicKey,
            sizeof(publicKey) < 0))
    {
        printf("public key fetch error: %s\n", openssl_helper_errstr);
        return 1;
    }

    printf("public key: ");
    for (size_t i = 0; i < sizeof(publicKey); i++) {
		printf("%02x", publicKey[i]);
	}
	printf("\n");

	const int ret =
        openssl_helper_sign_256_out(
            key,
            sizeof(key),
            out,
            sizeof(out),
            sig,
            sizeof(sig));

	if (ret < 0) {
		printf("sign error: %s\n", openssl_helper_errstr);
        return 1;
	}

    printf("signature: ");
	for (int i = 0; i < 64; i++) {
		printf("%02x", sig[i]);
	}
	printf("\n");

    /* sig[0] = 'j'; */
    /* sig[1] = 'j'; */
    /* sig[2] = 'j'; */

    /* key[0] = 'j'; */
    /* key[1] = 'j'; */

	const int ret2 =
        openssl_helper_verify_256(
            publicKey,
            sizeof(publicKey),
            out,
            sizeof(out),
            sig,
            sizeof(sig));

    printf("ret2 = %d\n", ret2);
	if (ret2 == 0) {
		printf("verify passed\n");
	} else {
		printf("verify not passed\n");
	}

	return 0;
}
