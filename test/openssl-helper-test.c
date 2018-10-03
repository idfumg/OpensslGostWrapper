#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl-helper/openssl-helper.h>

void print_hex(const char* text, const uint8_t* data, const size_t size)
{
    printf(text);
    for (size_t i = 0; i < size; i++) {
		printf("%02x", data[i]);
	}
	printf("\n");
}

int main()
{
	openssl_helper_initialize();

    /*
      Generate private key
     */

	uint8_t privateKey[32] = {0};
    int ret = openssl_helper_keygen_256_out(privateKey,
                                            sizeof(privateKey));
    if (ret < 0) {
        printf("private key generation error: %s\n", openssl_helper_errstr);
        return 1;
    }

    print_hex("private key: ", privateKey, sizeof(privateKey));

    /*
      Generate public key from public key
     */

    uint8_t publicKey[64] = {0};
    ret = openssl_helper_compute_public_256_out(privateKey,
                                                sizeof(privateKey),
                                                publicKey,
                                                sizeof(publicKey) < 0);
    if (ret < 0) {
        printf("public key fetch error: %s\n", openssl_helper_errstr);
        return 1;
    }

    print_hex("public key: ", publicKey, sizeof(publicKey));

    /*
      Sign data with the private key
     */

    const uint8_t data[32] = "iRHr2os1j0PXz65gVf9kmnwEW2SX3hu6";
    uint8_t signature[64] = {0};
	ret = openssl_helper_sign_256_out(privateKey,
                                      sizeof(privateKey),
                                      data,
                                      sizeof(data),
                                      signature,
                                      sizeof(signature));
	if (ret < 0) {
		printf("sign error: %s\n", openssl_helper_errstr);
        return 1;
	}

    print_hex("signature: ", signature, sizeof(signature));

    /*
      Verify data signature with the public key
     */

	ret = openssl_helper_verify_256(publicKey,
                                    sizeof(publicKey),
                                    data,
                                    sizeof(data),
                                    signature,
                                    sizeof(signature));

    printf("verify with the publicKey: %s\n",
           ret < 0 ? openssl_helper_errstr : "passed");

    /*
      Verify data signature with the corrupted public key
     */

    publicKey[0] = 'j'; publicKey[1] = 'j'; publicKey[2] = 'j'; publicKey[3] = 'j';

	ret = openssl_helper_verify_256(publicKey,
                                    sizeof(publicKey),
                                    data,
                                    sizeof(data),
                                    signature,
                                    sizeof(signature));

    printf("verify with the corrupted publicKey: %s\n",
           ret < 0 ? openssl_helper_errstr : "passed");

	return 0;
}
