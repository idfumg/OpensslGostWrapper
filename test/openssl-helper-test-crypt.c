#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "openssl-helper.h"

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
      Generate random salt
     */

    uint8_t salt[32] = {0};
    int ret = openssl_helper_random_out(salt, sizeof(salt));
    if (ret < 0) {
        printf("random error: %s\n", openssl_helper_errstr);
        return 1;
    }

    print_hex("random: ", salt, sizeof(salt));

    /*
      Generate key with the key derivation function with random salt for strong crypto
     */

    const uint8_t password[] = "12345";
    const uint16_t iterations = 1000;
    uint8_t key[32] = {0};
    ret = openssl_helper_pbkdf2_256_out(password,
                                        sizeof(password),
                                        salt,
                                        sizeof(salt),
                                        iterations,
                                        key,
                                        sizeof(key));
    if (ret < 0) {
        printf("pbkdf2 error: %s\n", openssl_helper_errstr);
        return 1;
    }

    print_hex("pbkdf2: ", key, sizeof(key));

    /*
      Encrypt buf with random iv and generated key
     */

    const uint8_t iv[16] = "c0M2eicdmI4sYyEK";
    const uint8_t buf[] = "oGFLcJ0sEqd1lyiumcLhqQIugdUZWT9u";
    uint8_t encrypted[sizeof(buf)] = {0};

	ret = openssl_helper_ofb_kuznyechik_out(OPENSSL_HELPER_ENCRYPTION,
                                            key,
                                            sizeof(key),
                                            iv,
                                            sizeof(iv),
                                            buf,
                                            sizeof(buf),
                                            encrypted,
                                            sizeof(encrypted));
    if (ret < 0) {
        printf("ofb_kuznyechik error: %s\n", openssl_helper_errstr);
        return 1;
    }

	print_hex("ofb_kuznyechik: ", encrypted, sizeof(encrypted));

	return 0;
}
