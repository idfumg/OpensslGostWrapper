#ifndef OPENSSL_HELPER_H
#define OPENSSL_HELPER_H

#include <alloca.h>
#include <stdio.h>
#include <sys/types.h>

#define OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE       32
#define OPENSSL_HELPER_KUZNYECHIK_BLOCK_SIZE     16

#define OPENSSL_HELPER_OFB_KUZNYECHIK_IV_SIZE    OPENSSL_HELPER_KUZNYECHIK_BLOCK_SIZE
#define OPENSSL_HELPER_OFB_KUZNYECHIK_BLOCK_SIZE 1

#define OPENSSL_HELPER_ECB_KUZNYECHIK_IV_SIZE    0
#define OPENSSL_HELPER_ECB_KUZNYECHIK_BLOCK_SIZE OPENSSL_HELPER_KUZNYECHIK_BLOCK_SIZE

#define OPENSSL_HELPER_GOST_DIGEST_SIZE          32
#define OPENSSL_HELPER_GOST_HMAC_KEY_SIZE        32
#define OPENSSL_HELPER_GOST_HMAC_SIZE            OPENSSL_HELPER_GOST_DIGEST_SIZE

#define OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE          32
#define OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE   64
#define OPENSSL_HELPER_GOST_SIGNATURE_SIZE              64
#define OPENSSL_HELPER_GOST_SIGNATURE_CMS_MAX_SIZE      1024

#define OPENSSL_HELPER_GOST_CERTIFICATE_MAX_SIZE        512
#define OPENSSL_HELPER_GOST_CERTIFICATE_SERIAL_SIZE     20
#define OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN      127
#define OPENSSL_HELPER_GOST_CERTIFICATE_GROUP_MAX_LEN   127
#define OPENSSL_HELPER_GOST_REQUEST_MAX_SIZE            OPENSSL_HELPER_GOST_CERTIFICATE_MAX_SIZE

#define OPENSSL_HELPER_CBC_KUZNYECHIK_BLOCK_SIZE OPENSSL_HELPER_KUZNYECHIK_BLOCK_SIZE
#define OPENSSL_HELPER_GOST_CMAC_SIZE            OPENSSL_HELPER_CBC_KUZNYECHIK_BLOCK_SIZE

#define OPENSSL_HELPER_PBKDF2_ITERATION_COUNT    1000
#define OPENSSL_HELPER_PBKDF2_SALT_SIZE          OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE
#define OPENSSL_HELPER_PBKDF2_SIZE               32

#define OPENSSL_HELPER_ENCRYPTION 1
#define OPENSSL_HELPER_DECRYPTION 0

#ifdef __cplusplus
extern "C" {
#endif

extern __thread char *openssl_helper_errstr;

int openssl_helper_initialize(void);

int openssl_helper_digest_256_iter_out(void *buf, size_t buf_size,
                                       ssize_t (*iter)(void *buf, size_t buf_size, void *data),
                                       void *data, void *out, size_t out_size);

int openssl_helper_digest_256_out(const void *buf, size_t buf_size, void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_digest_256(buf, bufsz) ({\
void*out=alloca(32);openssl_helper_digest_256_out(buf,bufsz,out,32)<0?NULL:out;})
#endif

int openssl_helper_keygen_256_out(void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_keygen_256() ({\
void*out=alloca(32);openssl_helper_keygen_256_out(out,32)<0?NULL:out;})
#endif

int openssl_helper_compute_public_256_out(const void *key, size_t key_size,
                                          void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_compute_public_256(key, keysz) ({\
void*out=alloca(64);openssl_helper_compute_public_256_out(out,64)<0?NULL:out;})
#endif

int openssl_helper_key_write(FILE *fp, const void *key, size_t key_size);

int openssl_helper_key_read(FILE *fp, void *key, size_t key_size);

int openssl_helper_public_write(FILE *fp, const void *pub, size_t pub_size);

int openssl_helper_public_read(FILE *fp, void *pub, size_t pub_size);

int openssl_helper_certificate_write(FILE *fp, const void *cer, size_t cer_size);

int openssl_helper_certificate_read(FILE *fp, void *cer, size_t cer_size);

int openssl_helper_certificate_subject_out(const void *cer, size_t cer_size,
                                           void *out, size_t out_size);

int openssl_helper_certificate_keyid_out(const void *cer, size_t cer_size,
                                         void *out, size_t out_size);

int openssl_helper_certificate_group_out(const void *cer, size_t cer_size,
                                         void *out, size_t out_size);

int openssl_helper_request_read(FILE *fp, void *csr, size_t csr_size);

/*
 * returns 1 if passed, 0 if not passed, -1 on error
 */
int openssl_helper_request_verify(const void *csr, size_t csr_size);

int openssl_helper_request_subject_out(const void *csr, size_t csr_size,
                                       void *out, size_t out_size);

int openssl_helper_request_public_out(const void *csr, size_t csr_size,
                                      void *out, size_t out_size);

int openssl_helper_makecertca_256_out(const char *issuer,  const void *key, size_t key_size,
                                      void *out, size_t out_size);

int openssl_helper_makecert_256_out(const char *subject, const char *group,
                                    const void *pub, size_t pub_size,
                                    const void *key, size_t key_size,
                                    const void *cer, size_t cer_size,
                                    void *out, size_t out_size);

int openssl_helper_sign_256_out(const void *key, size_t key_size,
                                const void *buf, size_t buf_size,
                                void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_sign_256(key, keysz, buf, bufsz) ({\
void*out=alloca(32);openssl_helper_sign_256_out(key,keysz,buf,bufsz,out,32)<0?NULL:out;})
#endif

int openssl_helper_sign_cms_256_out(const void *key, size_t key_size,
                                    const void *cer, size_t cer_size,
                                    const void *buf, size_t buf_size,
                                    void *out, size_t out_size);

/*
 * returns 1 if passed, 0 if not passed, -1 on error
 */
int openssl_helper_verify_256(const void *pub, size_t pub_size,
                              const void *buf, size_t buf_size,
                              const void *sig, size_t sig_size);

/*
 * returns 1 or size of data if passed, 0 if not passed, -1 on error
 */
int openssl_helper_verify_cms_256(const void *cms, size_t cms_size,
                                  const void *cacer, size_t cacer_size,
                                  void *data, size_t data_size);

int openssl_helper_cms_certificate_out(const void *cms, size_t cms_size,
                                       void *out, size_t out_size);

int openssl_helper_hmac_256_out(const void *key, size_t key_size, const void *buf, size_t buf_size, void *hash, size_t hash_size);

#ifdef __GNUC__
#define openssl_helper_hmac_256(key, keysz, buf, bufsz) ({\
void*out=alloca(32);if(openssl_helper_hmac_256_out(key,keysz,buf,bufsz,out,32)<0)?NULL:out;})
#endif

int openssl_helper_cmac_128_out(const void *buf, size_t buf_size, void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_cmac_128(key, keysz, buf, bufsz) ({\
void*out=alloca(16);if(openssl_helper_cmac_128_out(key,keysz,buf,bufsz,out,16)<0)?NULL:out;})
#endif

int openssl_helper_pbkdf2_256_out(const void *pass, size_t pass_size,
                                  const void *salt, size_t salt_size,
                                  unsigned int iter,
                                  void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_pbkdf2_256(pass, passsz, salt, saltsz, iter) ({\
void*out=alloca(32);if(openssl_helper_pbkdf2_256_out(pass,passsz,salt,saltsz,iter,out,32)<0)?NULL:out;})
#endif

int openssl_helper_random_out(void *out, size_t out_size);

#ifdef __GNUC__
#define openssl_helper_random_256() ({\
void*out=alloca(32);if(openssl_helper_random_out(out,32)<0)?NULL:out;})
#endif

int openssl_helper_ofb_kuznyechik_out(int direction,
                                      const void *key, size_t key_size,
                                      const void *iv, size_t iv_size,
                                      const void *buf, size_t buf_size,
                                      void *out, size_t out_size);

int openssl_helper_ecb_kuznyechik_out(int direction,
                                      const void *key, size_t key_size,
                                      const void *buf, size_t buf_size,
                                      void *out, size_t out_size);

size_t openssl_helper_gost_padd1(void *buf, size_t buf_size, size_t block_size);

size_t openssl_helper_gost_padd2(void *buf, size_t buf_size, size_t block_size);

#ifdef __cplusplus
}
#endif

#endif // OPENSSL_HELPER_H
