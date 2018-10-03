#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include "openssl-helper.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <endian.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>

__thread char *openssl_helper_errstr = NULL;

static inline void _free_p(void *p) {
	if (p && *(void **)p) {
		free(*(void **)p);
	}
}

#define _cleanup_free_p __attribute__((cleanup(_free_p)))

static inline void _openssl_free_p(void *p) {
	if (p && *(void **)p) {
		OPENSSL_free(*(void **)p);
	}
}

#define _cleanup_openssl_free_p __attribute__((cleanup(_openssl_free_p)))


static inline void _md_ctx(EVP_MD_CTX *ctx) {
	if (ctx) {
		EVP_MD_CTX_cleanup(ctx);
	}
}

#define _cleanup_md_ctx __attribute__((cleanup(_md_ctx)))

static inline void _pkey_p(EVP_PKEY **pkey) {
	if (pkey && *pkey) {
		EVP_PKEY_free(*pkey);
	}
}

#define _cleanup_pkey_p __attribute__((cleanup(_pkey_p)))

static inline void _x509_p(X509 **x509) {
	if (x509 && *x509) {
		X509_free(*x509);
	}
}

#define _cleanup_x509_p __attribute__((cleanup(_x509_p)))

static inline void _x509_req_p(X509_REQ **req) {
	if (req && *req) {
		X509_REQ_free(*req);
	}
}

#define _cleanup_x509_req_p __attribute__((cleanup(_x509_req_p)))

static inline void _x509_store_p(X509_STORE **store) {
	if (store && *store) {
		X509_STORE_free(*store);
	}
}

#define _cleanup_x509_store_p __attribute__((cleanup(_x509_store_p)))

static inline void _stack_x509_p(STACK_OF(X509) **stack) {
	if (stack && *stack) {
		sk_X509_pop_free(*stack, X509_free);
	}
}

#define _cleanup_stack_x509_p __attribute__((cleanup(_stack_x509_p)))

static inline void _x509_extension_p(X509_EXTENSION **extension) {
	if (extension && *extension) {
		X509_EXTENSION_free(*extension);
	}
}

#define _cleanup_x509_extension_p __attribute__((cleanup(_x509_extension_p)))

static inline void _cms_p(CMS_ContentInfo **cms) {
	if (cms && *cms) {
		CMS_ContentInfo_free(*cms);
	}
}

#define _cleanup_cms_p __attribute__((cleanup(_cms_p)))

static inline void _pkey_ctx_p(EVP_PKEY_CTX **ctx) {
	if (ctx && *ctx) {
		EVP_PKEY_CTX_free(*ctx);
	}
}

#define _cleanup_pkey_ctx_p __attribute__((cleanup(_pkey_ctx_p)))

static inline void _ec_group_p(EC_GROUP **group) {
	if (group && *group) {
		EC_GROUP_clear_free(*group);
	}
}

#define _cleanup_ec_group_p __attribute__((cleanup(_ec_group_p)))

static inline void _ec_point_p(EC_POINT **point) {
	if (point && *point) {
		EC_POINT_free(*point);
	}
}

#define _cleanup_ec_point_p __attribute__((cleanup(_ec_point_p)))

static inline void _ec_key_p(EC_KEY **key) {
	if (key && *key) {
		EC_KEY_free(*key);
	}
}

#define _cleanup_ec_key_p __attribute__((cleanup(_ec_key_p)))

static inline void _bn_p(BIGNUM **bn) {
	if (bn && *bn) {
		BN_free(*bn);
	}
}

#define _cleanup_bn_p __attribute__((cleanup(_bn_p)))

static inline void _bn_ctx_p(BN_CTX **ctx) {
	if (ctx && *ctx) {
		BN_CTX_free(*ctx);
	}
}

#define _cleanup_bn_ctx_p __attribute__((cleanup(_bn_ctx_p)))

static inline void _bio_p(BIO **bio) {
	if (bio && *bio) {
		BIO_free(*bio);
	}
}

#define _cleanup_bio_p __attribute__((cleanup(_bio_p)))

static inline void _hmac_ctx(HMAC_CTX *ctx) {
	if (ctx) {
		HMAC_CTX_cleanup(ctx);
	}
}

#define _cleanup_hmac_ctx __attribute__((cleanup(_hmac_ctx)))

static inline void _cmac_ctx(CMAC_CTX *ctx) {
	if (ctx) {
		CMAC_CTX_cleanup(ctx);
	}
}

#define _cleanup_cmac_ctx __attribute__((cleanup(_cmac_ctx)))

static inline void _cipher_ctx(EVP_CIPHER_CTX *ctx) {
	if (ctx) {
		EVP_CIPHER_CTX_cleanup(ctx);
	}
}

#define _cleanup_cipher_ctx __attribute__((cleanup(_cipher_ctx)))

static pthread_mutex_t *openssl_mutex;

static void locking_function(int mode, int n, const char *file, int line) {
	(void) file;
	(void) line;
	if(mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&openssl_mutex[n]);
	} else {
		pthread_mutex_unlock(&openssl_mutex[n]);
	}
}

static unsigned long id_function(void)
{
	return ((unsigned long)pthread_self());
}

static int init_locks(void) {
	openssl_mutex = malloc(CRYPTO_num_locks() * sizeof(*openssl_mutex));
	if(!openssl_mutex) {
		openssl_helper_errstr = "lock initialization failure";
		return -1;
	}
	for(int i = 0;  i < CRYPTO_num_locks();  i++) {
		pthread_mutex_init(&openssl_mutex[i], NULL);
	}
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);

	return 0;
}

static int init_rand(void) {
	struct timespec tms;
	if (clock_gettime(CLOCK_REALTIME, &tms)) {
		openssl_helper_errstr = "cannot get time for seed";
		return -1;
	}
	RAND_seed(&tms.tv_nsec, sizeof(tms.tv_nsec));

	return 0;
}

static ENGINE *engine = NULL;

static int init_engine() {
	int ret;

	OPENSSL_no_config();
	ENGINE_load_builtin_engines();
	engine = ENGINE_by_id("gost");
	if (!engine) {
		openssl_helper_errstr = "failed to get structural reference to engine";
		ret = -1;
		goto error;
	}
	if (!ENGINE_init(engine)) {
		openssl_helper_errstr = "failed to get functional reference to engine";
		ret = -1;
		goto error;
	}
	ENGINE_free(engine);
	ENGINE_set_default(engine,
	                   ENGINE_METHOD_CIPHERS | ENGINE_METHOD_DIGESTS |
	                   ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS);
	ERR_load_crypto_strings();

	ret = init_locks();
	if (ret < 0) {
		goto error;
	}
	ret = init_rand();
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	if (engine) {
		ENGINE_finish(engine);
	}
	return ret;
}

#define SN_OMP_kuznyechik_ofb "OMP-kuznyechik-ofb"
#define LN_OMP_kuznyechik_ofb "OMP-gost-3412-2015-128-ofb"

#define SN_OMP_XKU_PACKAGE_SIGNING "OMP-xku-ps"
#define LN_OMP_XKU_PACKAGE_SIGNING "OMP-xku-packageSigning"

#define SN_OMP_EXT_PACKAGE_GROUP "OMP-ext-pg"
#define LN_OMP_EXT_PACKAGE_GROUP "OMP-ext-packageGroup"

static const volatile int NID_OMP_KUZNYECHIK_OFB __attribute__ ((section (".bss")));
static const volatile int NID_OMP_XKU_PACKAGE_SIGNING __attribute__ ((section (".bss")));
static const volatile int NID_OMP_EXT_PACKAGE_GROUP __attribute__ ((section (".bss")));

int init_const(void) {
	int ret;

	*(int *)&NID_OMP_KUZNYECHIK_OFB = OBJ_create("1.2.643.2.81.1.3.1.23",
	                                             SN_OMP_kuznyechik_ofb,
	                                             LN_OMP_kuznyechik_ofb);
	*(int *)&NID_OMP_XKU_PACKAGE_SIGNING = OBJ_create("1.2.643.2.81.1.1.1",
	                                                  SN_OMP_XKU_PACKAGE_SIGNING,
	                                                  LN_OMP_XKU_PACKAGE_SIGNING);
	*(int *)&NID_OMP_EXT_PACKAGE_GROUP = OBJ_create("1.2.643.2.81.1.2.1",
	                                                  SN_OMP_EXT_PACKAGE_GROUP,
	                                                  LN_OMP_EXT_PACKAGE_GROUP);

	ret = X509V3_EXT_add_alias(NID_OMP_EXT_PACKAGE_GROUP, NID_netscape_comment);
	if (ret == 0) {
		openssl_helper_errstr = "add alias extension failure";
		return -1;
	}

	return 0;
}

static const EVP_MD *md = NULL;
static const EVP_MD *mac_kuznyechik = NULL;
static const EVP_CIPHER *ofb_kuznyechik = NULL;
static const EVP_CIPHER *ecb_kuznyechik = NULL;
static const EVP_CIPHER *cbc_kuznyechik = NULL;
static const EVP_CIPHER *gost89 = NULL;

static int (*_BN_bn2binpad)(const BIGNUM *a, unsigned char *to, int tolen);

static int _BN_bn2binpad_my(const BIGNUM *a, unsigned char *to, int tolen) {
	int len = BN_num_bytes(a);

	if (tolen < len) {
		return -1;
	}

	if (tolen > len) {
		memset(to, 0, tolen - len);
		to += tolen - len;
	}

	int _len = BN_bn2bin(a, to);
	if (_len != len) {
		return -1;
	}

	return tolen;
}

int openssl_helper_initialize(void) {
	int ret;
	static pthread_mutex_t guard = PTHREAD_MUTEX_INITIALIZER;
	static bool initialized = false;

	pthread_mutex_lock(&guard);
	if (initialized) {
		ret = 0;
		goto unlock;
	}

	ret = init_engine();
	if (ret < 0) {
		goto unlock;
	}

	ret = init_const();
	if (ret < 0) {
		goto unlock;
	}

	md = EVP_get_digestbynid(NID_id_GostR3411_2012_256);
	if (!md) {
		openssl_helper_errstr = "failed to get digest";
		ret = -1;
		goto unlock;
	}

	mac_kuznyechik = EVP_get_digestbynid(NID_grasshopper_mac);
	if (!mac_kuznyechik) {
		openssl_helper_errstr = "failed to get digest";
		ret = -1;
		goto unlock;
	}

	ofb_kuznyechik = EVP_get_cipherbynid(NID_grasshopper_ofb);
	if (!ofb_kuznyechik) {
		openssl_helper_errstr = "failed to get cipher";
		ret = -1;
		goto unlock;
	}

	ecb_kuznyechik = EVP_get_cipherbynid(NID_grasshopper_ecb);
	if (!ecb_kuznyechik) {
		openssl_helper_errstr = "failed to get cipher";
		ret = -1;
		goto unlock;
	}

	cbc_kuznyechik = EVP_get_cipherbynid(NID_grasshopper_cbc);
	if (!cbc_kuznyechik) {
		openssl_helper_errstr = "failed to get cipher";
		ret = -1;
		goto unlock;
	}

	gost89 = EVP_get_cipherbynid(NID_id_Gost28147_89);
	if (!gost89) {
		openssl_helper_errstr = "failed to get cipher";
		ret = -1;
		goto unlock;
	}

	void *handle = dlopen(NULL, RTLD_LAZY);
	_BN_bn2binpad = dlsym(handle, "BN_bn2binpad");
	if (_BN_bn2binpad == NULL) {
		_BN_bn2binpad = _BN_bn2binpad_my;
	}
	dlclose(handle);

	initialized = true;
	ret = 0;

unlock:
	pthread_mutex_unlock(&guard);
	return ret;
}

static EVP_PKEY_CTX *_pkey_ctx_new(BIGNUM *priv, BIGNUM *pub_x, BIGNUM *pub_y) {
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    EC_POINT *ecpoint = NULL;
    EC_GROUP *ecgroup = NULL;

    ecgroup = EC_GROUP_new_by_curve_name(NID_id_GostR3410_2001_CryptoPro_A_ParamSet);
    //ecgroup = EC_GROUP_new_by_curve_name(NID_id_GostR3410_2001_TestParamSet);
    if(ecgroup == NULL)
    {
        openssl_helper_errstr = "ec_group allocation failure";
        goto error;
    }

    eckey = EC_KEY_new();
    if(eckey == NULL)
    {
        openssl_helper_errstr = "ec_key allocation failure";
        goto error;
    }

    ret = EC_KEY_set_group(eckey, ecgroup);
    if(ret <= 0)
    {
        openssl_helper_errstr = "ec_key set group failure";
        goto error;
    }

    EC_GROUP_free(ecgroup);
    ecgroup = NULL;

    pkey = EVP_PKEY_new();
    if(pkey == NULL)
    {
        openssl_helper_errstr = "evp_pkey allocation failure";
        goto error;
    }

    ret = EVP_PKEY_assign(pkey, NID_id_GostR3410_2012_256, eckey);
    if(ret <= 0)
    {
        openssl_helper_errstr = "pkey assign failure";
        goto error;
    }

    ctx = EVP_PKEY_CTX_new(pkey, engine);
    if(ctx == NULL)
    {
        openssl_helper_errstr = "evp_pkey_ctx allocation failure";
        goto error;
    }

    if(priv) {
        ret = EC_KEY_set_private_key(eckey, priv);

        if (ret <= 0) {
            openssl_helper_errstr = "set private key failure";
            goto error;
        }
    }

    if(pub_x && pub_y) {
        ecpoint = EC_POINT_new(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
        if(ecpoint == NULL)
        {
            openssl_helper_errstr = "ec_point allocation failure";
            goto error;
        }

        ret = EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0((EVP_PKEY *)pkey)), ecpoint, pub_x, pub_y, NULL);
        if(ret <= 0)
        {
            openssl_helper_errstr = "ec_point set x,y failure";
            goto error;
        }

        ret = EC_KEY_set_public_key(eckey, ecpoint);
        EC_POINT_free(ecpoint);
        if(ret <= 0)
        {
            openssl_helper_errstr = "ec_key set public key failure";
            goto error;
        }
    }

    return ctx;

error:
    if(ecpoint)EC_POINT_free(ecpoint);
    if(pkey)EVP_PKEY_free(pkey);
    if(eckey)EC_KEY_free(eckey);
    if(ecgroup)EC_GROUP_clear_free(ecgroup);
    if(ctx)EVP_PKEY_CTX_free(ctx);
    return NULL;
}

int openssl_helper_digest_256_iter_out(void *buf, size_t buf_size,
                                       ssize_t (*iter)(void *buf, size_t buf_size, void *data),
                                       void *data, void *out, size_t out_size) {
	int ret;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	_cleanup_md_ctx EVP_MD_CTX ctx;

	if (out_size < OPENSSL_HELPER_GOST_DIGEST_SIZE) {
		openssl_helper_errstr = "output buffer size failure";
		return -1;
	}

	EVP_MD_CTX_init(&ctx);

	pthread_mutex_lock(&engine_guard);
	ret = EVP_DigestInit_ex(&ctx, md, engine);
	pthread_mutex_unlock(&engine_guard);
	if (ret == 0) {
		openssl_helper_errstr = "digest initialization failure";
		return -1;
	}

	ssize_t zdret;
	for (;;) {
		zdret = iter(buf, buf_size, data);
		if (zdret < 0) {
			openssl_helper_errstr = "digest iteration failed";
			return -1;
		}
		if (zdret == 0) {
			break;
		}

		ret = EVP_DigestUpdate(&ctx, buf, zdret);
		if (ret == 0) {
			openssl_helper_errstr = "digest update failure";
			return -1;
		}
	}

	unsigned int len;
	ret = EVP_DigestFinal_ex(&ctx, out, &len);
	if (ret == 0) {
		openssl_helper_errstr = "digest finalization failure";
		return -1;
	}
	if (len != out_size) {
		openssl_helper_errstr = "digest wrong size";
		return -1;
	}

	return 0;
}

static ssize_t _iter(void *buf, size_t buf_size, void *data) {
	(void) buf;

	int *count = (int *) data;
	if (*count == 0) {
		return 0;
	}

	*count = 0;
	return (ssize_t) buf_size;
}

int openssl_helper_digest_256_out(const void *buf, size_t buf_size, void *out, size_t out_size) {
	int count = 1;
	return openssl_helper_digest_256_iter_out((void *) buf, buf_size, _iter, &count, out, out_size);
}

static EVP_PKEY *_pkey_new() {
	int ret;
	_cleanup_pkey_ctx_p EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&engine_guard);
	ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, engine);
	pthread_mutex_unlock(&engine_guard);
	if (ctx == NULL) {
		openssl_helper_errstr = "evp_pkey_ctx allocation failure";
		goto error;
	}

	ret = EVP_PKEY_keygen_init(ctx);
	if (ret == 0) {
		openssl_helper_errstr = "keygen initialization failure";
		goto error;
	}

	ret = EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "A");
	if (ret <= 0) {
		openssl_helper_errstr = "paramset failure";
		goto error;
	}

	ret = EVP_PKEY_keygen(ctx, &pkey);
	if (ret == 0) {
		openssl_helper_errstr = "keygen failure";
		goto error;
	}

	return pkey;

error:
	EVP_PKEY_free(pkey);
	return NULL;
}

int openssl_helper_sign_256_out(const void *key, size_t key_size,
                                const void *buf, size_t buf_size,
                                void *out, size_t out_size) {
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *priv = NULL;
    size_t sig_size;
    int res = -1;

    priv = BN_bin2bn(key, key_size, NULL);
    if (priv == NULL) {
        openssl_helper_errstr = "convert private key failure";
        return -1;
    }

    ctx = _pkey_ctx_new(priv, NULL, NULL);
    if (ctx == NULL)
    {
        openssl_helper_errstr = "_pkey_ctx_new failure";
        goto error;
    }

    //DEBUG
    //EVP_PKEY_CTX_ctrl_str(ctx, "testmode", NULL);

    ret = EVP_PKEY_sign_init(ctx);
    if (ret == 0) {
        openssl_helper_errstr = "sign initialization failure";
        goto error;
    }

    ret = EVP_PKEY_sign(ctx, out, &sig_size, buf, buf_size);

    if (ret <=0 ) {
        openssl_helper_errstr = "sign failure";
        goto error;
    }
    if (sig_size != out_size) {
        openssl_helper_errstr = "sign output size mismatch";
        goto error;
    }

    res = 0;

error:
    if(ctx) {
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if(pkey)EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    }

    return res;
}

int openssl_helper_sign_cms_256_out(const void *key, size_t key_size,
                                    const void *cer, size_t cer_size,
                                    const void *buf, size_t buf_size,
                                    void *out, size_t out_size) {
	int ret;
	long lret;
	_cleanup_pkey_ctx_p EVP_PKEY_CTX *ctx = NULL;
	_cleanup_bn_ctx_p BN_CTX *bn_ctx = NULL;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	_cleanup_x509_p X509 *x509 = NULL;
	_cleanup_cms_p CMS_ContentInfo *cms = NULL;
	_cleanup_bn_p BIGNUM *priv = NULL;
	_cleanup_bio_p BIO *buf_bio = NULL;
	_cleanup_bio_p BIO *out_bio = NULL;
	_cleanup_ec_point_p EC_POINT *pub = NULL;
	const unsigned char *out_bio_mem = NULL;
	size_t out_bio_mem_size;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	const unsigned char *cer_buf = cer;

	out_bio = BIO_new(BIO_s_mem());
	if (out_bio == NULL) {
		openssl_helper_errstr = "bio allocation failure";
		return -1;
	}

	bn_ctx = BN_CTX_new();
	if (bn_ctx == NULL) {
		openssl_helper_errstr = "bn context allocation failure";
		return -1;
	}

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	pthread_mutex_lock(&engine_guard);
	ctx = EVP_PKEY_CTX_new(pkey, engine);
	pthread_mutex_unlock(&engine_guard);
	if (ctx == NULL) {
		openssl_helper_errstr = "evp_pkey_ctx allocation failure";
		return -1;
	}

	priv = BN_bin2bn(key, key_size, NULL);
	if (priv == NULL) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	ret = EC_KEY_set_private_key(EVP_PKEY_get0(pkey), priv);
	if (ret == 0) {
		openssl_helper_errstr = "set private key failure";
		return -1;
	}

	pub = EC_POINT_new(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
	if (pub == NULL) {
		openssl_helper_errstr = "ec point allocation failure";
		return -1;
	}

	ret = EC_POINT_mul(EC_KEY_get0_group(EVP_PKEY_get0(pkey)), pub,
	                   EC_KEY_get0_private_key(EVP_PKEY_get0(pkey)), NULL, NULL, bn_ctx);
	if (ret == 0) {
		openssl_helper_errstr = "elliptic curve multiplication failure";
		return -1;
	}

	ret = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), pub);
	if (ret == 0) {
		openssl_helper_errstr = "set public key failure";
		return -1;
	}

	x509 = d2i_X509(NULL, &cer_buf, cer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	buf_bio = BIO_new_mem_buf(buf, buf_size);
	if (buf_bio == NULL) {
		openssl_helper_errstr = "buffer bio allocation failure";
		return -1;
	}

	cms = CMS_sign(x509, pkey, NULL, buf_bio,
	               CMS_BINARY | CMS_NOSMIMECAP | CMS_USE_KEYID);
	if (cms == NULL) {
		openssl_helper_errstr = "cms signing failure";
		return -1;
	}

	ret = i2d_CMS_bio_stream(out_bio, cms, NULL, 0);
	if (ret == 0) {
		openssl_helper_errstr = "cms write failure";
		return -1;
	}

	lret = BIO_get_mem_data(out_bio, (void *) &out_bio_mem);
	if (lret <= 0) {
		openssl_helper_errstr = "get underlying bio memory failure";
		return -1;
	}
	out_bio_mem_size = lret;

	if (out_size < out_bio_mem_size) {
		openssl_helper_errstr = "cms size mismatch failure";
		return -1;
	}

	memcpy(out, out_bio_mem, out_bio_mem_size);

	return out_bio_mem_size;
}

int _public_export_out(const EVP_PKEY *pkey, void *out, size_t out_size) {
	int ret;
	_cleanup_bn_ctx_p BN_CTX *ctx = NULL;
	_cleanup_bn_p BIGNUM *x = NULL;
	_cleanup_bn_p BIGNUM *y = NULL;

	x = BN_new();
	if (x == NULL) {
		openssl_helper_errstr = "bn allocation failure";
		return -1;
	}

	y = BN_new();
	if (y == NULL) {
		openssl_helper_errstr = "bn allocation failure";
		return -1;
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		openssl_helper_errstr = "bn context allocation failure";
		return -1;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0((EVP_PKEY *) pkey)),
	                                          EC_KEY_get0_public_key(EVP_PKEY_get0((EVP_PKEY *) pkey)),
	                                          x,
	                                          y,
	                                          ctx);
	if (ret == 0) {
		openssl_helper_errstr = "get affine coordinates failure";
		return -1;
	}

	if (out_size / 2 < (unsigned int) BN_num_bytes(x) ||
	    out_size / 2 < (unsigned int) BN_num_bytes(y) ||
	    out_size % 2 != 0) {
		openssl_helper_errstr = "key size mismatch";
		return -1;
	}

	ret = _BN_bn2binpad(x, out, out_size / 2);
	if (ret < 0) {
		openssl_helper_errstr = "convert x coordinate failure";
		return -1;
	}

	ret = _BN_bn2binpad(y, (unsigned char *) out + out_size / 2, out_size / 2);
	if (ret < 0) {
		openssl_helper_errstr = "convert y coordinate failure";
		return -1;
	}

	return 0;
}

/* int openssl_helper_compute_public_256_out(const void *privateKey, */
/*                                           size_t privateKeySize, */
/*                                           void *publicKey, */
/*                                           size_t publicKeySize) */
/* { */
/*     EVP_PKEY_CTX* ctx = NULL; */
/*     BIGNUM* opensslPrivateKey = NULL; */
/*     int ret = 0; */

/*     if (publicKeySize < OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE) { */
/*         openssl_helper_errstr = "public key out size mismatch"; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       Load private key into OpenSSL structures */
/*      *\/ */
/*     opensslPrivateKey = BN_bin2bn(privateKey, privateKeySize, NULL); */
/*     if (opensslPrivateKey == NULL) { */
/*         openssl_helper_errstr = "convert private key to openssl bignum failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       Create and initialize pkey context with private key */
/*      *\/ */
/*     ctx = _pkey_ctx_new(opensslPrivateKey, NULL, NULL); */
/*     if (ctx == NULL) { */
/*         openssl_helper_errstr = "_pkey_ctx_new failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       Load public key from context as points structure */
/*       Get point y an point y fo public key from points universal structure */
/*     *\/ */
/*     EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx); */
/*     if (pkey == NULL) { */
/*         openssl_helper_errstr = "evp_pkey_ctx pkey failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* return _public_export_out(pkey, publicKey, publicKeySize); *\/ */

/*     const EC_POINT* pubkeyPoint = EC_KEY_get0_public_key(EVP_PKEY_get0(pkey)); */
/*     if (pubkeyPoint == NULL) { */
/*         openssl_helper_errstr = "retrieve public key failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     BN_CTX* bnctx = BN_CTX_new(); */
/*     if (bnctx == NULL) { */
/*         openssl_helper_errstr = "bn_ctx allocation failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       Extract x and y to public key array */
/*     *\/ */
/*     BIGNUM *pubkey_x = BN_CTX_get(bnctx); */
/*     if (pubkey_x == NULL) { */
/*         openssl_helper_errstr = "pubkey_x allocation failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     BIGNUM *pubkey_y = BN_CTX_get(bnctx); */
/*     if (pubkey_y == NULL) { */
/*         openssl_helper_errstr = "pubkey_y allocation failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     if (EC_POINT_get_affine_coordinates_GFp( */
/*             EC_KEY_get0_group( */
/*                 EVP_PKEY_get0( */
/*                     pkey)), */
/*             pubkeyPoint, */
/*             pubkey_x, */
/*             pubkey_y, */
/*             bnctx) <= 0) */
/*     { */
/*         openssl_helper_errstr = "pubkey extract failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       copy an openssl big number to the result byte array with padding if need */
/*     *\/ */
/*     if (_BN_bn2binpad( */
/*             pubkey_x, */
/*             publicKey, */
/*             publicKeySize / 2) < 0) */
/*     { */
/*         openssl_helper_errstr = "convert public key(x) failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/*     /\* */
/*       copy second part of public key data */
/*     *\/ */
/*     if (_BN_bn2binpad( */
/*             pubkey_y, */
/*             (uint8_t*)publicKey + publicKeySize / 2, */
/*             publicKeySize / 2) < 0) */
/*     { */
/*         openssl_helper_errstr = "convert public key(y) failure"; */
/*         ret = -1; */
/*         goto exit; */
/*     } */

/* exit: */
/*     /\* if (ctx) { *\/ */
/*     /\*     EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx); *\/ */
/*     /\*     if (pkey) { *\/ */
/*     /\*         EVP_PKEY_free(pkey); *\/ */
/*     /\*         pkey = NULL; *\/ */
/*     /\*     } *\/ */
/*     /\*     EVP_PKEY_CTX_free(ctx); *\/ */
/*     /\*     ctx = NULL; *\/ */
/*     /\* } *\/ */

/*     /\* if (pubkey_x) { *\/ */
/*     /\*     BN_free(pubkey_x); *\/ */
/*     /\*     pubkey_x = NULL; *\/ */
/*     /\* } *\/ */

/*     /\* if (pubkey_y) { *\/ */
/*     /\*     BN_free(pubkey_y); *\/ */
/*     /\*     pubkey_y = NULL; *\/ */
/*     /\* } *\/ */

/*     /\* if (opensslPrivateKey) { *\/ */
/*     /\*     BN_free(opensslPrivateKey); *\/ */
/*     /\*     opensslPrivateKey = NULL; *\/ */
/*     /\* } *\/ */

/*     return ret; */
/* } */

int openssl_helper_compute_public_256_out(const void *key, size_t key_size,
                                          void *out, size_t out_size) {
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    EC_GROUP *ecgroup = NULL;
    BN_CTX *bnctx = NULL;
    BIGNUM *priv = NULL;
    EC_POINT *pubkey = NULL;
    BIGNUM *pubkey_x = NULL;
    BIGNUM *pubkey_y = NULL;
    int res = -1;

    priv = BN_bin2bn(key, key_size, NULL);
    if (priv == NULL) {
        openssl_helper_errstr = "convert private key failure";
        return -1;
    }

    ctx = _pkey_ctx_new(priv, NULL, NULL);
    if (ctx == NULL) {
        return -1;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if(pkey == NULL) {
        openssl_helper_errstr = "evp_pkey_ctx pkey failure";
        goto exit;
    }

    eckey = (EC_KEY*)EVP_PKEY_get0(pkey);
    if(eckey == NULL) {
        openssl_helper_errstr = "evp_pkey eckey failure";
        goto exit;
    }

    ecgroup = (EC_GROUP*)EC_KEY_get0_group(eckey);
    if(ecgroup == NULL) {
        openssl_helper_errstr = "ec_key egroup failure";
        goto exit;
    }

    bnctx = BN_CTX_new();
    if(bnctx == NULL) {
        openssl_helper_errstr = "bn context allocation failure";
        goto exit;
    }

    pubkey = EC_POINT_new(ecgroup);
    if(pubkey == NULL) {
        openssl_helper_errstr = "ec_point allocation failure";
        goto exit;
    }

    ret = EC_POINT_mul(ecgroup, pubkey, priv, NULL, NULL, bnctx);
    if(!ret) {
        openssl_helper_errstr = "pub key compute failure";
        goto exit;
    }

    pubkey_x = BN_CTX_get(bnctx);
    if(pubkey_x == NULL) {
        openssl_helper_errstr = "pubkey_x allocation failure";
        goto exit;
    }

    pubkey_y = BN_CTX_get(bnctx);
    if(pubkey_y == NULL) {
        openssl_helper_errstr = "pubkey_y allocation failure";
        goto exit;
    }

    ret = EC_POINT_get_affine_coordinates_GFp(ecgroup, pubkey, pubkey_x, pubkey_y, bnctx);
    if(ret <= 0) {
        openssl_helper_errstr = "pubkey extract failure";
        goto exit;
    }

    ret = _BN_bn2binpad(pubkey_x, out, OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1);
    if (ret < 0) {
        openssl_helper_errstr = "convert public key(x) failure";
        goto exit;
    }

    ret = _BN_bn2binpad(pubkey_y, ((uint8_t*)out) + (OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1), OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1);
    if (ret < 0) {
        openssl_helper_errstr = "convert public key(y) failure";
        goto exit;
    }

    res = 0;

exit:
    if(bnctx)BN_CTX_free(bnctx);
    if(pubkey)EC_POINT_free(pubkey);
    if(pkey)EVP_PKEY_free(pkey);
    if(ctx)EVP_PKEY_CTX_free(ctx);
    return res;
}

int openssl_helper_verify_256(const void *key, size_t key_size,
                              const void *buf, size_t buf_size,
                              const void *sig, size_t sig_size) {
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *pubkey_x= NULL;
    BIGNUM *pubkey_y= NULL;
    int res = -1;

    if(key_size != OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE) {
        openssl_helper_errstr = "public key incorrect size";
        goto error;
    }

    pubkey_x = BN_bin2bn(key, OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1, NULL);
    if (pubkey_x == NULL) {
        openssl_helper_errstr = "convert public key(X) failure";
        goto error;
    }

    pubkey_y = BN_bin2bn(((uint8_t*)key) + (OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1), OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE >> 1, NULL);
    if (pubkey_y == NULL) {
        openssl_helper_errstr = "convert public key(X) failure";
        goto error;
    }

    ctx = _pkey_ctx_new(NULL, pubkey_x, pubkey_y);
    if (ctx == NULL)
    {
        openssl_helper_errstr = "_pkey_ctx_new failure";
        goto error;
    }

    ret = EVP_PKEY_verify_init(ctx);
    if (ret == 0) {
        openssl_helper_errstr = "verify initialization failure";
        goto error;
    }

    ret = EVP_PKEY_verify(ctx, sig, sig_size, buf, buf_size);
    if (ret <= 0) {
        openssl_helper_errstr = "verification internal failure";
        goto error;
    }
    else
        res = 0;

error:
    if(pubkey_x)BN_free(pubkey_x);
    if(pubkey_y)BN_free(pubkey_y);
    if(ctx) {
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if(pkey)EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    }

    return res;
}

int openssl_helper_verify_cms_256(const void *cms, size_t cms_size,
                                  const void *cacer, size_t cacer_size,
                                  void *data, size_t data_size) {
	int ret;
	long lret;
	_cleanup_x509_store_p X509_STORE *store = NULL;
	_cleanup_x509_p X509 *x509 = NULL;
	_cleanup_cms_p CMS_ContentInfo *icms = NULL;
	_cleanup_bio_p BIO *cms_bio = NULL;
	_cleanup_bio_p BIO *data_bio = NULL;
	_cleanup_bio_p BIO *out_bio = NULL;
	const unsigned char *out_bio_mem = NULL;
	size_t out_bio_mem_size;
	const unsigned char *buf = cacer;

	cms_bio = BIO_new_mem_buf(cms, cms_size);
	if (cms_bio == NULL) {
		openssl_helper_errstr = "bio allocation failure";
		return -1;
	}

	icms = d2i_CMS_bio(cms_bio, NULL);
	if (icms == NULL) {
		openssl_helper_errstr = "cms decode failure";
		return -1;
	}

	if (CMS_is_detached(icms)) {
		if (data == NULL) {
			openssl_helper_errstr = "detached cms signature require data failure";
			return -1;
		}

		data_bio = BIO_new_mem_buf(data, data_size);
		if (cms_bio == NULL) {
			openssl_helper_errstr = "bio allocation failure";
			return -1;
		}
	} else {
		out_bio = BIO_new(BIO_s_mem());
		if (out_bio == NULL) {
			openssl_helper_errstr = "bio allocation failure";
			return -1;
		}
	}

	if (cacer == NULL) {
		ret = CMS_verify(icms, NULL, NULL, data_bio, out_bio, CMS_NO_SIGNER_CERT_VERIFY);
		if (ret == 0) {
			return 0;
		}

		return 1;
	}

	x509 = d2i_X509(NULL, &buf, cacer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	store = X509_STORE_new();
	if (store == NULL) {
		openssl_helper_errstr = "x509 store allocation failure";
		return -1;
	}

	ret = X509_STORE_add_cert(store, x509);
	if (ret == 0) {
		openssl_helper_errstr = "x509 add to store failure";
		return -1;
	}

	ret = CMS_verify(icms, NULL, store, data_bio, out_bio, 0);
	if (ret == 0) {
		return 0;
	}

	if (!CMS_is_detached(icms) && data != NULL) {
		lret = BIO_get_mem_data(out_bio, (void *) &out_bio_mem);
		if (lret <= 0) {
			openssl_helper_errstr = "get underlying bio memory failure";
			return -1;
		}
		out_bio_mem_size = lret;

		if (data_size < out_bio_mem_size) {
			openssl_helper_errstr = "size of data mismatch failure";
			return -1;
		}

		memcpy(data, out_bio_mem, out_bio_mem_size);

		return out_bio_mem_size;
	}

	return 1;
}

int openssl_helper_keygen_256_out(void *out, size_t out_size) {
	int ret;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	const BIGNUM *priv = NULL;

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	ret = EC_KEY_generate_key(EVP_PKEY_get0(pkey));
	if (ret == 0) {
		openssl_helper_errstr = "key generation failure";
		return -1;
	}

	priv = EC_KEY_get0_private_key(EVP_PKEY_get0(pkey));
	if (priv == NULL) {
		openssl_helper_errstr = "retrieve private key failure";
		return -1;
	}

	if (out_size < OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE) {
		openssl_helper_errstr = "out size mismatch";
		return -1;
	}

	ret = _BN_bn2binpad(priv, out, OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE);
	if (ret < 0) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	return 0;
}

int openssl_helper_key_write(FILE *fp, const void *key, size_t key_size) {
	int ret;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	_cleanup_bn_p BIGNUM *priv = NULL;

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	priv = BN_bin2bn(key, key_size, NULL);
	if (priv == NULL) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	ret = EC_KEY_set_private_key(EVP_PKEY_get0(pkey), priv);
	if (ret == 0) {
		openssl_helper_errstr = "set private key failure";
		return -1;
	}

	ret = PEM_write_PrivateKey(fp, pkey, gost89, NULL, 0, NULL, NULL);
	if (ret == 0) {
		openssl_helper_errstr = "pem write private key failure";
		return -1;
	}

	return 0;
}

int openssl_helper_key_read(FILE *fp, void *key, size_t key_size) {
	int ret;
	void *pret;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	const BIGNUM *priv = NULL;

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	pret = PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
	if (pret == NULL) {
		openssl_helper_errstr = "pem read private key failure";
		return -1;
	}

	priv = EC_KEY_get0_private_key(EVP_PKEY_get0(pkey));
	if (priv == NULL) {
		openssl_helper_errstr = "retrieve private key failure";
		return -1;
	}

	if (key_size < (unsigned int) BN_num_bytes(priv)) {
		openssl_helper_errstr = "key size mismatch";
		return -1;
	}

	ret = _BN_bn2binpad(priv, key, key_size);
	if (ret < 0) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	return 0;
}

int openssl_helper_public_write(FILE *fp, const void *pub, size_t pub_size) {
	int ret;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	_cleanup_ec_point_p EC_POINT *point = NULL;
	_cleanup_bn_p BIGNUM *x= NULL;
	_cleanup_bn_p BIGNUM *y= NULL;

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	x = BN_bin2bn(pub, pub_size / 2, NULL);
	if (x == NULL) {
		openssl_helper_errstr = "convert x coordinate failure";
		return -1;
	}

	y = BN_bin2bn((unsigned char *) pub + pub_size / 2, pub_size / 2, NULL);
	if (y == NULL) {
		openssl_helper_errstr = "convert y coordinate failure";
		return -1;
	}

	point = EC_POINT_new(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
	if (point == NULL) {
		openssl_helper_errstr = "ec point allocation failure";
		return -1;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0(pkey)),
	                                          point, x, y, NULL);
	if (ret == 0) {
		openssl_helper_errstr = "set coordinates failure";
		return -1;
	}

	ret = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), point);
	if (ret == 0) {
		openssl_helper_errstr = "set public key failure";
		return -1;
	}

	ret = PEM_write_PUBKEY(fp, pkey);
	if (ret == 0) {
		openssl_helper_errstr = "pem write public key failure";
		return -1;
	}

	return 0;
}

int openssl_helper_public_read(FILE *fp, void *pub, size_t pub_size) {
	void *pret;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	pret = PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
	if (pret == NULL) {
		openssl_helper_errstr = "pem read public key failure";
		return -1;
	}

	return _public_export_out(pkey, pub, pub_size);
}

static int _certificate_export(const X509 *x509, void *cer, size_t cer_size) {
	int ret;
	_cleanup_free_p unsigned char *x509_buf = NULL;
	size_t x509_buf_size;

	ret = i2d_X509((X509 *) x509, &x509_buf);
	if (ret <= 0) {
		openssl_helper_errstr = "x509 encode failure";
		return -1;
	}
	x509_buf_size = ret;

	if (cer_size < x509_buf_size) {
		openssl_helper_errstr = "x509 size mismatch failure";
		return -1;
	}

	memcpy(cer, x509_buf, x509_buf_size);

	return x509_buf_size;
}

int openssl_helper_certificate_write(FILE *fp, const void *cer, size_t cer_size) {
	int ret;
	_cleanup_x509_p X509 *x509 = NULL;
	const unsigned char *buf = cer;

	x509 = d2i_X509(NULL, &buf, cer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	ret = PEM_write_X509(fp, x509);
	if (ret == 0) {
		openssl_helper_errstr = "x509 write failure";
		return -1;
	}

	return 0;
}

int openssl_helper_certificate_read(FILE *fp, void *cer, size_t cer_size) {
	_cleanup_x509_p X509 *x509 = NULL;

	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 read failure";
		return -1;
	}

	return _certificate_export(x509, cer, cer_size);
}

int openssl_helper_request_read(FILE *fp, void *csr, size_t csr_size) {
	int ret;
	_cleanup_x509_req_p X509_REQ *req = NULL;
	_cleanup_free_p unsigned char *csr_buf = NULL;
	size_t csr_buf_size;

	req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	if (req == NULL) {
		openssl_helper_errstr = "csr read failure";
		return -1;
	}

	ret = i2d_X509_REQ(req, &csr_buf);
	if (ret <= 0) {
		openssl_helper_errstr = "csr encode failure";
		return -1;
	}
	csr_buf_size = ret;

	if (csr_size < csr_buf_size) {
		openssl_helper_errstr = "csr size mismatch failure";
		return -1;
	}

	memcpy(csr, csr_buf, csr_buf_size);

	return csr_buf_size;
}

static int _get_cn_out(const X509_NAME *name, void *out, size_t out_size) {
	int ret;
	char cn[OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN + 1];
	size_t cn_len;

	ret = X509_NAME_get_text_by_NID((X509_NAME *) name, NID_commonName, NULL, 0);
	if (ret <= 0) {
		openssl_helper_errstr = "common name size determination failure";
		return -1;
	}
	if (ret > OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN) {
		openssl_helper_errstr = "common name limit failure";
		return -1;
	}
	if ((size_t) ret >= sizeof(cn)) {
		openssl_helper_errstr = "subject size mismatch failure";
		return -1;
	}

	ret = X509_NAME_get_text_by_NID((X509_NAME *) name, NID_commonName, cn, sizeof(cn));
	if (ret <= 0 || (size_t) ret >= sizeof(cn)) {
		openssl_helper_errstr = "subject fetch failure";
		return -1;
	}
	cn_len = ret;

	if (out_size < cn_len) {
		openssl_helper_errstr = "subject length mismatch failure";
		return -1;
	}

	memcpy(out, cn, cn_len);

	return cn_len;
}

int openssl_helper_cms_certificate_out(const void *cms, size_t cms_size,
                                       void *out, size_t out_size) {
	_cleanup_cms_p CMS_ContentInfo *icms = NULL;
	_cleanup_bio_p BIO *cms_bio = NULL;
	_cleanup_stack_x509_p STACK_OF(X509) *stack_x509 = NULL;
	const X509 *x509 = NULL;

	cms_bio = BIO_new_mem_buf(cms, cms_size);
	if (cms_bio == NULL) {
		openssl_helper_errstr = "bio allocation failure";
		return -1;
	}

	icms = d2i_CMS_bio(cms_bio, NULL);
	if (icms == NULL) {
		openssl_helper_errstr = "cms decode failure";
		return -1;
	}

	stack_x509 = CMS_get1_certs(icms);
	if (stack_x509 == NULL) {
		openssl_helper_errstr = "cms get signers failure";
		return -1;
	}
	if (sk_BIO_num(stack_x509) != 1) {
		openssl_helper_errstr = "wrong number of signers failure";
		return -1;
	}

	x509 = sk_X509_value(stack_x509, 0);

	return _certificate_export(x509, out, out_size);
}

int openssl_helper_certificate_subject_out(const void *cer, size_t cer_size,
                                           void *out, size_t out_size) {
	_cleanup_x509_p X509 *x509 = NULL;
	const unsigned char *buf = cer;

	x509 = d2i_X509(NULL, &buf, cer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	return _get_cn_out(X509_get_subject_name(x509), out, out_size);
}

int openssl_helper_certificate_keyid_out(const void *cer, size_t cer_size,
                                         void *out, size_t out_size) {
	_cleanup_x509_p X509 *x509 = NULL;
	const ASN1_OCTET_STRING *keyid = NULL;
	const unsigned char *buf = cer;
	int critical;

	x509 = d2i_X509(NULL, &buf, cer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	keyid = X509_get_ext_d2i(x509, NID_subject_key_identifier, &critical, NULL);
	if (keyid == NULL) {
		openssl_helper_errstr = "keyid fetch failure";
		return -1;
	}

	if (keyid->length <= 0) {
		openssl_helper_errstr = "keyid length failure";
		return -1;
	}
	if ((size_t) keyid->length > out_size) {
		openssl_helper_errstr = "keyid length mismatch failure";
		return -1;
	}

	memcpy(out, keyid->data, keyid->length);

	return keyid->length;
}

int openssl_helper_certificate_group_out(const void *cer, size_t cer_size,
                                         void *out, size_t out_size) {
	_cleanup_x509_p X509 *x509 = NULL;
	const EXTENDED_KEY_USAGE *ext = NULL;
	const ASN1_IA5STRING *group = NULL;
	int critical;
	bool xku = false;
	const unsigned char *buf = cer;

	x509 = d2i_X509(NULL, &buf, cer_size);
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 decode failure";
		return -1;
	}

	ext = X509_get_ext_d2i(x509, NID_ext_key_usage, &critical, NULL);
	if (ext == NULL) {
		openssl_helper_errstr = "get extension failure";
		return -1;
	}

	for (int i = 0; i < sk_ASN1_OBJECT_num(ext); ++i) {
		int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(ext, i));
		if (nid == NID_OMP_XKU_PACKAGE_SIGNING) {
			xku = true;
			break;
		}
	}
	if (!xku) {
		openssl_helper_errstr = "extended key usage does not allow package signing failure";
		return -1;
	}

	group = X509_get_ext_d2i(x509, NID_OMP_EXT_PACKAGE_GROUP, &critical, NULL);
	if (group == NULL) {
		openssl_helper_errstr = "get group extension failure";
		return -1;
	}

	if (group->length <= 0) {
		openssl_helper_errstr = "group length failure";
		return -1;
	}
	if ((size_t) group->length > out_size) {
		openssl_helper_errstr = "group length mismatch failure";
		return -1;
	}

	memcpy(out, group->data, group->length);

	return group->length;
}

int openssl_helper_request_subject_out(const void *csr, size_t csr_size,
                                       void *out, size_t out_size) {
	_cleanup_x509_req_p X509_REQ *req = NULL;
	const unsigned char *buf = csr;

	req = d2i_X509_REQ(NULL, &buf, csr_size);
	if (req == NULL) {
		openssl_helper_errstr = "req decode failure";
		return -1;
	}

	return _get_cn_out(X509_REQ_get_subject_name(req), out, out_size);
}

int openssl_helper_request_verify(const void *csr, size_t csr_size) {
	int ret;
	_cleanup_x509_req_p X509_REQ *req = NULL;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	const unsigned char *buf = csr;

	req = d2i_X509_REQ(NULL, &buf, csr_size);
	if (req == NULL) {
		openssl_helper_errstr = "req decode failure";
		return -1;
	}

	pkey = X509_REQ_get_pubkey(req);
	if (pkey == NULL) {
		openssl_helper_errstr = "pkey fetch failure";
		return -1;
	}

	ret = X509_REQ_verify(req, pkey);
	if (ret < 0) {
		openssl_helper_errstr = "csr verify failure";
		return -1;
	}

	return ret;
}

int openssl_helper_request_public_out(const void *csr, size_t csr_size,
                                      void *out, size_t out_size) {
	_cleanup_x509_req_p X509_REQ *req = NULL;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	const unsigned char *buf = csr;

	req = d2i_X509_REQ(NULL, &buf, csr_size);
	if (req == NULL) {
		openssl_helper_errstr = "req decode failure";
		return -1;
	}

	pkey = X509_REQ_get_pubkey(req);
	if (pkey == NULL) {
		openssl_helper_errstr = "pkey fetch failure";
		return -1;
	}

	return _public_export_out(pkey, out, out_size);
}

static int _nanoseconds(uint64_t *ns) {
	int ret;
	struct timespec ts;

	ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret < 0) {
		openssl_helper_errstr = "get time failure";
		return -1;
	}

	*ns = ts.tv_sec * (uint64_t) 1000000000 + ts.tv_nsec;

	return 0;
}

static int _serial(void *out, size_t out_size) {
	int ret;
	uint64_t ns;

	if (out_size < sizeof(ns)) {
		openssl_helper_errstr = "serial size mismatch failure";
		return -1;
	}

	ret = _nanoseconds(&ns);
	if (ret < 0) {
		return -1;
	}

	memcpy(out + out_size - sizeof(ns), &ns, sizeof(ns));

	if (out_size <= sizeof(ns)) {
		return 0;
	}

	ret = openssl_helper_random_out(out, out_size - sizeof(ns));
	if (ret < 0) {
		return -1;
	}

	*(unsigned char *) out &= 0x7f;

	return 0;
}

int _add_extension(X509 *cacert, X509 *cert, int nid, const char *value) {
	int ret;
	X509V3_CTX ctx;
	_cleanup_x509_extension_p X509_EXTENSION *extension = NULL;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cacert, cert, NULL, NULL, 0);

	extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *) value);
	if (!extension) {
		openssl_helper_errstr = "extension allocation failure";
		return -1;
	}

	ret = X509_add_ext(cert, extension, -1);
	if (ret == 0) {
		openssl_helper_errstr = "extension addition failure";
		return -1;
	}

	return 0;
}

int openssl_helper_makecertca_256_out(const char *issuer, const void *key, size_t key_size,
                                      void *out, size_t out_size) {
	int ret;
	void *pret;
	_cleanup_x509_p X509 *x509 = NULL;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	_cleanup_bn_p BIGNUM *priv = NULL;
	_cleanup_bn_p BIGNUM *serial = NULL;
	_cleanup_ec_point_p EC_POINT *point = NULL;
	_cleanup_bn_p BIGNUM *x= NULL;
	_cleanup_bn_p BIGNUM *y= NULL;
	unsigned char serial_buf[OPENSSL_HELPER_GOST_CERTIFICATE_SERIAL_SIZE];
	unsigned char pub[OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE];
	size_t pub_size = sizeof(pub);
	_cleanup_free_p unsigned char *x509_buf = NULL;
	size_t x509_buf_size;
	unsigned char pub_dgst[OPENSSL_HELPER_GOST_DIGEST_SIZE];
	_cleanup_openssl_free_p char *pub_dgst_hex = NULL;

	if (issuer == NULL || strlen(issuer) > OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN) {
		openssl_helper_errstr = "common name limit failure";
		return -1;
	}

	ret = openssl_helper_compute_public_256_out(key, key_size, pub, sizeof(pub));
	if (ret < 0) {
		return -1;
	}

	x509 = X509_new();
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 allocation failure";
		return -1;
	}

	X509_set_version(x509, 2);

	ret = _serial(serial_buf, sizeof(serial_buf));
	if (ret < 0) {
		return -1;
	}

	serial = BN_bin2bn(serial_buf, sizeof(serial_buf), NULL);
	if (serial == NULL) {
		openssl_helper_errstr = "serial allocation failure";
		return -1;
	}

	pret = (void *) BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x509));
	if (pret == NULL) {
		openssl_helper_errstr = "serial set failure";
		return -1;
	}

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	// 24 years
	X509_gmtime_adj(X509_get_notAfter(x509), (long) 60 * 60 * 24 * 1461 * 6);

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	priv = BN_bin2bn(key, key_size, NULL);
	if (priv == NULL) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	ret = EC_KEY_set_private_key(EVP_PKEY_get0(pkey), priv);
	if (ret == 0) {
		openssl_helper_errstr = "set private key failure";
		return -1;
	}

	x = BN_bin2bn(pub, pub_size / 2, NULL);
	if (x == NULL) {
		openssl_helper_errstr = "convert x coordinate failure";
		return -1;
	}

	y = BN_bin2bn((unsigned char *) pub + pub_size / 2, pub_size / 2, NULL);
	if (y == NULL) {
		openssl_helper_errstr = "convert y coordinate failure";
		return -1;
	}

	point = EC_POINT_new(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
	if (point == NULL) {
		openssl_helper_errstr = "ec point allocation failure";
		return -1;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0(pkey)),
	                                          point, x, y, NULL);
	if (ret == 0) {
		openssl_helper_errstr = "set coordinates failure";
		return -1;
	}

	ret = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), point);
	if (ret == 0) {
		openssl_helper_errstr = "set public key failure";
		return -1;
	}

	ret = X509_set_pubkey(x509, pkey);
	if (ret == 0) {
		openssl_helper_errstr = "set x509 public key failure";
		return -1;
	}

	X509_NAME_add_entry_by_txt(X509_get_subject_name(x509), "CN", MBSTRING_ASC, (const void *) issuer, -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_issuer_name(x509), "CN", MBSTRING_ASC, (const void *) issuer, -1, -1, 0);

	ret = _add_extension(x509, x509, NID_basic_constraints, "critical,CA:TRUE");
	if (ret < 0) {
		return -1;
	}

	ret = _add_extension(x509, x509, NID_key_usage, "critical,keyCertSign,cRLSign");
	if (ret < 0) {
		return -1;
	}

	ret = openssl_helper_digest_256_out(pub, pub_size, pub_dgst, sizeof(pub_dgst));
	if (ret < 0) {
		return -1;
	}

	pub_dgst_hex = hex_to_string(pub_dgst, sizeof(pub_dgst));
	if (pub_dgst_hex == NULL) {
		openssl_helper_errstr = "hex allocation failure";
		return -1;
	}

	ret = _add_extension(x509, x509, NID_subject_key_identifier, pub_dgst_hex);
	if (ret < 0) {
		return -1;
	}

	ret = X509_sign(x509, pkey, md);
	if (ret == 0) {
		openssl_helper_errstr = "x509 sign failure";
		return -1;
	}

	ret = i2d_X509(x509, &x509_buf);
	if (ret <= 0) {
		openssl_helper_errstr = "x509 encode failure";
		return -1;
	}
	x509_buf_size = ret;

	if (out_size < x509_buf_size) {
		openssl_helper_errstr = "x509 size mismatch failure";
		return -1;
	}

	memcpy(out, x509_buf, x509_buf_size);

	return x509_buf_size;
}

// return: 0 if not passed, 1 if passed
static int _verify(X509 *x509, EVP_PKEY *pkey) {
	int ret;
	_cleanup_pkey_p EVP_PKEY *key = NULL;

	if (pkey == NULL) {
		key = X509_get_pubkey(x509);
	}

	ret = X509_verify(x509, key);
	if (ret < 0) {
		openssl_helper_errstr = "x509 verification failure";
		return -1;
	}

	return ret;
}

int openssl_helper_makecert_256_out(const char *subject, const char *group,
                                    const void *pub, size_t pub_size,
                                    const void *key, size_t key_size,
                                    const void *cer, size_t cer_size,
                                    void *out, size_t out_size) {
	int ret;
	void *pret;
	_cleanup_x509_p X509 *x509 = NULL;
	_cleanup_x509_p X509 *cax509 = NULL;
	_cleanup_pkey_p EVP_PKEY *pkey = NULL;
	_cleanup_bn_p BIGNUM *priv = NULL;
	_cleanup_bn_p BIGNUM *serial = NULL;
	_cleanup_ec_point_p EC_POINT *point = NULL;
	_cleanup_bn_p BIGNUM *x = NULL;
	_cleanup_bn_p BIGNUM *y = NULL;
	unsigned char serial_buf[OPENSSL_HELPER_GOST_CERTIFICATE_SERIAL_SIZE];
	char *issuer = NULL;
	size_t issuer_size;
	_cleanup_free_p unsigned char *x509_buf = NULL;
	size_t x509_buf_size;
	_cleanup_free_p char *ex_key_usage = NULL;
	_cleanup_free_p char *ex_package_group= NULL;
	unsigned char pub_dgst[OPENSSL_HELPER_GOST_DIGEST_SIZE];
	_cleanup_openssl_free_p char *pub_dgst_hex = NULL;
	const unsigned char *buf = cer;

	if (subject == NULL || strlen(subject) > OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN) {
		openssl_helper_errstr = "common name limit failure";
		return -1;
	}

	x509 = X509_new();
	if (x509 == NULL) {
		openssl_helper_errstr = "x509 allocation failure";
		return -1;
	}

	X509_set_version(x509, 2);

	ret = _serial(serial_buf, sizeof(serial_buf));
	if (ret < 0) {
		return -1;
	}

	serial = BN_bin2bn(serial_buf, sizeof(serial_buf), NULL);
	if (serial == NULL) {
		openssl_helper_errstr = "serial allocation failure";
		return -1;
	}
	serial->neg = 0;

	pret = (void *) BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x509));
	if (pret == NULL) {
		openssl_helper_errstr = "serial set failure";
		return -1;
	}

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	// 24 years
	X509_gmtime_adj(X509_get_notAfter(x509), (long) 60 * 60 * 24 * 1461 * 6);

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	x = BN_bin2bn(pub, pub_size / 2, NULL);
	if (x == NULL) {
		openssl_helper_errstr = "convert x coordinate failure";
		return -1;
	}

	y = BN_bin2bn((unsigned char *) pub + pub_size / 2, pub_size / 2, NULL);
	if (y == NULL) {
		openssl_helper_errstr = "convert y coordinate failure";
		return -1;
	}

	point = EC_POINT_new(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
	if (point == NULL) {
		openssl_helper_errstr = "ec point allocation failure";
		return -1;
	}

	ret = EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0(pkey)),
	                                          point, x, y, NULL);
	if (ret == 0) {
		openssl_helper_errstr = "set coordinates failure";
		return -1;
	}

	ret = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), point);
	if (ret == 0) {
		openssl_helper_errstr = "set public key failure";
		return -1;
	}

	ret = X509_set_pubkey(x509, pkey);
	if (ret == 0) {
		openssl_helper_errstr = "set x509 public key failure";
		return -1;
	}

	EVP_PKEY_free(pkey);
	pkey = NULL;

	cax509 = d2i_X509(NULL, &buf, cer_size);
	if (cax509 == NULL) {
		openssl_helper_errstr = "x509 binary read failure";
		return -1;
	}

	ret = _verify(cax509, NULL);
	if (ret < 0) {
		return -1;
	}
	if (ret == 0) {
		openssl_helper_errstr = "not self-signed certificate failure";
		return -1;
	}

	ret = X509_NAME_get_text_by_NID(X509_get_subject_name(cax509), NID_commonName, NULL, 0);
	if (ret <= 0) {
		openssl_helper_errstr = "issuer size determination failure";
		return -1;
	}
	if (ret > OPENSSL_HELPER_GOST_CERTIFICATE_CN_MAX_LEN) {
		openssl_helper_errstr = "common name limit failure";
		return -1;
	}
	issuer_size = ret + 1;

	issuer = alloca(issuer_size);
	ret = X509_NAME_get_text_by_NID(X509_get_subject_name(cax509), NID_commonName, issuer, issuer_size);
	if (ret <= 0 || (size_t) ret >= issuer_size) {
		openssl_helper_errstr = "issuer fetch failure";
		return -1;
	}

	X509_NAME_add_entry_by_txt(X509_get_subject_name(x509), "CN", MBSTRING_ASC, (void *) subject, -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_issuer_name(x509), "CN", MBSTRING_ASC, (void *) issuer, -1, -1, 0);

	ret = _add_extension(x509, x509, NID_key_usage, "critical,digitalSignature");
	if (ret < 0) {
		return -1;
	}

	ret = openssl_helper_digest_256_out(pub, pub_size, pub_dgst, sizeof(pub_dgst));
	if (ret < 0) {
		return -1;
	}

	pub_dgst_hex = hex_to_string(pub_dgst, sizeof(pub_dgst));
	if (pub_dgst_hex == NULL) {
		openssl_helper_errstr = "hex allocation failure";
		return -1;
	}

	ret = _add_extension(cax509, x509, NID_subject_key_identifier, pub_dgst_hex);
	if (ret < 0) {
		return -1;
	}

	if (group != NULL) {
		ret = asprintf(&ex_key_usage, "critical,emailProtection,%s", LN_OMP_XKU_PACKAGE_SIGNING);
	} else {
		ret = asprintf(&ex_key_usage, "critical,emailProtection");
	}
	if (ret < 0) {
		ex_key_usage = NULL;
		openssl_helper_errstr = "extended key usage value failure";
		return -1;
	}

	ret = _add_extension(cax509, x509, NID_ext_key_usage, ex_key_usage);
	if (ret < 0) {
		return -1;
	}

	if (group != NULL) {
		ret = asprintf(&ex_package_group, "%s", group);
		if (ret < 0) {
			ex_package_group = NULL;
			openssl_helper_errstr = "package group value failure";
			return -1;
		}

		ret = _add_extension(cax509, x509, NID_OMP_EXT_PACKAGE_GROUP, ex_package_group);
		if (ret < 0) {
			return -1;
		}
	}

	pkey = _pkey_new();
	if (pkey == NULL) {
		return -1;
	}

	priv = BN_bin2bn(key, key_size, NULL);
	if (priv == NULL) {
		openssl_helper_errstr = "convert private key failure";
		return -1;
	}

	ret = EC_KEY_set_private_key(EVP_PKEY_get0(pkey), priv);
	if (ret == 0) {
		openssl_helper_errstr = "set private key failure";
		return -1;
	}

	ret = X509_sign(x509, pkey, md);
	if (ret == 0) {
		openssl_helper_errstr = "x509 sign failure";
		return -1;
	}

	ret = i2d_X509(x509, &x509_buf);
	if (ret <= 0) {
		openssl_helper_errstr = "x509 encode failure";
		return -1;
	}
	x509_buf_size = ret;

	if (out_size < x509_buf_size) {
		openssl_helper_errstr = "x509 size mismatch failure";
		return -1;
	}

	memcpy(out, x509_buf, x509_buf_size);

	return x509_buf_size;
}

int openssl_helper_hmac_256_out(const void *key, size_t key_size,
                                const void *buf, size_t buf_size,
                                void *out, size_t out_size) {
	int ret;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	_cleanup_hmac_ctx HMAC_CTX ctx;

	if (out_size < OPENSSL_HELPER_GOST_HMAC_SIZE) {
		openssl_helper_errstr = "output buffer size failure";
		return -1;
	}

	HMAC_CTX_init(&ctx);

	pthread_mutex_lock(&engine_guard);
	ret = HMAC_Init_ex(&ctx, key, key_size, md, engine);
	pthread_mutex_unlock(&engine_guard);
	if (ret == 0) {
		openssl_helper_errstr = "mac initialization failure";
		return -1;
	}

	ret = HMAC_Update(&ctx, buf, buf_size);
	if (ret == 0) {
		openssl_helper_errstr = "mac update failure";
		return -1;
	}

	unsigned int len;
	ret = HMAC_Final(&ctx, out, &len);
	if (ret == 0) {
		openssl_helper_errstr = "mac finalization failure";
		return -1;
	}
	if (len != out_size) {
		openssl_helper_errstr = "mac wrong size";
		return -1;
	}

	return 0;
}

int openssl_helper_cmac_128_out(const void *buf, size_t buf_size, void *out, size_t out_size) {
	int ret;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	_cleanup_md_ctx EVP_MD_CTX ctx;

	if (out_size < 16) {
		openssl_helper_errstr = "output buffer size failure";
		return -1;
	}

	EVP_MD_CTX_init(&ctx);

	pthread_mutex_lock(&engine_guard);
	ret = EVP_DigestInit_ex(&ctx, mac_kuznyechik, engine);
	pthread_mutex_unlock(&engine_guard);
	if (ret == 0) {
		openssl_helper_errstr = "digest initialization failure";
		return -1;
	}

	ret = EVP_DigestUpdate(&ctx, buf, buf_size);
	if (ret == 0) {
		openssl_helper_errstr = "digest update failure";
		return -1;
	}

	unsigned int len;
	ret = EVP_DigestFinal_ex(&ctx, out, &len);
	if (ret == 0) {
		openssl_helper_errstr = "digest finalization failure";
		return -1;
	}
	if (len != out_size) {
		openssl_helper_errstr = "digest wrong size";
		return -1;
	}

	return 0;
}

int openssl_helper_pbkdf2_256_out(const void *pass, size_t pass_size,
                                  const void *salt, size_t salt_size,
                                  unsigned int iter,
                                  void *out, size_t out_size) {
	int ret;

	if (out_size < OPENSSL_HELPER_PBKDF2_SIZE) {
		openssl_helper_errstr = "output buffer size failure";
		return -1;
	}

	if (iter > INT_MAX) {
		openssl_helper_errstr = "operand type failure";
		return -1;
	}

	ret = PKCS5_PBKDF2_HMAC(pass, pass_size, salt, salt_size, iter, md, out_size, out);
	if (ret == 0) {
		openssl_helper_errstr = "pbkdf2 calculation failure";
		return -1;
	}

	return 0;
}

int openssl_helper_random_out(void *out, size_t out_size) {
	int ret;

	ret = RAND_bytes(out, out_size);
	if (ret == 0) {
		openssl_helper_errstr = "rand calculation failure";
		return -1;
	}

	return 0;
}

int openssl_helper_ecb_kuznyechik_out(int direction,
                                      const void *key, size_t key_size,
                                      const void *buf, size_t buf_size,
                                      void *out, size_t out_size) {
	int ret;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	_cleanup_cipher_ctx EVP_CIPHER_CTX ctx;

	EVP_CIPHER_CTX_init(&ctx);

	if (key_size < OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE) {
		openssl_helper_errstr = "key size failure";
		return -1;
	}

	if (buf_size % OPENSSL_HELPER_ECB_KUZNYECHIK_BLOCK_SIZE != 0) {
		openssl_helper_errstr = "buf size failure";
		return -1;
	}

	if (out_size != buf_size) {
		openssl_helper_errstr = "out size failure";
		return -1;
	}

	pthread_mutex_lock(&engine_guard);
	ret = EVP_CipherInit_ex(&ctx, ecb_kuznyechik, engine, key, NULL, direction);
	pthread_mutex_unlock(&engine_guard);

	int outl;
	ret = EVP_CipherUpdate(&ctx, out, &outl, buf, buf_size);
	if (ret == 0) {
		openssl_helper_errstr = "cipher update failure";
		return -1;
	}
	if ((size_t)outl != buf_size) {
		openssl_helper_errstr = "cipher update size failure";
		return -1;
	}

	ret = EVP_CipherFinal_ex(&ctx, out + outl, &outl);
	if (ret == 0) {
		openssl_helper_errstr = "cipher final failure";
		return -1;
	}
	if(outl != 0) {
		openssl_helper_errstr = "cipher final size failure";
		return -1;
	}

	return 0;
}

int openssl_helper_ofb_kuznyechik_out(int direction,
                                      const void *key, size_t key_size,
                                      const void *iv, size_t iv_size,
                                      const void *buf, size_t buf_size,
                                      void *out, size_t out_size) {
	int ret;
	static pthread_mutex_t engine_guard = PTHREAD_MUTEX_INITIALIZER;
	_cleanup_cipher_ctx EVP_CIPHER_CTX ctx;

	EVP_CIPHER_CTX_init(&ctx);

	if (key_size < OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE) {
		openssl_helper_errstr = "key size failure";
		return -1;
	}

	if (iv_size < OPENSSL_HELPER_OFB_KUZNYECHIK_IV_SIZE) {
		openssl_helper_errstr = "iv size failure";
		return -1;
	}

	if (out_size != buf_size) {
		openssl_helper_errstr = "out size failure";
		return -1;
	}

	pthread_mutex_lock(&engine_guard);
	ret = EVP_CipherInit_ex(&ctx, ofb_kuznyechik, engine, key, iv, direction);
	pthread_mutex_unlock(&engine_guard);

	int outl;
	ret = EVP_CipherUpdate(&ctx, out, &outl, buf, buf_size);
	if (ret == 0) {
		openssl_helper_errstr = "cipher update failure";
		return -1;
	}
	if ((size_t)outl != buf_size) {
		openssl_helper_errstr = "cipher update size failure";
		return -1;
	}

	ret = EVP_CipherFinal_ex(&ctx, out + outl, &outl);
	if (ret == 0) {
		openssl_helper_errstr = "cipher final failure";
		return -1;
	}
	if(outl != 0) {
		openssl_helper_errstr = "cipher final size failure";
		return -1;
	}

	return 0;
}

size_t openssl_helper_gost_padd2(void *buf, size_t buf_size, size_t block_size)
{
	size_t padd_length;

	padd_length = block_size - (buf_size % block_size);
	if (!buf) {
		return buf_size + padd_length;
	}

	((unsigned char *)buf)[buf_size] = 0x80;
	for (size_t i = 1; i < padd_length; ++i){
		((unsigned char *)buf)[buf_size + i] = 0;
	}

	return buf_size + padd_length;
}

size_t openssl_helper_gost_padd1(void *buf, size_t buf_size, size_t block_size)
{
	size_t padd_length;

	unsigned int residue = buf_size % block_size;
	padd_length = residue > 0 ? block_size - residue : 0;
	if (!buf) {
		return buf_size + padd_length;
	}

	for (size_t i = 0; i < padd_length; ++i){
		((unsigned char *)buf)[buf_size + i] = 0;
	}

	return buf_size + padd_length;
}
