/**
 * @file /cryptron/ecies.c
 *
 * @brief ECIES encryption/decryption functions.
 *
 * $Author: Ladar Levison $
 * $Website: http://lavabit.com $
 *
 */

#include "ies.h"

#define SET_ERROR(string) \
    sprintf(error, "%s %s:%d", (string), __FILE__, __LINE__)
#define SET_OSSL_ERROR(string) \
    sprintf(error, "%s {error = %s} %s:%d", (string), ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__)

static void * ecies_key_derivation(const void *input, size_t ilen, void *output, size_t *olen) {

    if (*olen < SHA512_DIGEST_LENGTH) {
	return NULL;
    }

    *olen = SHA512_DIGEST_LENGTH;
    return SHA512(input, ilen, output);
}

static EC_KEY * ecies_key_create(const EC_KEY *user, char *error) {

    const EC_GROUP *group;
    EC_KEY *key = NULL;

    if (!(key = EC_KEY_new())) {
	SET_OSSL_ERROR("EC_KEY_new failed");
	return NULL;
    }

    if (!(group = EC_KEY_get0_group(user))) {
	SET_ERROR("The user key does not have group");
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_group(key, group) != 1) {
	SET_OSSL_ERROR("EC_KEY_set_group failed");
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_generate_key(key) != 1) {
	SET_OSSL_ERROR("EC_KEY_generate_key failed");
	EC_KEY_free(key);
	return NULL;
    }

    return key;
}

static unsigned char *prepare_envelope_key(const ies_ctx_t *ctx, cryptogram_t *cryptogram, char *error)
{
    unsigned char *envelope_key;
    EC_KEY *ephemeral;
    size_t written_length;

    if ((envelope_key = malloc(ctx->KDF_digest_length)) == NULL) {
	SET_ERROR("Failed to allocate memory for envelope_key");
	return NULL;
    }

    // Create the ephemeral key
    if (!(ephemeral = ecies_key_create(ctx->user_key, error))) {
	free(envelope_key);
	return NULL;
    }

    // key agreement + KDF
    if (ECDH_compute_key(envelope_key,
			 ctx->KDF_digest_length,
			 EC_KEY_get0_public_key(ctx->user_key),
			 ephemeral,
			 ecies_key_derivation) != (int)ctx->KDF_digest_length) {
	SET_OSSL_ERROR("An error occurred while trying to compute the envelope key");
	free(envelope_key);
	EC_KEY_free(ephemeral);
	return NULL;
    }


    // Store the public key portion of the ephemeral key.

    written_length = EC_POINT_point2oct(
	EC_KEY_get0_group(ephemeral),
	EC_KEY_get0_public_key(ephemeral),
	POINT_CONVERSION_COMPRESSED,
	(void *)cryptogram_key_data(cryptogram),
	ctx->envelope_key_length,
	NULL);
    if (written_length == 0) {
	SET_OSSL_ERROR("Error while recording the public portion of the envelope key");
	free(envelope_key);
	EC_KEY_free(ephemeral);
	return NULL;
    }
    if (written_length != ctx->envelope_key_length) {
	SET_ERROR("Written envelope key length does not match with expected");
	free(envelope_key);
	EC_KEY_free(ephemeral);
	return NULL;
    }

    EC_KEY_free(ephemeral);

    return envelope_key;
}

static int store_cipher_body(
    const ies_ctx_t *ctx,
    const unsigned char *envelope_key,
    const unsigned char *data,
    size_t length,
    cryptogram_t *cryptogram,
    char *error)
{
    int out_len, len_sum = 0;
    size_t expected_len = cryptogram_body_length(cryptogram);
    unsigned char iv[EVP_MAX_IV_LENGTH];
    EVP_CIPHER_CTX cipher;
    unsigned char *body;

    // For now we use an empty initialization vector.
    memset(iv, 0, EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX_init(&cipher);
    body = cryptogram_body_data(cryptogram);

    if (EVP_EncryptInit_ex(&cipher, ctx->cipher, NULL, envelope_key, iv) != 1
	|| EVP_EncryptUpdate(&cipher, body, &out_len, data, length) != 1) {
	SET_OSSL_ERROR("Error while trying to secure the data using the symmetric cipher");
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 0;
    }

    if (expected_len < (size_t)out_len) {
	SET_ERROR("The symmetric cipher overflowed");
	EVP_CIPHER_CTX_cleanup(&cipher);
	return 0;
    }

    body += out_len;
    len_sum += out_len;
    if (EVP_EncryptFinal_ex(&cipher, body, &out_len) != 1) {
	SET_OSSL_ERROR("Error while finalizing the data using the symmetric cipher");
	EVP_CIPHER_CTX_cleanup(&cipher);
	cryptogram_free(cryptogram);
	return 0;
    }

    EVP_CIPHER_CTX_cleanup(&cipher);

    if (expected_len < (size_t)len_sum) {
	SET_ERROR("The symmetric cipher overflowed");
	return 0;
    }

    return 1;
}

static int store_mac_tag(const ies_ctx_t *ctx, const unsigned char *envelope_key, cryptogram_t *cryptogram, char *error) {
    const size_t key_length = EVP_CIPHER_key_length(ctx->cipher);
    const size_t mac_length = cryptogram_mac_length(cryptogram);
    unsigned int out_len;
    HMAC_CTX hmac;

    HMAC_CTX_init(&hmac);

    // Generate hash tag using encrypted data
    if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ctx->md, NULL) != 1
	|| HMAC_Update(&hmac, cryptogram_body_data(cryptogram), cryptogram_body_length(cryptogram)) != 1
	|| HMAC_Final(&hmac, cryptogram_mac_data(cryptogram), &out_len) != 1) {
	SET_OSSL_ERROR("Unable to generate tag");
	HMAC_CTX_cleanup(&hmac);
	return 0;
    }

    HMAC_CTX_cleanup(&hmac);

    if (out_len != mac_length) {
	SET_ERROR("MAC length expectation does not meet");
	return 0;
    }

    return 1;
}

cryptogram_t * ecies_encrypt(const ies_ctx_t *ctx, const unsigned char *data, size_t length, char *error) {

    const size_t block_length = EVP_CIPHER_block_size(ctx->cipher);
    const size_t key_length = EVP_CIPHER_key_length(ctx->cipher);
    const size_t mac_length = EVP_MD_size(ctx->md);
    cryptogram_t *cryptogram;
    unsigned char *envelope_key;

    if (!ctx || !data || !length) {
	SET_ERROR("Invalid arguments");
	return NULL;
    }

    if (block_length == 0 || block_length > EVP_MAX_BLOCK_LENGTH) {
	SET_ERROR("Derived block size is incorrect");
	return NULL;
    }

    // Make sure we are generating enough key material for the symmetric ciphers.
    if (key_length * 2 > ctx->KDF_digest_length) {
	SET_ERROR("The key derivation method will not produce enough envelope key material for the chosen ciphers");
	return NULL;
    }

    cryptogram = cryptogram_alloc(ctx->envelope_key_length,
				  mac_length,
				  length + (length % block_length ? (block_length - (length % block_length)) : 0));
    if (!cryptogram) {
	SET_ERROR("Unable to allocate a cryptogram_t buffer to hold the encrypted result.");
	return NULL;
    }

    if ((envelope_key = prepare_envelope_key(ctx, cryptogram, error)) == NULL) {
	cryptogram_free(cryptogram);
	return NULL;
    }

    if (!store_cipher_body(ctx, envelope_key, data, length, cryptogram, error)) {
	cryptogram_free(cryptogram);
	free(envelope_key);
	return NULL;
    }

    if (!store_mac_tag(ctx, envelope_key, cryptogram, error)) {
	cryptogram_free(cryptogram);
	free(envelope_key);
	return NULL;
    }

    return cryptogram;
}

static EC_KEY *ecies_key_create_public_octets(EC_KEY *user, unsigned char *octets, size_t length, char *error) {

    EC_KEY *key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    if (!(key = EC_KEY_new())) {
	SET_OSSL_ERROR("Cannot create instance for ephemeral key");
	return NULL;
    }

    if (!(group = EC_KEY_get0_group(user))) {
	SET_ERROR("Cannot get group from user key");
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_group(key, group) != 1) {
	SET_OSSL_ERROR("EC_KEY_set_group failed");
	EC_KEY_free(key);
	return NULL;
    }

    if (!(point = EC_POINT_new(group))) {
	SET_OSSL_ERROR("EC_POINT_new failed");
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_POINT_oct2point(group, point, octets, length, NULL) != 1) {
	SET_OSSL_ERROR("EC_POINT_oct2point failed");
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_public_key(key, point) != 1) {
	SET_OSSL_ERROR("EC_KEY_set_public_key failed");
	EC_POINT_free(point);
	EC_KEY_free(key);
	return NULL;
    }

    EC_POINT_free(point);

    if (EC_KEY_check_key(key) != 1) {
	SET_OSSL_ERROR("EC_KEY_check_key failed");
	EC_KEY_free(key);
	return NULL;
    }

    return key;
}

unsigned char *restore_envelope_key(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, char *error)
{
    EC_KEY *ephemeral, *user_copy;
    unsigned char *envelope_key;

    if ((envelope_key = malloc(ctx->KDF_digest_length)) == NULL) {
	SET_ERROR("Failed to allocate memory for envelope_key");
	return NULL;
    }

    if (!(user_copy = EC_KEY_new())) {
	SET_OSSL_ERROR("Failed to create instance for user key copy");
	free(envelope_key);
	return NULL;
    }

    if (!(EC_KEY_copy(user_copy, ctx->user_key))) {
	SET_OSSL_ERROR("Failed to copy user key");
	EC_KEY_free(user_copy);
	free(envelope_key);
	return NULL;
    }

    if (!(ephemeral = ecies_key_create_public_octets(user_copy, cryptogram_key_data(cryptogram), cryptogram_key_length(cryptogram), error))) {
	EC_KEY_free(user_copy);
	free(envelope_key);
	return NULL;
    }

    // Use the intersection of the provided keys to generate the envelope data
    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(ephemeral), user_copy, ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
	SET_OSSL_ERROR("Error while computing the envelope key");
	EC_KEY_free(ephemeral);
	EC_KEY_free(user_copy);
	free(envelope_key);
	return NULL;
    }

    EC_KEY_free(user_copy);
    EC_KEY_free(ephemeral);

    return envelope_key;
}

static int verify_mac(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, const unsigned char * envelope_key, char *error)
{
    const size_t key_length = EVP_CIPHER_key_length(ctx->cipher);
    const size_t mac_length = cryptogram_mac_length(cryptogram);
    unsigned int out_len;
    HMAC_CTX hmac;
    unsigned char md[EVP_MAX_MD_SIZE];

    HMAC_CTX_init(&hmac);

    // Generate hash tag using encrypted data
    if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ctx->md, NULL) != 1
	|| HMAC_Update(&hmac, cryptogram_body_data(cryptogram), cryptogram_body_length(cryptogram)) != 1
	|| HMAC_Final(&hmac, md, &out_len) != 1) {
	SET_OSSL_ERROR("Unable to generate tag");
	HMAC_CTX_cleanup(&hmac);
	return 0;
    }

    HMAC_CTX_cleanup(&hmac);

    if (out_len != mac_length) {
	SET_ERROR("MAC length expectation does not meet");
	return 0;
    }

    if (memcmp(md, cryptogram_mac_data(cryptogram), mac_length) != 0) {
	SET_ERROR("MAC tag verification failed");
	return 0;
    }

    return 1;
}

unsigned char *decrypt_body(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, const unsigned char *envelope_key, size_t *length, char *error)
{
    int out_len;
    size_t output_sum;
    const size_t body_length = cryptogram_body_length(cryptogram);
    unsigned char iv[EVP_MAX_IV_LENGTH], *block, *output;
    EVP_CIPHER_CTX cipher;

    if (!(output = malloc(body_length + 1))) {
	SET_ERROR("Failed to allocate memory for clear text");
	return NULL;
    }

    // For now we use an empty initialization vector
    memset(iv, 0, EVP_MAX_IV_LENGTH);
    memset(output, 0, body_length + 1);

    EVP_CIPHER_CTX_init(&cipher);

    block = output;
    // Decrypt the data using the chosen symmetric cipher.
    if (EVP_DecryptInit_ex(&cipher, ctx->cipher, NULL, envelope_key, iv) != 1
	|| EVP_DecryptUpdate(&cipher, block, &out_len, cryptogram_body_data(cryptogram), body_length) != 1) {
	SET_OSSL_ERROR("Unable to decrypt");
	EVP_CIPHER_CTX_cleanup(&cipher);
	free(output);
	return NULL;
    }
    output_sum = out_len;

    block += output_sum;
    if (EVP_DecryptFinal_ex(&cipher, block, &out_len) != 1) {
	printf("Unable to decrypt the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EVP_CIPHER_CTX_cleanup(&cipher);
	free(output);
	return NULL;
    }
    output_sum += out_len;

    EVP_CIPHER_CTX_cleanup(&cipher);

    *length = output_sum;

    return output;
}

unsigned char * ecies_decrypt(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, size_t *length, char *error)
{

    unsigned char *envelope_key, *output;

    if (!ctx || !cryptogram || !length || !error) {
	SET_ERROR("Invalid argument");
	return NULL;
    }

    // Make sure we are generating enough key material for the symmetric ciphers.
    if ((unsigned)EVP_CIPHER_key_length(ctx->cipher) * 2 > ctx->KDF_digest_length) {
	SET_ERROR("The key derivation method will not produce enough envelope key material for the chosen ciphers");
	return NULL;
    }

    envelope_key = restore_envelope_key(ctx, cryptogram, error);
    if (envelope_key == NULL) {
	return NULL;
    }

    if (!verify_mac(ctx, cryptogram, envelope_key, error)) {
	free(envelope_key);
	return NULL;
    }

    if ((output = decrypt_body(ctx, cryptogram, envelope_key, length, error)) == NULL) {
	free(envelope_key);
	return NULL;
    }

    free(envelope_key);

    return output;
}
