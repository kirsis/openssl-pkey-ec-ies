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

static void * ecies_key_derivation(const void *input, size_t ilen, void *output, size_t *olen) {

    if (*olen < SHA512_DIGEST_LENGTH) {
	return NULL;
    }

    *olen = SHA512_DIGEST_LENGTH;
    return SHA512(input, ilen, output);
}

static EC_KEY * ecies_key_create(const EC_KEY *user) {

    const EC_GROUP *group;
    EC_KEY *key = NULL;

    if (!(key = EC_KEY_new())) {
	printf("EC_KEY_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }

    if (!(group = EC_KEY_get0_group(user))) {
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_group(key, group) != 1) {
	printf("EC_KEY_set_group failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_generate_key(key) != 1) {
	printf("EC_KEY_generate_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    return key;
}

cryptogram_t * ecies_encrypt(const EC_KEY *user, const unsigned char *data, size_t length) {

    const EVP_CIPHER * ECIES_CIPHER = EVP_aes_128_cbc();
    const EVP_MD * ECIES_HASHER = EVP_sha1();
    unsigned char *body;
    HMAC_CTX hmac;
    int body_length;
    size_t mac_length, envelope_length, block_length, key_length;
    cryptogram_t *cryptogram;
    EVP_CIPHER_CTX cipher;
    EC_KEY *ephemeral;
    unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], block[EVP_MAX_BLOCK_LENGTH];

    // Simple sanity check.
    if (!user || !data || !length) {
	printf("Invalid parameters passed in.\n");
	return NULL;
    }

    // Make sure we are generating enough key material for the symmetric ciphers.
    if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
	printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %d / required = %zu}", SHA512_DIGEST_LENGTH / 8,
	       (key_length * 2) / 8);
	return NULL;
    }

    // Create the ephemeral key used specifically for this block of data.
    if (!(ephemeral = ecies_key_create(user))) {
	printf("An error occurred while trying to generate the ephemeral key.\n");
	return NULL;
    }

    // Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
    // SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(user), ephemeral, ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
	printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(ephemeral);
	return NULL;
    }

    // Determine the envelope and block lengths so we can allocate a buffer for the result.
    if ((block_length = EVP_CIPHER_block_size(ECIES_CIPHER)) == 0
	|| block_length > EVP_MAX_BLOCK_LENGTH
	|| (envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral),
						 EC_KEY_get0_public_key(ephemeral),
						 POINT_CONVERSION_COMPRESSED,
						 NULL, 0, NULL)) == 0) {
	printf("Invalid block or envelope length. {block = %zu / envelope = %zu}\n", block_length, envelope_length);
	EC_KEY_free(ephemeral);
	return NULL;
    }

    // We use a conditional to pad the length if the input buffer is not evenly divisible by the block size.
    if (!(cryptogram = cryptogram_alloc(envelope_length,
					EVP_MD_size(ECIES_HASHER),
					length + (length % block_length ? (block_length - (length % block_length)) : 0)))) {
	printf("Unable to allocate a cryptogram_t buffer to hold the encrypted result.\n");
	EC_KEY_free(ephemeral);
	return NULL;
    }

    // Store the public key portion of the ephemeral key.
    {
	size_t written_length = EC_POINT_point2oct(
	    EC_KEY_get0_group(ephemeral),
	    EC_KEY_get0_public_key(ephemeral),
	    POINT_CONVERSION_COMPRESSED,
	    (void *)cryptogram_key_data(cryptogram),
	    envelope_length,
	    NULL);
	if (written_length != envelope_length) {
	    printf("An error occurred while trying to record the public portion of the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	    EC_KEY_free(ephemeral);
	    cryptogram_free(cryptogram);
	    return NULL;
	}
    }

    // The envelope key has been stored so we no longer need to keep the keys around.
    EC_KEY_free(ephemeral);

    // For now we use an empty initialization vector.
    memset(iv, 0, EVP_MAX_IV_LENGTH);

    // Setup the cipher context, the body length, and store a pointer to the body buffer location.
    EVP_CIPHER_CTX_init(&cipher);
    body = cryptogram_body_data(cryptogram);
    body_length = cryptogram_body_length(cryptogram);

    // Initialize the cipher with the envelope key.
    if (EVP_EncryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1
	|| EVP_EncryptUpdate(&cipher, body, &body_length, data, length) != 1) {
	printf("An error occurred while trying to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EVP_CIPHER_CTX_cleanup(&cipher);
	cryptogram_free(cryptogram);
	return NULL;
    }

    // Advance the pointer, then use pointer arithmetic to calculate how much of the body buffer has been used. The complex logic is needed so that we get
    // the correct status regardless of whether there was a partial data block.
    body += body_length;
    if ((body_length = cryptogram_body_length(cryptogram) - (body - cryptogram_body_data(cryptogram))) < 0) {
	printf("The symmetric cipher overflowed!\n");
	EVP_CIPHER_CTX_cleanup(&cipher);
	cryptogram_free(cryptogram);
	return NULL;
    }

    if (EVP_EncryptFinal_ex(&cipher, body, &body_length) != 1) {
	printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EVP_CIPHER_CTX_cleanup(&cipher);
	cryptogram_free(cryptogram);
	return NULL;
    }

    EVP_CIPHER_CTX_cleanup(&cipher);

    // Generate an authenticated hash which can be used to validate the data during decryption.
    HMAC_CTX_init(&hmac);
    mac_length = cryptogram_mac_length(cryptogram);

    // At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
    {
	unsigned int length;
	if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1
	    || HMAC_Update(&hmac, cryptogram_body_data(cryptogram), cryptogram_body_length(cryptogram)) != 1
	    || HMAC_Final(&hmac, cryptogram_mac_data(cryptogram), &length) != 1
	    || length != mac_length) {
	    printf("Unable to generate a data authentication code. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	    HMAC_CTX_cleanup(&hmac);
	    cryptogram_free(cryptogram);
	    return NULL;
	}
    }

    HMAC_CTX_cleanup(&hmac);

    return cryptogram;
}

static EC_KEY *ecies_key_create_public_octets(EC_KEY *user, unsigned char *octets, size_t length) {

    EC_KEY *key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    if (!(key = EC_KEY_new())) {
	printf("EC_KEY_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }

    if (!(group = EC_KEY_get0_group(user))) {
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_group(key, group) != 1) {
	printf("EC_KEY_set_group failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    if (!(point = EC_POINT_new(group))) {
	printf("EC_POINT_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_POINT_oct2point(group, point, octets, length, NULL) != 1) {
	printf("EC_POINT_oct2point failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    if (EC_KEY_set_public_key(key, point) != 1) {
	printf("EC_KEY_set_public_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_POINT_free(point);
	EC_KEY_free(key);
	return NULL;
    }

    EC_POINT_free(point);

    if (EC_KEY_check_key(key) != 1) {
	printf("EC_KEY_check_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(key);
	return NULL;
    }

    return key;
}

unsigned char * ecies_decrypt(const EC_KEY *user, cryptogram_t *cryptogram, size_t *length) {

    const EVP_CIPHER * ECIES_CIPHER = EVP_aes_128_cbc();
    const EVP_MD * ECIES_HASHER = EVP_sha1();
    size_t key_length, output_sum, body_length;
    int out_len;
    EVP_CIPHER_CTX cipher;
    EC_KEY *ephemeral, *user_copy;
    unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], md[EVP_MAX_MD_SIZE], *block, *output;

    // Simple sanity check.
    if (!user || !cryptogram || !length) {
	printf("Invalid parameters passed in.\n");
	return NULL;
    }

    // Make sure we are generating enough key material for the symmetric ciphers.
    if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
	printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}",
	       SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
	return NULL;
    }

    if (!(user_copy = EC_KEY_new())) {
	return NULL;
    }

    if (!(EC_KEY_copy(user_copy, user))) {
	EC_KEY_free(user_copy);
	return NULL;
    }

    // Create the ephemeral key used specifically for this block of data.
    if (!(ephemeral = ecies_key_create_public_octets(user_copy, cryptogram_key_data(cryptogram), cryptogram_key_length(cryptogram)))) {
	printf("An error occurred while trying to recreate the ephemeral key.\n");
	EC_KEY_free(user_copy);
	return NULL;
    }

    // Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
    // SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(ephemeral), user_copy, ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
	printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	EC_KEY_free(user_copy);
	EC_KEY_free(ephemeral);
	return NULL;
    }

    // The envelope key material has been extracted, so we no longer need the user and ephemeral keys.
    EC_KEY_free(user_copy);
    EC_KEY_free(ephemeral);

    {
	HMAC_CTX hmac;
	unsigned int out_length;
	// Use the authenticated hash of the ciphered data to ensure it was not modified after being encrypted.
	HMAC_CTX_init(&hmac);

	// At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
	if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1
	    || HMAC_Update(&hmac, cryptogram_body_data(cryptogram), cryptogram_body_length(cryptogram)) != 1
	    || HMAC_Final(&hmac, md, &out_length) != 1) {
	    printf("Unable to generate the authentication code needed for validation. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	    HMAC_CTX_cleanup(&hmac);
	    return NULL;
	}
	HMAC_CTX_cleanup(&hmac);

	// We can use the generated hash to ensure the encrypted data was not altered after being encrypted.
	if (out_length != cryptogram_mac_length(cryptogram)
	    || memcmp(md, cryptogram_mac_data(cryptogram), out_length)) {
	    printf("The authentication code was invalid! The ciphered data has been corrupted!\n");
	    return NULL;
	}
    }

    // Create a buffer to hold the result.
    body_length = cryptogram_body_length(cryptogram);
    if (!(block = output = malloc(body_length + 1))) {
	printf("An error occurred while trying to allocate memory for the decrypted data.\n");
	return NULL;
    }

    // For now we use an empty initialization vector. We also clear out the result buffer just to be on the safe side.
    memset(iv, 0, EVP_MAX_IV_LENGTH);
    memset(output, 0, body_length + 1);

    EVP_CIPHER_CTX_init(&cipher);

    // Decrypt the data using the chosen symmetric cipher.
    if (EVP_DecryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1
	|| EVP_DecryptUpdate(&cipher, block, &out_len, cryptogram_body_data(cryptogram), cryptogram_body_length(cryptogram)) != 1) {
	printf("Unable to decrypt the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
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
