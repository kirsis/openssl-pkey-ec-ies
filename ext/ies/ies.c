#include "ies.h"

static VALUE eIESError;

static EC_KEY *require_ec_key(VALUE self)
{
    EVP_PKEY *pkey;
    EC_KEY *ec;
    Data_Get_Struct(self, EVP_PKEY, pkey);
    if (!pkey) {
	rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!");
    }
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_EC) {
	rb_raise(rb_eRuntimeError, "THIS IS NOT A EC PKEY!");
    }
    ec = pkey->pkey.ec;
    if (ec == NULL)
	rb_raise(eIESError, "EC_KEY is not initialized");
    return ec;
}

static uint64_t ies_key_length(VALUE self)
{
    // TODO
    return 25;
}

static uint64_t ies_mac_length(VALUE self)
{
    // TODO
    return 20;
}

static VALUE ies_cryptogram_to_rb_string(VALUE self, const cryptogram_t *cryptogram)
{
    if (cryptogram_key_length(cryptogram) != ies_key_length(self)) {
	rb_raise(eIESError, "ECIES bug: Key length mismatch");
    }
    if (cryptogram_mac_length(cryptogram) != ies_mac_length(self)) {
	rb_raise(eIESError, "ECIES bug: MAC length mismatch");
    }
    return rb_str_new((char *)cryptogram_key_data(cryptogram), cryptogram_data_sum_length(cryptogram));
}

static cryptogram_t *ies_rb_string_to_cryptogram(VALUE self, const VALUE string)
{
    uint64_t data_len = RSTRING_LEN(string);
    const char * data = RSTRING_PTR(string);

    uint64_t key_length = ies_key_length(self);
    uint64_t mac_length = ies_mac_length(self);
    cryptogram_t *cryptogram = cryptogram_alloc(key_length, mac_length, data_len - key_length - mac_length);

    memcpy(cryptogram_key_data(cryptogram), data, data_len);

    return cryptogram;
}

/*
 *  call-seq:
 *     OpenSSL::PKey::EC::IES.new(key, algorithm_spec)
 *
 *  Algorithm spec is currently ignored.
 */
static VALUE ies_initialize(VALUE self, VALUE key, VALUE algo)
{
    VALUE args[1];

    rb_iv_set(self, "@algorithm", algo);

    args[0] = key;
    return rb_call_super(1, args);
}

/*
 *  call-seq:
 *     ecies.public_encrypt(plaintext) => String
 *
 *  The pem_string given in init must contain public key.
 */
static VALUE ies_public_encrypt(VALUE self, VALUE clear_text)
{
    EC_KEY *ec;
    VALUE cipher_text;
    cryptogram_t *cryptogram;

    ec = require_ec_key(self);
    if (!EC_KEY_get0_public_key(ec))
	rb_raise(eIESError, "Given EC key is not public key");

    StringValue(clear_text);

    cryptogram = ecies_encrypt(ec, (unsigned char*)RSTRING_PTR(clear_text), RSTRING_LEN(clear_text));
    cipher_text = ies_cryptogram_to_rb_string(self, cryptogram);
    cryptogram_free(cryptogram);
    return cipher_text;
}

/*
 *  call-seq:
 *     ecies.private_decrypt(plaintext) => String
 *
 *  The pem_string given in init must contain private key.
 */
static VALUE ies_private_decrypt(VALUE self, VALUE cipher_text)
{
    EC_KEY *ec;
    VALUE clear_text;
    cryptogram_t *cryptogram;
    size_t length;
    unsigned char *data;

    ec = require_ec_key(self);
    if (!EC_KEY_get0_private_key(ec))
	rb_raise(eIESError, "Given EC key is not private key");

    StringValue(cipher_text);

    cryptogram = ies_rb_string_to_cryptogram(self, cipher_text);
    data = ecies_decrypt(ec, cryptogram, &length);
    cryptogram_free(cryptogram);
    clear_text = rb_str_new((char *)data, length);
    free(data);
    return clear_text;
}

/*
 * INIT
 */
void
Init_ies(void)
{
    static VALUE cIES;
    VALUE cEC;

    rb_require("openssl");
    cEC = rb_path2class("OpenSSL::PKey::EC");

    /* Document-class: OpenSSL::PKey::EC::IES
     *
     * An implementation of ECIES cryptography.
     */
    cIES = rb_define_class_under(cEC, "IES", cEC);

    rb_define_method(cIES, "initialize", ies_initialize, 2);
    rb_define_method(cIES, "public_encrypt", ies_public_encrypt, 1);
    rb_define_method(cIES, "private_decrypt", ies_private_decrypt, 1);

    eIESError = rb_define_class_under(cIES, "IESError", rb_eRuntimeError);
}
