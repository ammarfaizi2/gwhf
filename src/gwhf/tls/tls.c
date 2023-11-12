
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <gwhf/tls/tls.h>

#define RSA_KEY_BITS (8192)
#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application"

static void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
static void print_bytes(uint8_t *data, size_t size);

int gwhf_tls_gen_key_rsa(EVP_PKEY **out_key, unsigned bits)
{
	*out_key = EVP_RSA_gen(bits);
	if (!*out_key)
		return -1;

	return 0;
}

int gwhf_tls_gen_x509_csr(X509_REQ **out_req, EVP_PKEY *key,
			  struct gwhf_tls_csr_txt_entry *entries,
			  size_t nr_entries)
{
	X509_NAME *name;
	size_t i;

	*out_req = X509_REQ_new();
	if (!*out_req)
		return -1;

	X509_REQ_set_pubkey(*out_req, *key);
	name = X509_REQ_get_subject_name(*req);
	for (i = 0; i < nr_entries; i++) {
		struct gwhf_tls_csr_txt_entry *e = &entries[i];
		const unsigned char *val = (const unsigned char *)e->value;
		int ret;

		ret = X509_NAME_add_entry_by_txt(name, e->field, MBSTRING_ASC,
						 val, -1, -1, 0);
		if (!ret)
			goto out_err;
	}

	/*
	 * Self-sign the request to prove that we posses the key.
	 */
	if (!X509_REQ_sign(*out_req, *key, EVP_sha256()))
		goto out_err;

	return 0;

out_err:
	X509_REQ_free(*out_req);
	*out_req = NULL;
	return -1;
}

int gwhf_tls_signed_key_pair(EVP_PKEY **out_key, X509 **out_crt,
			     EVP_PKEY *ca_key, X509 *ca_crt, unsigned bits,
			     struct gwhf_tls_csr_txt_entry *csr_entries,
			     size_t nr_csr_entries)
{
	EVP_PKEY *key = NULL;
	X509 *crt = NULL;
	int ret;

	ret = gwhf_tls_gen_key_rsa(&key, bits);
	if (ret)
		goto out_err;

	ret = gwhf_tls_gen_x509_csr(&crt, key, csr_entries, nr_csr_entries);
	if (ret)
		goto out_err;

	ret = gwhf_tls_sign_x509_crt(ca_key, ca_crt, key, crt);
	if (ret)
		goto out_err;

	*out_key = key;
	*out_crt = crt;
	return 0;

out_err:
	EVP_PKEY_free(key);
	X509_free(crt);
	return -1;
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt)
{
	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(key, &req)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*24*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int gen_key(const char *ca_key_path, const char *ca_crt_path)
{
	/* Load CA key and cert. */
	EVP_PKEY *ca_key = NULL;
	X509 *ca_crt = NULL;
	if (!load_ca(ca_key_path, &ca_key, ca_crt_path, &ca_crt)) {
		fprintf(stderr, "Failed to load CA certificate and/or key!\n");
		return 1;
	}

	/* Generate keypair and then print it byte-by-byte for demo purposes. */
	EVP_PKEY *key = NULL;
	X509 *crt = NULL;

	int ret = generate_signed_key_pair(ca_key, ca_crt, &key, &crt);
	if (!ret) {
		fprintf(stderr, "Failed to generate key pair!\n");
		return 1;
	}
	/* Convert key and certificate to PEM format. */
	uint8_t *key_bytes = NULL;
	uint8_t *crt_bytes = NULL;
	size_t key_size = 0;
	size_t crt_size = 0;

	key_to_pem(key, &key_bytes, &key_size);
	crt_to_pem(crt, &crt_bytes, &crt_size);

	/* Print key and certificate. */
	print_bytes(key_bytes, key_size);
	print_bytes(crt_bytes, crt_size);

	/* Free stuff. */
	EVP_PKEY_free(ca_key);
	EVP_PKEY_free(key);
	X509_free(ca_crt);
	X509_free(crt);
	free(key_bytes);
	free(crt_bytes);

	return 0;
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt)
{
	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(key, &req)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*24*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int generate_key_csr(EVP_PKEY **key, X509_REQ **req)
{
	*key = NULL;
	*req = NULL;

	*key = EVP_RSA_gen(RSA_KEY_BITS);
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)REQ_DN_CN, -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;

	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}

int generate_set_random_serial(X509 *crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt)
{
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);BIO_free_all(bio);le());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

void print_bytes(uint8_t *data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		printf("%c", data[i]);
	}
}
