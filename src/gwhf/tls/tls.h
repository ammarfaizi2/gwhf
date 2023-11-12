// SPDX-License-Identifier: GPL-2.0-only
#ifndef GWHF__TLS__TLS_H
#define GWHF__TLS__TLS_H

struct gwhf_tls_csr_txt_entry {
	const char *field;
	const char *value;
};

int gwhf_tls_gen_key_rsa(EVP_PKEY **out_key, unsigned bits);
int gwhf_tls_gen_csr(X509_REQ **out_req, EVP_PKEY *key,
		     struct gwhf_tls_csr_txt_entry *entries,
		     size_t nr_entries);

#endif /* #ifndef GWHF__TLS__TLS_H */
