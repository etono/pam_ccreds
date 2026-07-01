/*
 * Copyright (c) 2004 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(USE_OPENSSL)
#include <openssl/sha.h>
#include <openssl/evp.h>
#elif defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#elif defined(USE_NETTLE)
#include <nettle/pbkdf2.h>
#include <nettle/hmac.h>
#endif

#include "cc_private.h"

#if defined(USE_LIBGCRYPT)
/* If libgcrypt isn't initalized try to do it here.
   Calls to the library will drop priviledges if it isn't initialized with
   GCRYCTL_DISABLE_SECMEM. */
static void _pam_cc_initialize_libgcrypt_if_needed()
{
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
		syslog(LOG_INFO, "pam_ccreds: initializing libgcrypt");
		if (!gcry_check_version(GCRYPT_VERSION)) {
			syslog(LOG_ERR, "pam_ccreds: incorrect libgcrypt version: expected '%s'",
				GCRYPT_VERSION);
			return;
		}     
		gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
}
#endif

static char * _pam_cc_get_salt(pam_cc_handle_t *pamcch, pam_cc_type_t type, size_t * salt_length_p)
{
	size_t user_offset = (pamcch->service ? strlen(pamcch->service) : 0) + 4;
	char * salt;

	*salt_length_p = user_offset + strlen(pamcch->user);
	salt = (char *)malloc(*salt_length_p);
	
	if (salt != NULL) {
		salt[0] = (type >> 24) & 0xFF;
		salt[1] = (type >> 16) & 0xFF;
		salt[2] = (type >> 8)  & 0xFF;
		salt[3] = (type >> 0)  & 0xFF;
		
		if (pamcch->service != NULL) {
			memcpy(&salt[4], pamcch->service, strlen(pamcch->service));
		}
		memcpy(&salt[user_offset], pamcch->user, strlen(pamcch->user));
	}
	return salt;
}

#if HAVE_SHA1
static int _pam_cc_derive_key_pbkdf2_sha1(pam_cc_handle_t *pamcch,
					  pam_cc_type_t type,
					  uint iterations,
					  const char *credentials,
					  size_t length,
					  char **derived_key_p,
					  size_t *derived_key_length_p)
{
	int rv = PAM_SUCCESS;
	size_t salt_length;
	char * salt = _pam_cc_get_salt(pamcch, type, &salt_length);

	if (salt == NULL) {
		return PAM_BUF_ERR;
	}	

#if defined(USE_OPENSSL)
	*derived_key_length_p = SHA_DIGEST_LENGTH;
	*derived_key_p = malloc(SHA_DIGEST_LENGTH);

	if (!PKCS5_PBKDF2_HMAC_SHA1(credentials, length, 
				    (unsigned char *)salt, salt_length, iterations, 
				    *derived_key_length_p, 
				    (unsigned char *)*derived_key_p)) {
	     rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_LIBGCRYPT)
	_pam_cc_initialize_libgcrypt_if_needed();
	*derived_key_length_p = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
	*derived_key_p = (char *)malloc(*derived_key_length_p);

	if (gcry_kdf_derive(credentials, length, GCRY_KDF_PBKDF2, GCRY_MD_SHA1, 
			    salt, salt_length, iterations, 
			    *derived_key_length_p, *derived_key_p)) {
		rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_NETTLE)
        *derived_key_length_p = SHA1_DIGEST_SIZE;
        *derived_key_p = (char *)malloc(*derived_key_length_p);

	nettle_pbkdf2_hmac_sha1(length, (uint8_t*)credentials, iterations,
				salt_length, (uint8_t*)salt, 
				*derived_key_length_p, (uint8_t*)*derived_key_p);
#endif
	free(salt);

	return rv;
}
#endif

#if HAVE_SHA256
static int _pam_cc_derive_key_pbkdf2_sha256(pam_cc_handle_t *pamcch,
					    pam_cc_type_t type,
					    uint iterations,
					    const char *credentials,
					    size_t length,
					    char **derived_key_p,
					    size_t *derived_key_length_p)
{
	int rv = PAM_SUCCESS;
	size_t salt_length;
	char * salt = _pam_cc_get_salt(pamcch, type, &salt_length);

	if (salt == NULL) {
		return PAM_BUF_ERR;
	}	

#if defined(USE_OPENSSL)
	*derived_key_length_p = SHA256_DIGEST_LENGTH;
	*derived_key_p = malloc(SHA256_DIGEST_LENGTH);

	if (!PKCS5_PBKDF2_HMAC(credentials, length, 
			       (unsigned char *)salt, salt_length, 
			       iterations, EVP_sha256(),
			       *derived_key_length_p, 
			       (unsigned char *)*derived_key_p)) {
	      rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_LIBGCRYPT)
	_pam_cc_initialize_libgcrypt_if_needed();
	*derived_key_length_p = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	*derived_key_p = (char *)malloc(*derived_key_length_p);

	if (gcry_kdf_derive(credentials, length, GCRY_KDF_PBKDF2, GCRY_MD_SHA256, 
			    salt, salt_length, iterations, 
			    *derived_key_length_p, *derived_key_p)) {
		rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_NETTLE)
        *derived_key_length_p = SHA256_DIGEST_SIZE;
        *derived_key_p = (char *)malloc(*derived_key_length_p);

	nettle_pbkdf2_hmac_sha256(length, (uint8_t*)credentials, iterations,
				  salt_length, (uint8_t*)salt, 
				  *derived_key_length_p, (uint8_t*)*derived_key_p);
#endif

	free(salt);

	return rv;
}
#endif

#if HAVE_SHA512
static int _pam_cc_derive_key_pbkdf2_sha512(pam_cc_handle_t *pamcch,
					    pam_cc_type_t type,
					    uint iterations,
					    const char *credentials,
					    size_t length,
					    char **derived_key_p,
					    size_t *derived_key_length_p)
{	
	int rv = PAM_SUCCESS;
	size_t salt_length;
	char * salt = _pam_cc_get_salt(pamcch, type, &salt_length);

	if (salt == NULL) {
		return PAM_BUF_ERR;
	}	

#if defined(USE_OPENSSL)
	*derived_key_length_p = SHA512_DIGEST_LENGTH;
	*derived_key_p = malloc(SHA512_DIGEST_LENGTH);

	if (!PKCS5_PBKDF2_HMAC(credentials, length, 
			       (unsigned char *)salt, salt_length, 
			       iterations, EVP_sha512(),
			       *derived_key_length_p, 
			       (unsigned char *)*derived_key_p)) {
	      rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_LIBGCRYPT)
	_pam_cc_initialize_libgcrypt_if_needed();
	*derived_key_length_p = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	*derived_key_p = (char *)malloc(*derived_key_length_p);

	if (gcry_kdf_derive(credentials, length, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, 
			    salt, salt_length, iterations, 
			    *derived_key_length_p, *derived_key_p)) {
		rv = PAM_SYSTEM_ERR;
	}
#elif defined(USE_NETTLE)
        *derived_key_length_p = SHA512_DIGEST_SIZE;
        *derived_key_p = (char *)malloc(*derived_key_length_p);

	struct hmac_sha512_ctx ctx;
	nettle_hmac_sha512_set_key(&ctx, length, (uint8_t*)credentials);
	PBKDF2(&ctx, nettle_hmac_sha512_update, nettle_hmac_sha512_digest,
	       SHA512_DIGEST_SIZE, iterations, salt_length, (uint8_t*)salt,
	       *derived_key_length_p, (uint8_t*)*derived_key_p);
#endif
	free(salt);

	return rv;
}
#endif

static struct {
	pam_cc_type_t type;
	const char *name;
	pam_cc_key_derivation_function_t function;
} _pam_cc_key_derivation_functions[] = {
#if HAVE_SHA1
	{ PAM_CC_TYPE_PBKDF2_SHA1, "PBKDF2 SHA1", _pam_cc_derive_key_pbkdf2_sha1 },
#endif
#if HAVE_SHA256
	{ PAM_CC_TYPE_PBKDF2_SHA256, "PBKDF2 SHA256", _pam_cc_derive_key_pbkdf2_sha256 },
#endif
#if HAVE_SHA512
	{ PAM_CC_TYPE_PBKDF2_SHA512, "PBKDF2 SHA512", _pam_cc_derive_key_pbkdf2_sha512 },
#endif
	{ PAM_CC_TYPE_NONE, NULL, NULL }
};

static const char *_pam_cc_find_key_name(pam_cc_type_t type)
{
	int i;

	for (i = 0; _pam_cc_key_derivation_functions[i].type != PAM_CC_TYPE_NONE; i++) {
		if (_pam_cc_key_derivation_functions[i].type == type) {
			return _pam_cc_key_derivation_functions[i].name;
		}
	}

	return NULL;
}

static int _pam_cc_find_key_derivation_function(pam_cc_type_t type,
						pam_cc_key_derivation_function_t *fn_p)
{
	int i;

	for (i = 0; _pam_cc_key_derivation_functions[i].type != PAM_CC_TYPE_NONE; i++) {
		if (_pam_cc_key_derivation_functions[i].type == type) {
			*fn_p = _pam_cc_key_derivation_functions[i].function;
			return PAM_SUCCESS;
		}
	}

	return PAM_SERVICE_ERR;
}

/* Initializes a cached credentials handle */
int pam_cc_start(const char *service,
		 const char *user,
		 const char *ccredsfile,
		 unsigned int cc_flags,
		 pam_cc_handle_t **pamcch_p)
{
	pam_cc_handle_t *pamcch;
	int rc;
	unsigned int cc_db_flags;

	*pamcch_p = NULL;

	pamcch = (pam_cc_handle_t *)calloc(1, sizeof(*pamcch));
	if (pamcch == NULL) {
		return PAM_BUF_ERR;
	}

	pamcch->flags = cc_flags;

	if (service != NULL) {
		pamcch->service = strdup(service);
		if (pamcch->service == NULL) {
			pam_cc_end(&pamcch);
			return PAM_BUF_ERR;
		}
	} else {
		pamcch->service = NULL;
	}

	pamcch->user = strdup(user);
	if (pamcch->user == NULL) {
		pam_cc_end(&pamcch);
		return PAM_BUF_ERR;
	}

	if (ccredsfile == NULL) {
		ccredsfile = CCREDS_FILE;
	}

	pamcch->ccredsfile = strdup(ccredsfile);
	if (pamcch->ccredsfile == NULL) {
		pam_cc_end(&pamcch);
		return PAM_BUF_ERR;
	}

	if (pamcch->flags & CC_FLAGS_READ_ONLY)
		cc_db_flags = CC_DB_FLAGS_READ;
	else
		cc_db_flags = CC_DB_FLAGS_WRITE;

	/* Initialize DB handle */
	rc = pam_cc_db_open(pamcch->ccredsfile, cc_db_flags,
		CC_DB_MODE, &pamcch->db);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to open cached credentials \"%s\": %m",
		       ccredsfile);
		pam_cc_end(&pamcch);
		return rc;
	}

	*pamcch_p = pamcch;

	return PAM_SUCCESS;
}

/* Initializes a cached credentials handle from PAM handle */
int pam_cc_start_ext(pam_handle_t *pamh,
		     int service_specific,
		     const char *ccredsfile,
		     unsigned int cc_flags,
		     pam_cc_handle_t **pamcch_p)
{
	int rc;
	const void *service;
	const void *user;

	if (service_specific) {
		rc = pam_get_item(pamh, PAM_SERVICE, &service);
		if (rc != PAM_SUCCESS) {
			return rc;
		}
	} else {
		service = NULL;
	}

	rc = pam_get_item(pamh, PAM_USER, &user);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_cc_start((const char *)service,
		(const char *)user,
		ccredsfile,
		cc_flags,
		pamcch_p);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	return PAM_SUCCESS;
}

static int _pam_cc_encode_key(pam_cc_handle_t *pamcch,
			      char **key_p,
			      size_t *keylength_p)
{
	size_t keylength;
	char *key;
	size_t service_len;
	size_t user_len; 
	char *p;

	if (pamcch->service != NULL) {
		service_len = strlen(pamcch->service);
	} else {
		service_len = 0;
	}

	user_len = strlen(pamcch->user);

	/* user\0[service\0] */
	keylength = user_len + 1 + service_len + 1;
	key = malloc(keylength);
	if (key == NULL) {
		return PAM_BUF_ERR;
	}

	p = key;

	memcpy(p, pamcch->user, user_len);
	p += user_len;
	*p++ = '\0';

	if (pamcch->service != NULL) {
		memcpy(p, pamcch->service, service_len);
		p += service_len;
	}
	*p++ = '\0';

	*key_p = key;
	*keylength_p = keylength;

	return PAM_SUCCESS;
}

int _pam_cc_encode_data(pam_cc_type_t type,
			uint iterations,
			const char *hash,
			size_t hashlength,
			char ** data_p,
			size_t * datalength_p)
{
	char * data = NULL;  
	*datalength_p = hashlength + 8;
	*data_p = (char *)malloc(*datalength_p);
	data = *data_p;

	if (data == NULL) {
		return PAM_BUF_ERR;
	}
	
	data[0] = (type >> 24) & 0xFF;
	data[1] = (type >> 16) & 0xFF;
	data[2] = (type >> 8)  & 0xFF;
	data[3] = (type >> 0)  & 0xFF;
	data[4] = (iterations >> 24) & 0xFF;
	data[5] = (iterations >> 16) & 0xFF;
	data[6] = (iterations >> 8)  & 0xFF;
	data[7] = (iterations >> 0)  & 0xFF;

	memcpy(&data[8], hash, hashlength);
	return PAM_SUCCESS;
}

int _pam_cc_decode_data(const char *data,
			size_t datalength,
			pam_cc_type_t* type_p,
			uint* iterations_p,
			const char ** hash_p,
			size_t * hashlength_p)
{
	if (datalength < 8) {
		return PAM_BUF_ERR;
	}

	unsigned char * ub = (unsigned char *)data;
	
	*type_p = (ub[0] << 24) | (ub[1] << 16) | (ub[2] << 8) | ub[3];
	*iterations_p = (ub[4] << 24) | (ub[5] << 16) | (ub[6] << 8) | ub[7];

	*hash_p = &data[8];
	*hashlength_p = datalength - 8;

	return PAM_SUCCESS;
}


/* Store credentials */
int pam_cc_store_credentials(pam_cc_handle_t *pamcch,
			     pam_cc_type_t type,
			     uint iterations,
			     const char *credentials,
			     size_t length)
{
	char *key;
	size_t keylength;
	char *hash;
	size_t hashlength;
	char *data;
	size_t datalength;
	int rc;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = _pam_cc_find_key_derivation_function(type, &key_derivation_fn);
	if (rc != PAM_SUCCESS) {
		free(key);
		return rc;
	}

	rc = (*key_derivation_fn)(pamcch, type, iterations, credentials, length, &hash, &hashlength);
	if (rc != PAM_SUCCESS) {
		free(key);
		return rc;
	}

	rc = _pam_cc_encode_data(type, iterations, hash, hashlength, &data, &datalength);
	if (rc != PAM_SUCCESS) {
		free(key);
		free(hash);
		return rc;
	}

	rc = pam_cc_db_put(pamcch->db, key, keylength, data, datalength);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to write cached credentials \"%s\": %m",
		       pamcch->ccredsfile);
	}

	free(key);

	memset(hash, 0, hashlength);
	free(hash);

	memset(data, 0, datalength);
	free(data);

	return rc;
}

/* Delete credentials */
int pam_cc_delete_credentials(pam_cc_handle_t *pamcch,
			      const char *credentials,
			      size_t length)
{
	int rc;
	char *key;
	size_t keylength;
	pam_cc_type_t type;
	uint iterations;
	char *hash = NULL;
	const char *storedhash = NULL;
	char *stored = NULL;
	size_t hashlength, storedhashlength, storedlength;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_cc_db_get(pamcch->db, key, keylength, &stored, &storedlength);

	if (rc != PAM_SUCCESS || stored == NULL) {
		goto out;
	}

	rc = _pam_cc_decode_data(stored, storedlength, &type, &iterations, &storedhash, &storedhashlength);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = _pam_cc_find_key_derivation_function(type, &key_derivation_fn);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = (*key_derivation_fn)(pamcch, type, iterations, credentials, length, &hash, &hashlength);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	if (storedhashlength != hashlength && credentials) {
		rc = PAM_IGNORE;
		goto out;
	}

	if (!credentials || memcmp(hash, storedhash, hashlength) == 0) {
		/* We need to delete them */
		rc = pam_cc_db_delete(pamcch->db, key, keylength);
		if (rc != PAM_SUCCESS && rc != PAM_AUTHINFO_UNAVAIL /* not found */) {
			syslog(LOG_WARNING, "pam_ccreds: failed to delete cached "
			       "credentials \"%s\": %m",
			       pamcch->ccredsfile);
		}
	}

out:
	free(key);

	if (hash != NULL) {
		memset(hash, 0, hashlength);
		free(hash);
	}

	if (stored != NULL) {
		memset(stored, 0, storedlength);
		free(stored);
	}

	return rc;
}

int pam_cc_validate_credentials(pam_cc_handle_t *pamcch,
				const char *credentials,
				size_t length)
{
	int rc;
	char *key = NULL;
	size_t keylength;
	char *hash = NULL;
	const char *storedhash = NULL;
	char *stored = NULL;
	pam_cc_type_t type;
	uint iterations;
	size_t hashlength, storedhashlength, storedlength;
	pam_cc_key_derivation_function_t key_derivation_fn;

	rc = _pam_cc_encode_key(pamcch, &key, &keylength);
	if (rc != PAM_SUCCESS) {
		return rc;
	}

	rc = pam_cc_db_get(pamcch->db, key, keylength, &stored, &storedlength);

	if (rc != PAM_SUCCESS || stored == NULL) {
		rc = PAM_USER_UNKNOWN;
		goto out;
	}

	rc = _pam_cc_decode_data(stored, storedlength, &type, &iterations, &storedhash, &storedhashlength);
	if (rc != PAM_SUCCESS) {
		rc = PAM_USER_UNKNOWN;
		goto out;
	}

	rc = _pam_cc_find_key_derivation_function(type, &key_derivation_fn);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = (*key_derivation_fn)(pamcch, type, iterations, credentials, length, &hash, &hashlength);
	if (rc != PAM_SUCCESS) {
		goto out;
	}

	rc = PAM_AUTH_ERR;

	if (hashlength == storedhashlength && memcmp(hash, storedhash, hashlength) == 0) {
		rc = PAM_SUCCESS;
	}

out:
	if (key != NULL) {
		free(key);
	}

	if (hash != NULL) {
		memset(hash, 0, hashlength);
		free(hash);
	}

	if (stored != NULL) {
		memset(stored, 0, storedlength);
		free(stored);
	}

	return rc;
}

/* Destroys a cached credentials handle */
int pam_cc_end(pam_cc_handle_t **pamcch_p)
{
	pam_cc_handle_t *pamcch;
	int rc = PAM_SUCCESS;

	pamcch = *pamcch_p;
	if (pamcch != NULL) {
		if (pamcch->user != NULL) {
			free(pamcch->user);
		}

		if (pamcch->service != NULL) {
			free(pamcch->service);
		}

		if (pamcch->ccredsfile != NULL) {
			free(pamcch->ccredsfile);
		}

		if (pamcch->db != NULL) {
			rc = pam_cc_db_close(&pamcch->db);
		}

		free(pamcch);

		*pamcch_p = NULL;
	}

	return rc;
}

static void _pam_cc_cleanup_data(pam_handle_t *pamh, void *data, int error)
{
	pam_cc_handle_t *pamcch = (pam_cc_handle_t *)data;

	pam_cc_end(&pamcch);
}

/* Associate a CC handle with a PAM handle */
int pam_cc_associate(pam_cc_handle_t *pamcch, pam_handle_t *pamh)
{
	return pam_set_data(pamh, PADL_CC_HANDLE_DATA,
			    (void *)pamcch, _pam_cc_cleanup_data);
}
                                                                                           
/* Deassociate a CC handle from a PAM handle */
int pam_cc_unassociate(pam_cc_handle_t *pamcch, pam_handle_t *pamh)
{
	return pam_set_data(pamh, PADL_CC_HANDLE_DATA,
			    NULL, _pam_cc_cleanup_data);
}

static const char *_pam_cc_next_token(const char *key, size_t keylength,
				      const char **tok_p)
{
	ssize_t i, left;
	int terminated = 0;
	const char *ret;

	left = keylength - (*tok_p - key);
	if (left < 0) {
		return NULL;
	}

	ret = *tok_p;

	for (i = 0; i < left; i++) {
		if ((*tok_p)[i] == '\0') {
			terminated++;
			break;
		}
	}

	*tok_p += i + 1;

	if (!terminated)
		return NULL;

	if (*ret == '\0')
		return NULL;

	return ret;
}

static int _pam_cc_print_entry(FILE *fp, const char *key, size_t keylength,
			       const char *data, size_t length)
{
	/* user\0[service\0] */
	pam_cc_type_t T;
	uint iterations;
	const char *p = key;
	const char *user, *service;
	char sz_key_type_buf[32];
	const char *sz_key_type;
	const char *hash;
	size_t hashlength;

	user = _pam_cc_next_token(key, keylength, &p);
	if (user == NULL)
		return PAM_BUF_ERR;

	service = _pam_cc_next_token(key, keylength, &p);
	if (service == NULL)
		service = "any";

	if (_pam_cc_decode_data(data, length, &T, &iterations, &hash, &hashlength) != PAM_SUCCESS)
		return PAM_BUF_ERR;	  

	sz_key_type = _pam_cc_find_key_name(T);
	if (sz_key_type == NULL) {
		snprintf(sz_key_type_buf, sizeof(sz_key_type_buf),
			 "Unknown key type %d", T);
		sz_key_type = sz_key_type_buf;
	}

	fprintf(fp, "%-16s %-12d %-16s %-8s ", 
		sz_key_type, iterations, user, service);

	while (hashlength--) {
		fprintf(fp, "%02x", *hash++ & 0xFF);
	}
	fprintf(fp, "\n");

	return PAM_SUCCESS;
}

/* Dump contents of DB - for debugging only */
int pam_cc_dump(pam_cc_handle_t *pamcch, FILE *fp)
{
	int rc;
	const char *key, *data;
	size_t keylength, datalength;
	void *cookie = NULL;

	fprintf(fp, "%-16s %-12s %-16s %-8s %-20s\n", 
		"Credential Type", "Iterations", "User", "Service", "Cached Credentials");
	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");

	rc = PAM_INCOMPLETE;

	while (rc == PAM_INCOMPLETE) {
		rc = pam_cc_db_seq(pamcch->db, &cookie,
				   &key, &keylength,
				   &data, &datalength);
		if (rc != PAM_INCOMPLETE)
			break;

		_pam_cc_print_entry(fp, key, keylength, data, datalength);
	}

	return rc;
}

int pam_cc_run_helper_binary(pam_handle_t *pamh, const char *helper,
                             const char *passwd, int service_specific)
{
	int retval, child, fds[2], rc;
	void (*sighandler)(int) = NULL;
	const void *service, *user;

	rc = pam_get_item(pamh, PAM_USER, &user);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_WARNING, "pam_ccreds: failed to lookup user");
		return PAM_AUTH_ERR;
	}

	if (service_specific) {
		rc = pam_get_item(pamh, PAM_SERVICE, &service);
		if (rc != PAM_SUCCESS) {
			syslog(LOG_WARNING, "pam_ccreds: failed to lookup service");
			return PAM_AUTH_ERR;
		}
	} else
		service = NULL;

	/* create a pipe for the password */
	if (pipe(fds) != 0) {
		syslog(LOG_WARNING, "pam_ccreds: failed to create pipe");
		return PAM_AUTH_ERR;
	}

	sighandler = signal(SIGCHLD, SIG_DFL);

	/* fork */
	child = fork();
	if (child == 0) {
		static char *envp[] = { NULL };
		char *args[] = { NULL, NULL, NULL, NULL };

		/* XXX - should really tidy up PAM here too */

		/* reopen stdin as pipe */
		close(fds[1]);
		dup2(fds[0], STDIN_FILENO);

		/* exec binary helper */
		args[0] = x_strdup(helper);
		args[1] = x_strdup(user);
		if (service != NULL)
			args[2] = x_strdup(service);

		syslog(LOG_WARNING, "pam_ccreds: launching helper binary");
		execve(helper, args, envp);

		/* should not get here: exit with error */
		syslog(LOG_WARNING, "pam_ccreds: helper binary is not available");
		exit(PAM_AUTHINFO_UNAVAIL);
	} else if (child > 0) {
		int failed = 0;
		const char * pw = passwd != NULL ? passwd : "";
		int len = strlen(pw) + 1;
		if (write(fds[1], pw, len) != len) {
			failed = 1;
		}
		pw = passwd = NULL;

		close(fds[0]);			/* close here to avoid possible SIGPIPE above */
		close(fds[1]);
		(void) waitpid(child, &retval, 0); /* wait for helper to complete */
		retval = !failed && (retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
	} else {
		syslog(LOG_WARNING, "pam_ccreds: fork failed");
		retval = PAM_AUTH_ERR;
	}

	if (sighandler != NULL) {
		(void) signal(SIGCHLD, sighandler); /* restore old signal handler */
	}

	return retval;
}
