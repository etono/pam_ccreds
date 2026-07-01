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
#include <getopt.h>

#include "cc.h"

static int usage(void)
{
	fprintf(stderr, "Usage: cc_test [--validate|--store|--update] [options]\n\n");
	fprintf(stderr, "Actions:\n");
	fprintf(stderr, "  --update		    update user credentials\n");	
	fprintf(stderr, "  --store		    store user password in the case\n");	
	fprintf(stderr, "  --validate		    validate against cached credentials\n\n");		
	fprintf(stderr, "General options:\n");	
	fprintf(stderr, "  -c, --credsfile filename specify the file where the credentails are cached\n");	
	fprintf(stderr, "  -w, --password password  specify the user password\n");	
	fprintf(stderr, "  -s, --service name	    specify the name of the service\n");	
	fprintf(stderr, "  -u, --user name	    specify the name of the user\n\n");	
	fprintf(stderr, "Store options:\n");
	fprintf(stderr, "  -h, --hash hash	    specify one of the following hash functions\n"
			"			      \"sha1\", \"sha256\" or \"sha512\"\n");
	fprintf(stderr, "  -r, --rounds rounds	    specify the number of rounds\n");

	return PAM_SYSTEM_ERR;
}

typedef enum { 
	ACTION_VALIDATE, 
	ACTION_STORE, 
	ACTION_UPDATE, 
	ACTION_NONE 
} pam_cc_action_t;

int main(int argc, char *argv[])
{
	pam_cc_handle_t *pamcch;
	int rc;
	char *user = NULL;
	char *service = NULL;
	char *password = NULL;
	char *ccredsfile = NULL;
	char *rounds = NULL;
	char *hash = NULL;
	char *function = NULL;
	int action = ACTION_NONE;
	pam_cc_type_t type = PAM_CC_TYPE_DEFAULT;
	uint iterations = 10000;
	unsigned int cc_flags;

#if defined(CCREDS_FILE)
	ccredsfile = CCREDS_FILE;
#endif

	struct option options[] = {
		{"help",      no_argument,	  0, 'l'},
		{"rounds",    required_argument,  0, 'r'},
		{"hash",      required_argument,  0, 'h'},
		{"validate",  no_argument,	  &action, ACTION_VALIDATE},
		{"store",     no_argument,	  &action, ACTION_STORE},
		{"update",    no_argument,	  &action, ACTION_UPDATE},
		{"password",  required_argument,  0, 'w'},
		{"service",   required_argument,  0, 's'},
		{"user",      required_argument,  0, 'u'},
		{"credsfile", required_argument,  0, 'c'},
		{0, 0, 0, 0}
	};

	while(1) {	
		int c, index;
		c = getopt_long(argc, argv, "r:h:w:u:s:c:", options, &index);

		if (c == -1) {
			break;
		}

		switch(c) {
		case 0:
			break;
		case 'l':
			usage();
			return 0;
		case 'r':
			rounds = optarg;
			break;
		case 'h':
			hash = optarg;
			break;
		case 'w':
			password = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'c':
			ccredsfile = optarg;
			break;
		case '?':
			usage();
			return 1;
		default:
			return 1;
		}
	}

	if (action == ACTION_NONE) {
		fprintf(stderr, "No action specified. Please specify one of --store, --validate or --update\n\n");
		usage();
		return 1;
	}

	if (user == NULL) {
		fprintf(stderr, "No user specified.\n\n");
		usage();
		return 1;	  
	}

	if (password == NULL && (action == ACTION_VALIDATE || action == ACTION_STORE)) {
		fprintf(stderr, "Password required when storing or validating credentials.\n\n");
		usage();
		return 1;	  
	}

	if (hash != NULL) {
		if (strcmp(hash, "sha1") == 0) {
			type = PAM_CC_TYPE_PBKDF2_SHA1;
		} else if (strcmp(hash, "sha256") == 0) {
			type = PAM_CC_TYPE_PBKDF2_SHA256;
		} else if (strcmp(hash, "sha512") == 0) {
			type = PAM_CC_TYPE_PBKDF2_SHA512;
		} else {
			fprintf(stderr, "Invalid hash type.\n\n");
			usage();
			return 1;	  
		}
	}

	if (rounds != NULL) {
		iterations = strtol(rounds, NULL, 10);
		if (iterations == 0) {
			fprintf(stderr, "Invalid number of rounds.\n\n");
			usage();
			return 1;	  
		}
	}

	if (action == ACTION_VALIDATE)
		cc_flags = CC_FLAGS_READ_ONLY;
	else
		cc_flags = 0;

	rc = pam_cc_start(service, user, ccredsfile, cc_flags, &pamcch);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_cc_start failed: %s\n", pam_strerror(NULL, rc));
		exit(rc);
	}

	if (action == ACTION_VALIDATE) {
		rc = pam_cc_validate_credentials(pamcch, password, strlen(password));
		function = "pam_cc_validate_credentials";
	} else if (action == ACTION_STORE) {
		rc = pam_cc_store_credentials(pamcch, type, iterations,
					      password, strlen(password));
		function = "pam_cc_store_credentials";
	} else if (action == ACTION_UPDATE) {
		rc = pam_cc_delete_credentials(pamcch, password,
					       (password == NULL) ? 0 : strlen(password));
		function = "pam_cc_delete_credentials";
	} else {
		rc = usage();
	}

	if (function != NULL) {
		fprintf(stderr, "%s: %s\n", function, pam_strerror(NULL, rc));
	}

	pam_cc_end(&pamcch);

	exit(rc);
	return rc;
}

