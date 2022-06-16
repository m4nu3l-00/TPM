#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cerrno>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_esys.h>

int open_read_and_close (const char *path, void **input, size_t *size) {
    printf("%d\n",!strcmp(path, "-"));
    printf("%d\n", !path);
    if (!path || !strcmp(path, "-")) {
        size_t data_consumed = 0, buffer_size = 1024, data_read;
        *input = malloc (buffer_size + 1);
        if (!*input) {
            fprintf (stderr, "malloc(2) failed: %m\n");
            return 1;
        }
        while ((data_read = read (STDIN_FILENO, *input + data_consumed, 1024))){
            data_consumed += data_read;
            if (data_read < 1024) /* EOF reached */
                break;
            buffer_size += 1024;
            *input = realloc (*input, buffer_size + 1);
            if (!*input) {
                fprintf (stderr, "realloc(3) failed: %m\n");
                return 1;
            }
        }
        if (size)
            *size = data_consumed;
        ((char*)(*input))[data_consumed] = 0;
        return 0;
    }
    printf("path:%s\n", input);
    int fileno = open (path, O_RDONLY);
    if (fileno == -1) {
        fprintf (stderr, "Opening %s failed: %m\n", path);
        return 1;
    }

    struct stat stat_;
    errno = 0;
    if (fstat (fileno, &stat_)) {
        printf("\nfstat error: [%s]\n",strerror(errno));
        close(fileno);
        return 1;
    }
    if (size)
        *size = stat_.st_size;
    *input = malloc (stat_.st_size + 1);
    if (!*input) {
        fprintf (stderr, "malloc(2) failed: %m\n");
        close (fileno);
        return 1;
    }
    if (-1 == read (fileno, *input, stat_.st_size)) {
        fprintf (stderr, "read(2) %s failed with: %m\n", path);
        free (*input);
        close (fileno);
        return 1;
    }
    ((char*)(*input))[stat_.st_size] = '\0';
    if (close (fileno)) {
        fprintf (stderr, "Error close(2) %s: %m\n", path);
        free (*input);
        return 1;
    }
    return 0;
}



int load_key(ESYS_CONTEXT *ectx, TPM2B_PRIVATE *outPrivate, TPM2B_PUBLIC *outPublic,
		ESYS_TR parent, ESYS_TR *key){
	TSS2_RC rv = Esys_Load(ectx,
			parent,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			outPrivate,
			outPublic,
			key);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Load: 0x%x\n", rv);
		return 1;

	}
	return 0;

}

void create_primary(ESYS_CONTEXT *ectx, ESYS_TR *parent) {
    
    TPM2B_PUBLIC pub_templ = {
		.publicArea = {
			.type = TPM2_ALG_RSA,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_RESTRICTED |
								 TPMA_OBJECT_DECRYPT |
								 TPMA_OBJECT_FIXEDTPM |
								 TPMA_OBJECT_FIXEDPARENT |
								 TPMA_OBJECT_SENSITIVEDATAORIGIN),
			.authPolicy = {
				 .size = 0,
			 },
			.parameters ={
                     .rsaDetail = {
                         .symmetric = {
                              .algorithm = TPM2_ALG_AES,
                              .keyBits = { .aes = 128 },
                              .mode = { .aes = TPM2_ALG_NULL }
                              },
                         .scheme = {
                              .scheme = TPM2_ALG_NULL
                         },
                         .keyBits = 2048,
                         .exponent = 0,
                    },
               }, 
               .unique = {
                    .rsa ={
                         .size = 0,
                         .buffer = {},
                         } ,
                    },
		},
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };


    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TSS2_RC rv = Esys_CreatePrimary(ectx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &pub_templ,
                           &outsideInfo, &creationPCR, parent,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "t1: Esys_CreatePrimary: 0x%x\n", rv);
		exit(1);
	}
	

    TPM2_HANDLE permanentHandle = TPM2_PERSISTENT_FIRST;
    ESYS_TR persistent_handle1 = ESYS_TR_NONE;
    rv = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, *parent,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          permanentHandle, &persistent_handle1);
 	if (rv != TSS2_RC_SUCCESS) {
 	fprintf(stderr, "WARN: Esys_EvictControl: %s\n", Tss2_RC_Decode(rv));
		fprintf(stderr, "t1: Esys_EvictControl activate: 0x%x\n", rv);
		exit(1);
	} 
	rv = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, persistent_handle1,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          permanentHandle, &persistent_handle1);
 	if (rv != TSS2_RC_SUCCESS) {
 	fprintf(stderr, "WARN: Esys_EvictControl: %s\n", Tss2_RC_Decode(rv));
		fprintf(stderr, "t1: Esys_EvictControl delete: 0x%x\n", rv);
		exit(1);
	} 
	
}

void create_and_load_aes_key(ESYS_CONTEXT *ectx, ESYS_TR parent, ESYS_TR *aes_key) {

    TPM2B_PUBLIC pub_templ = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_SYMCIPHER,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_SIGN_ENCRYPT  |
								 TPMA_OBJECT_DECRYPT  |
								 TPMA_OBJECT_FIXEDTPM |
								 TPMA_OBJECT_FIXEDPARENT |
								 TPMA_OBJECT_SENSITIVEDATAORIGIN),
               .authPolicy = {
				 .size = 0,
			 },
			 .parameters = {
				 .symDetail = {
						 .sym = {
								 .algorithm = TPM2_ALG_AES,
								 .keyBits = { .aes = 128 },
								 .mode = { .aes = TPM2_ALG_NULL }
						 },
				 },
			},
		},
	};

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
				/* TODO: Set this to a non-hard coded password, or better yet use a policy */
                 .size = 8,
                 .buffer ={0} 
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TSS2_RC rv = Esys_Create(
		ectx,
		parent,
    	ESYS_TR_PASSWORD,
		ESYS_TR_NONE,
		ESYS_TR_NONE,
		&inSensitive,
		&pub_templ,
		&outsideInfo,
		&creationPCR,
		&outPrivate,
		&outPublic,
		&creationData,
		&creationHash,
		&creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Create: 0x%x\n", rv);
		exit(1);
	}

	/* if you want this key again, save the TPM2B_PUBLIC and TPM2B_PRIVATE for
	 * future use. You just need to call load again.
	 */
	 int ret;
	 ret = load_key(ectx, outPrivate, outPublic,
		parent, aes_key);
		if (ret) {
		printf("Error loading key\n");
		exit(1);
		}
	/*rv = Esys_Load(ectx,
			parent,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			outPrivate,
			outPublic,
			aes_key);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Load: 0x%x\n", rv);
		exit(1);
	}*/

}

void create_and_load_rsa_key(ESYS_CONTEXT *ectx, ESYS_TR parent, ESYS_TR *rsa_key) {

    TPM2B_PUBLIC pub_templ = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_SYMCIPHER,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_SIGN_ENCRYPT  |
								 TPMA_OBJECT_DECRYPT  |
								 TPMA_OBJECT_FIXEDTPM |
								 TPMA_OBJECT_FIXEDPARENT |
								 TPMA_OBJECT_SENSITIVEDATAORIGIN),
               .authPolicy = {
				 .size = 0,
			 },
			 .parameters = {
				 .symDetail = {
						 .sym = {
								 .algorithm = TPM2_ALG_AES,
								 .keyBits = { .aes = 128 },
								 .mode = { .aes = TPM2_ALG_NULL }
						 },
				 },
			},
		},
	};

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
				/* TODO: Set this to a non-hard coded password, or better yet use a policy */
                 .size = 8,
                 .buffer ={0} 
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TSS2_RC rv = Esys_Create(
		ectx,
		parent,
    	ESYS_TR_PASSWORD,
		ESYS_TR_NONE,
		ESYS_TR_NONE,
		&inSensitive,
		&pub_templ,
		&outsideInfo,
		&creationPCR,
		&outPrivate,
		&outPublic,
		&creationData,
		&creationHash,
		&creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Create: 0x%x\n", rv);
		exit(1);
	}

	/* if you want this key again, save the TPM2B_PUBLIC and TPM2B_PRIVATE for
	 * future use. You just need to call load again.
	 */
	 int ret;
	 ret = load_key(ectx, outPrivate, outPublic,
		parent, rsa_key);
		if (ret) {
		printf("Error loading key\n");
		exit(1);
		}
	/*rv = Esys_Load(ectx,
			parent,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			outPrivate,
			outPublic,
			aes_key);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Load: 0x%x\n", rv);
		exit(1);
	}*/

}


void enc_dec(ESYS_CONTEXT *ectx,
		TPMI_YES_NO decrypt,
		ESYS_TR aes_key,
		TPM2B_MAX_BUFFER *in,
		TPM2B_MAX_BUFFER **out) {

	const TPM2B_AUTH authValue = {
			.size = 8,
			.buffer ={0} ,
	};

	TSS2_RC rv =
	    Esys_TR_SetAuth(ectx, aes_key, &authValue);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_TR_SetAuth: 0x%x\n", rv);
		exit(1);
	}

	/* initialize to GOOD random values */
	TPM2B_IV iv_in = {
			.size = 16,
			.buffer = { 0 },
	};

	/* iv for next block */
	TPM2B_IV *iv_out = NULL;

	/* better to use the EncryptDecrypt2 call if your TPM supports it */
	rv = Esys_EncryptDecrypt(ectx,
			aes_key,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			decrypt,
			TPM2_ALG_CBC,
			&iv_in,
			in,
			out,
			&iv_out);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_EncryptDecrypt: 0x%x\n", rv);
		exit(1);
	}
}

void encrypt(ESYS_CONTEXT *ectx, ESYS_TR aes_key,
		TPM2B_MAX_BUFFER *ptext,
		TPM2B_MAX_BUFFER **ctext) {

	enc_dec(ectx, TPM2_NO, aes_key,
		ptext, ctext);
}

void decrypt(ESYS_CONTEXT *ectx, ESYS_TR aes_key,
		TPM2B_MAX_BUFFER *ctext,
		TPM2B_MAX_BUFFER **ptext) {

	enc_dec(ectx, TPM2_YES, aes_key,
		ctext, ptext);
}
void sign(ESYS_CONTEXT *ectx, ESYS_TR aes_key,
		TPM2B_DIGEST *digest,
		TPM2B_MAX_BUFFER **ptext){
		TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
		TPMT_TK_HASHCHECK hash_validation = {
		.tag = TPM2_ST_HASHCHECK,
		.hierarchy = TPM2_RH_OWNER,
		.digest = {0}
	    	};
		/*
	TSS2_RC rv = Esys_Sign(
        	ectx,
        	primaryHandle,
        	ESYS_TR_PASSWORD,
        	ESYS_TR_NONE,
        	ESYS_TR_NONE,
        	&digest,
        	&inScheme,
        	&hash_validation,
        	&signature);
        	if (rv != TSS2_RC_SUCCESS) {
			fprintf(stderr, "Esys_Sign: 0x%x\n", rv);
			exit(1);
		}*/
		}
		
void verify(ESYS_CONTEXT *ectx){/*
	TSS2_RC rv = Esys_VerifySignature(
        ectx,
        primaryHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digest,
        signature,
        &validation);
        if (rv != TSS2_RC_SUCCESS) {
			fprintf(stderr, "Esys_Sign: 0x%x\n", rv);
			exit(1);
		}*/

}
void string2ByteArray(char* input, BYTE* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}


int main(int argc, char *argv[]) {

	/*
	 * create a connection to the TPM letting ESAPI choose how to get there.
	 * If you need more control, you can use tcti and tcti-ldr libraries to
	 * get a TCTI pointer to use for the tcti argument of Esys_Initialize.
	 */
	fprintf(stderr, "****************************\n");
	fprintf(stderr, "* DO NOT USE IN PRODUCTION *\n");
	fprintf(stderr, "****************************\n");

	printf("main: initializing esys\n");

	ESYS_CONTEXT *ectx = NULL;

	TSS2_RC rv = Esys_Initialize(&ectx,
			NULL, /* let it find the TCTI */
			NULL);/* Use whatever ABI */
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: 0x%x\n", rv);
		return 1;
	}
	TPM2_CAP capability = TPM2_CAP_TPM_PROPERTIES;
	    UINT32                         property = TPM2_PT_LOCKOUT_COUNTER;
    UINT32                         propertyCount = 1;
    TPMS_CAPABILITY_DATA           *capabilityData;
    TPMI_YES_NO                    moreData;
	rv = Esys_GetCapability(ectx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_GetCapability: 0x%x\n", rv);
		return 1;
	}
	printf("%s\n", *capabilityData);
	ESYS_TR parent = ESYS_TR_NONE;
	create_primary(ectx, &parent);

	ESYS_TR aes_key = ESYS_TR_NONE;
	create_and_load_aes_key(ectx, parent, &aes_key);
	
	TPM2B_MAX_BUFFER ptext = {
			.size = 16,
			.buffer ={'h', 'e', 'l', 'l', 'o',  ' ','w', 'o', 'r', 'l', 'd'} 
	};

	TPM2B_MAX_BUFFER *ctext = NULL;
	unsigned char 		*data = NULL;
	size_t 			length;
	char			messageFilename[] = "test";
	    TPMT_SIGNATURE *signature = NULL;
	char *number;
    size_t digestSize, signatureSize;
	int r = open_read_and_close (messageFilename, (void**)&number, &digestSize);
	int len = strlen(*number);
	BYTE arr[len];
	string2ByteArray(number,arr);
	
	    TPM2B_DIGEST digest = {
	    	.size = len,
	    	.buffer = arr
	    
	    }
	printf("return: %d\n", r);
    	printf("%s\n", digest.buffer);

	printf("Encrypting Ciphertext\n");

	encrypt(ectx, aes_key,
			&ptext,
			&ctext);

	printf("Decrypting: \"hello world\"\n");

	TPM2B_MAX_BUFFER *ptext2 = NULL;
	decrypt(ectx, aes_key,
			ctext,
			&ptext2);

	printf("Decrypted data: %.*s\n", ptext2->size, ptext2->buffer);

	Esys_Finalize(&ectx);

	return 0;
}
