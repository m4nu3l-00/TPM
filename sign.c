#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cerrno>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            printf(param" must be specified\n"); \
            return false; \
        } \
    } while(0)


static ESYS_TR objectHandle;

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
    printf("path:%s\n", path);
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

static size_t readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    do {
        bread += fread(&data[bread], 1, size-bread, f);
    } while (bread < size && !feof(f) && errno == EINTR);

    return bread;
}

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            printf("Error getting current file offset for file \"%s\" error: "
                    "%s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            printf("Error seeking to end of file \"%s\" error: %s", path,
                    strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            printf("ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            printf(
                    "Could not restore initial stream position for file \"%s\" "
                    "failed: %s", path, strerror(errno));
        }
        return false;
    }

    // size cannot be negative at this point 
    *file_size = (unsigned long) size;
    return true;
}

bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path) {

    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        //  get_file_size() logs errors 
        return false;
    }

    //  max is bounded on *size 
    if (file_size > *size) {
        if (path) {
            printf(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u", path, file_size, *size);
        }
        return false;
    }

    *size = readx(f, buf, *size);
    if (*size < file_size) {
        if (path) {
            printf("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    return true;
}


bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {

    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("Could not open file \"%s\" error %s\n", path, strerror(errno));
        return false;
    }

    bool result = file_read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}


TPMT_SIGNATURE load_file(const char *path){
	TPMT_SIGNATURE sign = {0};
	//TPMT_SIGNATURE * sign;
	size_t offset = 0;
	size_t size;
	if (!path) {
        return sign;
    }
	
	TPM2B_MAX_BUFFER input_data;
    input_data.size = BUFFER_SIZE(TPM2B_MAX_BUFFER, buffer);
    
    bool result = files_load_bytes_from_path(path, input_data.buffer, &input_data.size);
    if (!result) {
        printf("Could not load data from file \"%s\"\n", path ? path : "<stdout>");
    }
	printf("buffer: %d\n", input_data.buffer);
   
	TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(input_data.buffer, input_data.size, &offset, &sign);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("Error serializing signature structure: 0x%x", rc);
        return sign;
    }
	printf("here2\n");
    return sign;
}


































static bool writex(FILE *f, UINT8 *data, size_t size) {

    size_t wrote = 0;
    size_t index = 0;
    do {
        wrote = fwrite(&data[index], 1, size, f);
        if (wrote != size) {
            if (errno != EINTR) {
                return false;
            }
            // 
        }
        size -= wrote;
        index += wrote;
    } while (size > 0);

    return true;
}
bool files_write_bytes(FILE *out, uint8_t bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return writex(out, bytes, len);
}

bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size) {

    if (!buf) {
        return false;
    }

    if (!path) {
        return true;
    }

    FILE *fp = path ? fopen(path, "wb+") : stdout;
    if (!fp) {
        printf("Could not open file \"%s\", error: %s", path, strerror(errno));
        return false;
    }

    bool result = files_write_bytes(fp, buf, size);
    if (!result) {
        printf("Could not write data to file \"%s\"", path ? path : "<stdout>");
    }

    if (fp != stdout) {
        fclose(fp);
    }

    return result;
}

bool files_save_signature(TPMT_SIGNATURE *signature, const char *path)
{
    size_t offset = 0;
    UINT8 buffer[sizeof(*signature)];
	printf("sizeof(buffer): %d\n",sizeof(buffer));
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, buffer, sizeof(buffer), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("Error serializing signature structure: 0x%x", rc);
        return false;
    }
    return files_save_bytes_to_file(path, buffer, offset);
}



void create_primary(ESYS_CONTEXT *ectx){
	printf("t1: starting\n");
    TPM2B_PUBLIC pub_templ = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_RSA,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_SIGN_ENCRYPT  |
								 TPMA_OBJECT_FIXEDTPM |
								 TPMA_OBJECT_FIXEDPARENT |
								 TPMA_OBJECT_SENSITIVEDATAORIGIN),
			.authPolicy = {
				 .size = 0,
			 },
			.parameters = {
				.rsaDetail = {
					 .symmetric = {
						 .algorithm = TPM2_ALG_NULL,
						 .keyBits = {.aes = 128},
					 .mode = {.aes = TPM2_ALG_CFB}},
					 .scheme = {
						  .scheme = TPM2_ALG_RSAPSS,
						  .details = {
							  .rsapss = { .hashAlg = TPM2_ALG_SHA256 }
						  }
					  },
					 .keyBits = 2048,
					 .exponent = 0,
				 },
			},
			.unique = {
				.rsa = {
					 .size = 0,
					 .buffer = {},
				},
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

    printf("t1: creating key\n");

    TSS2_RC rv = Esys_CreatePrimary(ectx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &pub_templ,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "t1: Esys_CreatePrimary: 0x%x\n", rv);
	}
}
	
void sign(ESYS_CONTEXT *ectx, TPMT_SIGNATURE **signature){
	TPMT_SIGNATURE *sign;
	TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
	char messageFilename[] = "test";
	char *number;
    size_t digestSize, signatureSize;
	// if encrypted better use files_load_bytes_from_path
	int r = open_read_and_close (messageFilename, (void**)&number, &digestSize);
	TPM2B_MAX_BUFFER hash = {
	    	.size = digestSize,
	    	.buffer = {}
	    
	    };
	memcpy(hash.buffer, number, 1 + digestSize);
    printf("t2: signing\n");
	TSS2_RC rv;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA256;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *valid = NULL;

     rv = Esys_Hash(
        ectx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &hash,
        hashAlg,
        ESYS_TR_RH_OWNER,
        &digest,
        &valid);
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: 0x%x\n", rv);
	}
	
     rv = Esys_Sign(
        ectx,
        objectHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        digest,
        &inScheme,
        valid,
        &sign);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "t2: Esys_Sign: 0x%x\n", rv);
	}
	(*signature) = sign;
	return;
}

void verify(ESYS_CONTEXT *ectx, TPMT_SIGNATURE *signature){
	char messageFilename[] = "test";
	char *number;
    size_t digestSize, signatureSize;
	int r = open_read_and_close (messageFilename, (void**)&number, &digestSize);
	TPM2B_MAX_BUFFER hash = {
	    	.size = digestSize,
	    	.buffer = {}
	    
	    };
	memcpy(hash.buffer, number, 1 + digestSize);
    printf("t2: verify\n");
	TSS2_RC rv;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA256;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *valid = NULL;
	
	rv = Esys_Hash(
        ectx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &hash,
        hashAlg,
        ESYS_TR_RH_OWNER,
        &digest,
        &valid);
	
	TPMT_TK_VERIFIED *validation = NULL;
	rv = Esys_VerifySignature(
        ectx,
        objectHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        digest,
        signature,
        &validation);
	printf("Esys_VerifySignature: 0x%x\n", rv);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_VerifySignature: 0x%x\n", rv);
		exit(1);
	}
	
}

int main(int argc, char *argv[]) {

	ESYS_CONTEXT *ectx = NULL;
	//ESYS_TR objectHandle = NULL;

	TSS2_RC rv = Esys_Initialize(&ectx,
			NULL, /* let it find the TCTI */
			NULL);/* Use whatever ABI */
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: 0x%x\n", rv);
		return 1;
	}

	create_primary(ectx);


	TPMT_SIGNATURE *signature= NULL;
	sign(ectx, &signature);
	char path[] = "test1";
	files_save_signature(signature, path);
	printf("here2\n");
	TPMT_SIGNATURE sign = load_file(path);
	printf("here2\n");
	verify(ectx, &sign);

	Esys_Finalize(&ectx);


	return 0;
}