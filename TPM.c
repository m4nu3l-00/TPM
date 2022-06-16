#include <tss2/tss2_fapi.h>
#include <string.h>
#include <stdio.h>
#include <tss2/tss2_rc.h>


int createEK(ESYS_CONTEXT *ectx){

	ESYS_TR parent = ESYS_TR_NONE;
	create_primary(ectx, &parent);
/*
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
	*/
    return 0;
} 
int createKeys(ESYS_CONTEXT *esysContext, ESYS_TR *parent){
// TODO: Create key with openssl
} 


int createNV(ESYS_CONTEXT *ectx, int index){
	/* build a template for the NV index */
	TPM2B_NV_PUBLIC pub_templ = {
		/* this is counter intuitive, but it tells the TSS2 library to calculate this 			for us */
		.size = 0,
		/* The things that define what NV index we are creating */
		.nvPublic = {
			/* Create at NV Index 1 or 0x1000001 */
			.nvIndex =  nv_index,
			/* uses sha256 to identify the tpm object by name */
			.nameAlg = TPM2_ALG_SHA256,
			/* allows the owner password or index password r/w access */
			.attributes = TPMA_NV_OWNERWRITE |
				TPMA_NV_OWNERREAD            |
				TPMA_NV_AUTHWRITE            |
				TPMA_NV_AUTHREAD,
			/* can hold 64 bytes of data */
			.dataSize = 64
		},
	};
	ESYS_TR nv_index=index;
	ESYS_TR rv = Esys_NV_DefineSpace(
	    ectx,
	    ESYS_TR_RH_OWNER, /* create an NV index in the owner hierarchy */
	    ESYS_TR_PASSWORD,
	    ESYS_TR_NONE,
	    ESYS_TR_NONE,
	    NULL,
	    &pub_templ,
	    &nv_index);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_NV_DefineSpace: 0x%x\n", rv);
		if (nv_index) {
		int rc2 = Esys_NV_UndefineSpace(
			ectx,
			ESYS_TR_RH_OWNER,
			nv_index,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE);
		if (rc2 != TSS2_RC_SUCCESS) {
			fprintf(stderr, "Esys_NV_UndefineSpace: 0x%x\n", rc2);
		}
		}
		Esys_Finalize(&ectx);
		return 1;
	}
	
	rv = Esys_TR_FromTPMPublic(
		ectx,
		nv_index, //Fix
		ESYS_TR_NONE,
		ESYS_TR_NONE,
		ESYS_TR_NONE,
		&nv_index);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_TR_FromTPMPublic: 0x%x\n", rv);
		if (nv_index) {
		int rc2 = Esys_NV_UndefineSpace(
			ectx,
			ESYS_TR_RH_OWNER,
			nv_index,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE);
		if (rc2 != TSS2_RC_SUCCESS) {
			fprintf(stderr, "Esys_NV_UndefineSpace: 0x%x\n", rc2);
		}
		}
		Esys_Finalize(&ectx);
		return 1;
	}
	return 0;
}

int writeToNV(ESYS_CONTEXT *ectx, int index, TPM2B_MAX_NV_BUFFER write_data){
	ESYS_TR nv_index=index;
	TSS2_RC rv = Esys_NV_Write(
	    ectx,
	    nv_index, /* authenticate to the NV index using the NV index password */
	    nv_index, /* the nv index to write to */
	    ESYS_TR_PASSWORD,
		ESYS_TR_NONE,
		ESYS_TR_NONE,
	    &write_data,
	    0);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_NV_Write: 0x%x\n", rv);
		return 1;
	}
	return 0;


}

int readFromNV(ESYS_CONTEXT *ectx, int index, PM2B_MAX_NV_BUFFER *read_data){
	ESYS_TR nv_index=index;
	TSS2_RC rv = Esys_NV_Read(
	    ectx,
	    nv_index, /* authenticate to the NV index using the NV index password */
	    nv_index, /* the nv index to read from */
	    ESYS_TR_PASSWORD,
	    ESYS_TR_NONE,
	    ESYS_TR_NONE,
	    256, //fix number
	    0,
	    &read_data);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_NV_Read: 0x%x\n", rv);
		return 1;
	}
	return 0;

}



int loadKeys(ESYS_CONTEXT *ectx, TPM2B_PRIVATE *outPrivate, TPM2B_PUBLIC *outPublic,
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

int signData(ESYS_CONTEXT *esysContext){

    return 0;
} 

int checkSingature(ESYS_CONTEXT *esysContext){

    return 0;
} 

int decryptData(ESYS_CONTEXT *esysContext){

    return 0;
} 

int encryptData(ESYS_CONTEXT *esysContext){

    return 0;
} 
