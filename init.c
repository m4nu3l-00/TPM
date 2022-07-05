#include "TPM.h"



int main(int argc, char *argv[]) {

	printf("main: initializing esys\n");

	ESYS_CONTEXT *ectx = NULL;

	TSS2_RC rv = Esys_Initialize(&ectx,
			NULL, /* pass in TCTI */
			NULL);/* Use whatever ABI */
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: 0x%x\n", rv);
		return 1;
	}


    // Configure hierarchy input
    ESYS_TR hierarchy_choice=ESYS_TR_RH_OWNER;

	

    // Create primary
	ESYS_TR objectHandle = ESYS_TR_NONE;
	char handle[] = "0x81810018";
	create_primary(ectx, &objectHandle, handle);

    // import and load external key
	ESYS_TR rsa_key = ESYS_TR_NONE;
	//char handle[] = "0x81810018";
	char auth[] = "newkeyauth";
	char path[] = "key.pem";
	openssl_import(ectx, objectHandle, &rsa_key, handle, auth, path);

    printf("Done import_and_load_rsa_key\n");    

	TPMI_DH_PERSISTENT persist_handle;	
    bool res = tpm2_util_string_to_uint32(handle, &persist_handle);
    if (!res) {
        fprintf(stderr, "Could not convert persistent handle to a number\n");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}
	int result;
	//int index = 0x800000;
	strcpy(handle, "0x100000b");
	ESYS_TR nv_index = 0;
	result = createNV(ectx, &nv_index);
	if (result != 0) {
        printf("createNV error \n");
		exit(1);
	}
	
	char messageFilename[] = "sym_keyfile.key";
	FILE* in_file = fopen(messageFilename, "rb");
	char *buffer;
	long filelen;

	fseek(in_file, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(in_file);             // Get the current byte offset in the file
	rewind(in_file);                      // Jump back to the beginning of the file

	buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
	fread(buffer, filelen, 1, in_file); // Read in the entire file
	fclose(in_file); // Close the file
	//printf("%d\n", sizeof(buffer));

	//printf("%s\n", buffer);
	
	TPM2B_MAX_NV_BUFFER write_data = { 0 };
	memcpy(write_data.buffer, buffer, filelen);
	write_data.size = filelen;

	result = writeToNV(ectx, &nv_index, &write_data);
	if (result != 0) {
        printf("writeToNV error \n");
		exit(1);
	}  
	
    // flush all transient objects
    /*rv = Esys_FlushContext(ectx, parent);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext error - parent: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		exit(1);
	}    

    rv = Esys_FlushContext(ectx, rsa_key);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext error - rsa_key: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		exit(1);
	}*/

	Esys_Finalize(&ectx);

	return 0;
}
