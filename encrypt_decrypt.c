#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>



FILE * load(const char * path, const char * mode)
{
        FILE * fp_src;
        fp_src=fopen(path,"rb");
        // encrypt source file & store the encrypted codes into a new file
        // open encrypted file, & return the file pointer
        return fp_src;
}

void write(const char * path, unsigned char * enc_out)
{
        FILE * fp_src;
		int i;
        fp_src=fopen(path,"wb");
		//printf("enc_out:\t");    
		//printf("%s",enc_out);
		/*for(i=0;*(enc_out+i)!=0x00;i++)
			printf("%X ",*(enc_out+i));*/
		if(fp_src){
			for(i=0;*(enc_out+i)!=0x00;i++)
				fputc(*(enc_out+i), fp_src);
				//fprintf(fp_src,"%X",*(enc_out+i));
            fclose(fp_src);
        }
        // encrypt source file & store the encrypted codes into a new file
        // open encrypted file, & return the file pointer
}


void encrypt(char * reading_path, unsigned char* key, char * writing_path){
	AES_KEY enc_key;
	FILE * fp;
	unsigned char * enc;
	unsigned char * text;
	int encrylen;
	
	fp=load(reading_path,"r");
	text=(unsigned char *)malloc(encrylen * sizeof(char));
    fread(text,encrylen,1,fp);
	
	printf("%s\n",text);
	enc=(unsigned char *)malloc(encrylen * sizeof(char));
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_encrypt(text, enc, &enc_key);
	write(writing_path, enc);
	
	
}

void decrypt(char * reading_path, unsigned char* key){
	AES_KEY dec_key;
	FILE * fp;
	unsigned char * enc;
	unsigned char * dec;
	int encrylen;
	
	fp=load(reading_path,"r");
	enc=(unsigned char *)malloc(encrylen * sizeof(char));
	dec=(unsigned char *)malloc(encrylen * sizeof(char));
	fread(enc,encrylen,1,fp);
	AES_set_decrypt_key(key,128,&dec_key);
    AES_decrypt(enc, dec, &dec_key);
	
	printf("\ndecrypted:\t");
	printf("%s ",dec);
    for(int i=0;*(dec+i)!=0x00;i++)
        printf("%X ",*(dec+i));
	
}


int main()
{

	char path[] = "/home/user/tpm/Code/build/test";
	char path_2[] = "/home/user/tpm/Code/build/test_3";
	
    unsigned char key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	encrypt(path, key, path_2);
	decrypt(path_2, key);
	

    return 0;
} 