/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __DJREWRITE_COMMON_UTILS__H_
#define __DJREWRITE_COMMON_UTILS__H_
#ifdef __cplusplus
	extern "C" {
#endif
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>

#define SAFESTR(str) (str!=NULL?str:"NULL")
#define SAFESTRBLANK(str) (str!=NULL?str:"")
#define SAFESTRELSE(str,elstr) (str!=NULL?str:elstr)
#define SAFESTRLEN(str) (str!=NULL?strlen(str):0)
#define BOOLTOSTR(bol) (bol!=1?"FALSE":"TRUE")
#define STRTOBOOL(str) ((str!=NULL&&(strcmp(str,"true")==0||strcmp(str,"TRUE")==0||strcmp(str,"on")==0))?1:0)
#define SAFEDUP(p,str) (str==NULL?NULL:apr_pstrdup(p,str))

// Use this macro instead of cu_getElement
#ifndef APR_ARRAY_IDX
	#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif

// Use this macro instead of apr_array_push
#ifndef APR_ARRAY_PUSH
	#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

// Use this macro instead of cu_getElementRef
#ifndef APR_ARRAY_REF_IDX
	#define APR_ARRAY_REF_IDX(ary,i,type) (((type *)(ary)->elts)+i)
#endif

// Use this macro instead of cu_getElementCount
#ifndef APR_ARRAY_NUM_ELTS
	#define APR_ARRAY_NUM_ELTS(ary) ( (ary!=NULL) ? (ary)->nelts : 0 )
#endif

int cu_getElementCount(apr_array_header_t* data);

char* cu_getElement(apr_array_header_t* data, int element);

void** cu_getElementRef(apr_array_header_t* data, int element);

char* cu_getNodeDetails(apr_pool_t* p,unsigned int defaultHttpPort);
char* cu_templateString(apr_pool_t* p, char* src, apr_hash_t* vals);

time_t cu_dateStringToSeconds(const char* dateString);
char* cu_nonHtmlToHtmlChar(apr_pool_t*p, char*src);
char* cu_getCurrentDateByFormat2(apr_pool_t* p, const char* format);

char* cu_getFormattedUrl(apr_pool_t *p, char* cur, char* namespaceid);
char* cu_getTrimmedStr(apr_pool_t* p, char* str);
apr_array_header_t* cu_parseStringArrayFromCsv(apr_pool_t* p, int arraySz, const char* delim, char* src);
char* cu_serializeCsvFromStringArray(apr_pool_t* p, apr_array_header_t* arr);
apr_table_t* cu_parseNvpTableFromCsv(apr_pool_t* p,const char* itemDelim,const char* nvpDelim, char* src);

//
// RSA implementation
//
// by key
char* comu_rsa256Sign(apr_pool_t*p, unsigned char * data,int dataLen,unsigned char * privateKey, char** error);
int comu_rsa256Verify(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * publicKey, char* encodedSign, char** error);
int comu_rsaVerifyByModulus(apr_pool_t*p, const char* algorithm, unsigned char * data,int dataLen, const char* modulus, const char* exponent, char* encodedSign, char** error);
char* comu_rsaEncrypt(apr_pool_t*p, unsigned char * data,int data_len,unsigned char * publicKey, char** error);
char* comu_rsaDecrypt(apr_pool_t*p, unsigned char * encrypted, unsigned char * privateKey, char** error);

// by keyFile
char* comu_rsa256SignFromFile(apr_pool_t*p, unsigned char * data,int dataLen,unsigned char * privateKeyFile, char** error);
int comu_rsa256VerifyFromFile(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * publicKeyFile, char* encodedSign, char** error);
char* comu_rsaEncryptFromFile(apr_pool_t*p, unsigned char * data,int data_len,unsigned char * publicKeyFile, char** error);
char* comu_rsaDecryptFromFile(apr_pool_t*p, unsigned char * encrypted, unsigned char * privateKeyFile, char** error);
char* comu_rsaPrintModulusFromFile(apr_pool_t*p, unsigned char * publicKeyFile, int isPublic);

// AES encryption/decryption
typedef struct oidc_cipher_cfg{
	apr_pool_t*p;
	char* crypto_passphrase;
	void* encrypt_ctx;
	void* decrypt_ctx;
}oidc_cipher_cfg;
apr_byte_t comu_aesCryptoInit(apr_pool_t*p, oidc_cipher_cfg *cfg,
		char** error);
unsigned char *comu_aesEncrypt(apr_pool_t*p, oidc_cipher_cfg *cfg,
		unsigned char *plaintext, int *len, char** error);
unsigned char *comu_aesDecrypt(apr_pool_t*p, oidc_cipher_cfg *cfg,
		unsigned char *ciphertext, int *len, char** error);
apr_byte_t comu_aesCryptoDestroy(oidc_cipher_cfg *cfg);
int cu_encryptAndBase64urlEncode(apr_pool_t*p, oidc_cipher_cfg*cfg, char **dst,
		const char *src, char** error);
int cu_base64urlDecodeAndDecrypt(apr_pool_t*p, oidc_cipher_cfg*cfg, char **dst,
		const char *src, char** error);

// uuid function
char* cu_generateGuid(apr_pool_t* p);

// base64 functions
int cu_base64urlEncode(apr_pool_t*p, char **dst, const char *src,
		int src_len, int remove_padding);
int cu_base64urlDecode(apr_pool_t*p, char **dst, const char *src);

#ifdef __cplusplus
	}
#endif
#endif//__DJREWRITE_COMMON_UTILS__H_
