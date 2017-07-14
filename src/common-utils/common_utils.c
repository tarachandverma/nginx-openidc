/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#include <common_utils.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <apr_time.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <apr_file_io.h>
#include <apr_uuid.h>

char* cu_getElement(apr_array_header_t* data, int element){
	 if(data!=NULL&&data->nelts>element&&element>=0){
     	return ((char**)data->elts)[element];
	 }
	 return NULL;
}

void** cu_getElementRef(apr_array_header_t* data, int element){
	if(data!=NULL&&data->nelts>element&&element>=0){
     	return ((void**)data->elts)+element;
	}
	return NULL;
}

char* cu_getNodeDetails(apr_pool_t* p,unsigned int defaultHttpPort){
	int i;
	//for second ip get test
	struct ifaddrs *ifa = NULL, *ifp = NULL;
	socklen_t salen;
	char ip[512];
	char* ret=NULL;

	if (getifaddrs (&ifp) >= 0){
		i=0;
		for (ifa = ifp; ifa&&ifa->ifa_addr; ifa = ifa->ifa_next){
			if (ifa->ifa_addr->sa_family == AF_INET)
				salen = sizeof (struct sockaddr_in);
			else if (ifa->ifa_addr->sa_family == AF_INET6)
				salen = sizeof (struct sockaddr_in6);
			else
				continue;

			if (getnameinfo (ifa->ifa_addr, salen,ip, sizeof (ip), NULL, 0, NI_NUMERICHOST) < 0){
				continue;
				}

			if(strcmp(ip,"127.0.0.1")!=0&&strcmp(ip,"::1")!=0){ //don't need to know localhost ip4 or ip6
				if(ifa->ifa_addr->sa_family == AF_INET){
					if(i==0)
						ret=apr_psprintf(p,"%s:%u",ip,defaultHttpPort);
					else
						ret=apr_psprintf(p,"%s,%s:%u",ret,ip,defaultHttpPort);
					}
				else{
					if(i==0)
						ret=apr_pstrdup(p,ip);
					else
						ret=apr_pstrcat(p,ret,",",ip,NULL);
					}
				i++;
				}
			}
		 freeifaddrs (ifp);
		}
	return ret;
}

#define CTEM_PRE	"{"
#define CTEP_POST	"}"
	char* cu_templateString(apr_pool_t* p, char* src, apr_hash_t* vals){
		char* cpy=NULL;
		char* ret=NULL,*begin=NULL, *end=NULL, *token=NULL, *tval=NULL;
		if(src==NULL){ return NULL; }

		cpy=apr_pstrdup(p,src);

		begin=strstr(cpy,"{");
		while(begin!=NULL){

			//find end
			end=strstr(begin,"}");

			//do append
			if(end!=NULL){
				*begin='\0';
				*end='\0';
				token=begin+1;
				tval=vals!=NULL?SAFESTRBLANK(apr_hash_get(vals,token,APR_HASH_KEY_STRING)):"";
				if(ret==NULL){
					ret=apr_pstrcat(p,cpy,tval,NULL);
				}else{
					ret=apr_pstrcat(p,ret,cpy,tval,NULL);
				}
				begin=cpy=end+1;
			}else{
				begin++;
			}

			//continue
			begin=strstr(begin,"{");
		}
		if(cpy!=NULL&&*cpy!='\0'){
			ret=apr_pstrcat(p,ret,cpy,NULL);
		}
		return ret;
	}

        time_t cu_dateStringToSeconds(const char* dateString){
        		struct tm tm;

        		if(dateString==NULL||strptime(dateString, "%a %b %d %H:%M:%S %Y", &tm)==0) return -1;
        		tm.tm_isdst=-1;//daylight saving
        		return mktime(&tm);
        	}

	// format is same asa apr_strftime
	/*
	%a	Abbreviated weekday name *	Thu
	%A	Full weekday name * 	Thursday
	%b	Abbreviated month name *	Aug
	%B	Full month name *	August
	%c	Date and time representation *	Thu Aug 23 14:55:02 2001
	%d	Day of the month (01-31)	23
	%H	Hour in 24h format (00-23)	14
	%I	Hour in 12h format (01-12)	02
	%j	Day of the year (001-366)	235
	%m	Month as a decimal number (01-12)	08
	%M	Minute (00-59)	55
	%p	AM or PM designation	PM
	%S	Second (00-61)	02
	%U	Week number with the first Sunday as the first day of week one (00-53)	33
	%w	Weekday as a decimal number with Sunday as 0 (0-6)	4
	%W	Week number with the first Monday as the first day of week one (00-53)	34
	%x	Date representation *	08/23/01
	%X	Time representation *	14:55:02
	%y	Year, last two digits (00-99)	01
	%Y	Year	2001
	%Z	Timezone name or abbreviation	CDT
	%%	A % sign	%
	*/
	char* cu_getCurrentDateByFormat2(apr_pool_t* p, const char* format){
		#define STR_SIZE	80
		apr_status_t status;
		apr_time_exp_t t;
		apr_size_t sz;
		char buf[STR_SIZE];

		if ( format==NULL ) return NULL;

		memset(buf, '\0', STR_SIZE);

		apr_time_exp_lt(&t, apr_time_now());
		status = apr_strftime(buf, &sz, STR_SIZE, format, &t);
		//assert (status == APR_SUCCESS );

		return apr_pstrdup(p, buf);
	}

	int cu_getElementCount(apr_array_header_t* data){
		return (data!=NULL) ? data->nelts : 0;
	}

	typedef struct html_char{
		const char c;
		const char* str;
	}html_char;

	static const html_char html_table[] = {
			{'<',"&lt;"},
			{'>',"&gt;"},
			{'\'',"&#39;"}
	};

	static const char* cu_getHtmlString(const char c) {
		int i;
		for(i=0; i < sizeof(html_table)/sizeof(html_char); i++ ){
			if(html_table[i].c==c) return html_table[i].str;
		}
		return NULL;
	}

	char* cu_nonHtmlToHtmlChar(apr_pool_t*p, char*src){
		if(src==NULL) return NULL;
		int size=8*strlen(src);
		char*ret=apr_palloc(p, size+1);
		char*q=ret;
		const char* str = NULL;

		while(*src!='\0'){
			if(str = cu_getHtmlString(*src)){
				strcpy(q, str);
				q += strlen(str);
				src++;
			}else{
				*q++=*src++;
			}
		}
		*q='\0';

		return ret;
	}

	char* cu_getFormattedUrl(apr_pool_t *p, char* cur, char* namespaceid) {
		int x,queryStrState=0;
		int curlen=0;
		if(cur==NULL|namespaceid==NULL) return cur;

		curlen=strlen(cur);
		for(x=curlen-1;x>=0;x--){
			if(cur[x]=='?'){
				if(x==curlen-1){
					queryStrState=2;
				}else{
					queryStrState=1;
				}
			}
		}
		if(queryStrState==0){
			return apr_pstrcat(p,cur,"?ns=",namespaceid,NULL);
		}else if(queryStrState==1){
			return apr_pstrcat(p,cur,"&ns=",namespaceid,NULL);
		}else if(queryStrState==2){
			return apr_pstrcat(p,cur,"ns=",namespaceid,NULL);
		}
	}

	char* cu_getTrimmedStr(apr_pool_t* p, char* str){
		char* start=NULL,*end=NULL;
		int len=0,size=0;

		if(str==NULL){
			return NULL;
		}

		start=str;
		while(*start!='\0'&&(*start==' '||*start=='\t'||*start=='\n'||*start=='\r')){
			start++;
		}
		len=strlen(str);
		end=&(str[len-1]);
		while(*end!='\0'&&(*end==' '||*end=='\t'||*end=='\n'||*end=='\r')){
			end--;
		}

		size=end-start+1;
		if(size<=0){return NULL;}
		return apr_pstrndup(p,start,size);
	}

	apr_array_header_t* cu_parseStringArrayFromCsv(apr_pool_t* p, int arraySz, const char* delim, char* src){
		char *srccpy=NULL, *prodStr=NULL, *p1=NULL;
        char **val=NULL;
        apr_array_header_t* arr=(apr_array_header_t*)apr_array_make(p,arraySz,sizeof(char*));
        if(src==NULL){return arr;}

        srccpy=apr_pstrdup(p,src);

        if(arr==NULL){
                return NULL;
        }
        prodStr=apr_strtok(srccpy,delim,&p1);
        while(prodStr!=NULL){
                val= (char**) apr_array_push(arr);
                *val = (char*) apr_pstrdup(p,prodStr);
                prodStr =strtok_r(NULL,delim,&p1);
        }

		return arr;
	}
	char* cu_serializeCsvFromStringArray(apr_pool_t* p, apr_array_header_t* arr){
		char* ret=NULL;
		int i=0;
		if(arr!=NULL){
			for(i=0;i<arr->nelts;i++){
				if(i==0){
					ret=apr_pstrdup(p,cu_getElement(arr,i));
				}else{
					ret=apr_pstrcat(p,ret,",",cu_getElement(arr,i),NULL);
				}
			}
		}
		return ret;
	}
	apr_table_t* cu_parseNvpTableFromCsv(apr_pool_t* p,const char* itemDelim,const char* nvpDelim, char* src){
		apr_array_header_t* list=NULL;
		apr_table_t* ret=NULL;
		char* item=NULL, *name=NULL,*val=NULL;
		int i=0;

		if(src==NULL){return NULL;}
		list=cu_parseStringArrayFromCsv(p,4,itemDelim,src);
		if(list!=NULL&&list->nelts>0){
			ret=apr_table_make(p,list->nelts);
			for(i=0;i<list->nelts;i++){
				item=cu_getElement(list,i);
				name=item;
				val=strstr(item,nvpDelim);
				if(val!=NULL&&(*(val+1))!='\0'){
					*val='\0';
					val++;
					apr_table_set(ret,name,val);
				}
			}
		}
		if(apr_is_empty_table(ret)){
			return NULL;
		}else{
			return ret;
		}
	}

	// RSA implementation
	int padding = RSA_PKCS1_PADDING;
	#define OAUTH_ERROR_STRING_MAX_LENGTH	256

	static void comu_printHex(const char *title, const unsigned char *s, int len) {
		int     n;
		printf("%s:", title);
		for (n = 0; n < len; ++n) {
			if ((n % 16) == 0) {
				printf("\n%04x", n);
			}
			printf(" %02x", s[n]);
		}
		printf("\n");
	}

	static RSA* comu_createRSA(apr_pool_t* p, unsigned char* key, int public, char** error) {
		BIO* mem = NULL;
		RSA* rsa = NULL;
		char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];

		ERR_load_crypto_strings();

		mem = BIO_new_mem_buf(key, -1);
		if (mem == NULL) {
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			 return NULL;
		}

		if(public) {
			rsa = PEM_read_bio_RSA_PUBKEY(mem, NULL, NULL, NULL);
		}else{
			rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
		}
		BIO_free (mem);

		if (rsa == NULL) {
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
		}

		return rsa;
	}

	static RSA* comu_createRSAFromFile(apr_pool_t* p, unsigned char* keyFile, int public, char** error) {
		RSA* rsa = NULL;
		char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];

		FILE * fp = fopen(keyFile, "rb");
		if (fp == NULL) {
			if(error!=NULL) { *error = apr_pstrdup(p, "unable to open file"); }
			 return NULL;
		}

		ERR_load_crypto_strings();

		rsa= RSA_new() ;
		if(public) {
			rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
		}else{
			rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
		}
		fclose(fp);

		if (rsa == NULL) {
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
		}

		return rsa;
	}

	char* comu_rsa256Sign(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * privateKey, char** error) {
		int retEr;
		unsigned char sign[256]={0};
		unsigned int signLen = 0;
		unsigned char encodeSign[1024];

		RSA* rsa = comu_createRSA(p, privateKey, FALSE, error);
	    if(rsa==NULL) return NULL;

		// sha256
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256(data, dataLen, hash);

		//  signing
		retEr = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &signLen, rsa);
		RSA_free(rsa);

		if(retEr != 1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

		memset(encodeSign,'\0',1024);
	    base64Url_encode(encodeSign, sign, signLen);
	    return apr_pstrdup(p, encodeSign);

	}

	int comu_rsa256Verify(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * publicKey, char* encodedSign, char** error) {
		int retEr;
		unsigned char sign[1024];

		RSA* rsa = comu_createRSA(p, publicKey, TRUE, error);
	    if(rsa==NULL) return FALSE;

	    // sha256
	    unsigned char hash[SHA256_DIGEST_LENGTH];

	    SHA256(data, dataLen, hash);

	    //  verification
		memset(sign,'\0',1024);
	    int signLen = base64Url_decode(sign, (char*)encodedSign, strlen(encodedSign));

	    retEr = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, rsa);
		RSA_free(rsa);

		if(retEr != 1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
		}

		return (retEr == 1) ?  TRUE : FALSE;
	}

static RSA* comu_createRSAByModulus(apr_pool_t* p, const char* modulus, const char* exponent, char** error) {
	RSA* rsa = NULL;
	char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
	unsigned char decoded[1024];

	BIGNUM* bn = NULL;
	int len;

	if(modulus==NULL||exponent==NULL) return NULL;

	memset(decoded,'\0',1024);
	len = base64Url_decode(decoded, modulus, strlen(modulus));
	if(len==0) return NULL;

	BIGNUM *n = BN_bin2bn(decoded, len, NULL);
	if (n == NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "Invalid encoding for modulus\n"); }
		return NULL;
	}

	memset(decoded,'\0',1024);
	len = base64Url_decode(decoded, exponent, strlen(exponent));
	if(len==0) return NULL;

	BIGNUM *e = BN_bin2bn(decoded, len, NULL);
	if (e == NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "Invalid encoding for public exponent\n"); }
		return NULL;
	}

	ERR_load_crypto_strings();
	rsa = RSA_new();
	rsa->e = e;
	rsa->n = n;

	if (rsa == NULL) {
		ERR_error_string(ERR_get_error(), errorBuffer);
		if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
	}

		return rsa;
	}

	int comu_rsaVerifyByModulus(apr_pool_t*p, const char* algorithm, unsigned char * data,int dataLen, const char* modulus, const char* exponent, char* encodedSign, char** error) {
		int retEr;

		RSA* rsa = comu_createRSAByModulus(p, modulus, exponent, error);
	    if(rsa==NULL) return FALSE;

		// RSA sha256
	    if(algorithm!=NULL&&(strcasecmp(algorithm,"RS256")==0)) {
			unsigned char sign[1024];
			unsigned char hash[SHA256_DIGEST_LENGTH];

			SHA256(data, dataLen, hash);

			//  verification
			memset(sign,'\0',1024);
			int signLen = base64Url_decode(sign, (char*)encodedSign, strlen(encodedSign));

			retEr = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, rsa);
			if(retEr != 1) {
				char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
				ERR_error_string(ERR_get_error(), errorBuffer);
				if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			}
	    }else{
	    		if(error!=NULL) { *error = apr_pstrdup(p, "algorithm not supported\n"); }
	    		retEr = 0;
	    }

		RSA_free(rsa);

		return (retEr == 1) ?  TRUE : FALSE;
	}
	char* comu_rsaEncrypt(apr_pool_t*p, unsigned char * data,int dataLen,unsigned char * publicKey, char** error) {
		unsigned char encoded[4098];
		unsigned char  encrypted[4098]={};

		RSA* rsa = comu_createRSA(p, publicKey, TRUE, error);
	    if(rsa==NULL) return NULL;

	    int retEr = RSA_public_encrypt(dataLen,data,encrypted,rsa,padding);
	    RSA_free(rsa);

		if(retEr == -1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

		memset(encoded,'\0',4098);
	    base64Url_encode(encoded, encrypted, retEr);
	    return apr_pstrdup(p, encoded);
	}

	char* comu_rsaDecrypt(apr_pool_t*p, unsigned char * encrypted, unsigned char * privateKey, char** error){
		unsigned char decrypted[4098]={};
		unsigned char decoded[4098];


		RSA* rsa = comu_createRSA(p, privateKey, FALSE, error);
	    if(rsa==NULL) return NULL;

	    int decodedLen = base64Url_decode(decoded, (char*)encrypted, strlen(encrypted));

	    int  retEr = RSA_private_decrypt(decodedLen,decoded,decrypted,rsa,padding);
	    RSA_free(rsa);

		if(retEr == -1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

	    return apr_pstrdup(p, decrypted);
	}

	char* comu_rsa256SignFromFile(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * privateKeyFile, char** error) {
		int retEr;
		unsigned char sign[256]={0};
		unsigned int signLen = 0;
		unsigned char encodeSign[1024];

		RSA* rsa = comu_createRSAFromFile(p, privateKeyFile, FALSE, error);
	    if(rsa==NULL) return NULL;

		// sha256
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256(data, dataLen, hash);

		//  signing
		retEr = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &signLen, rsa);
		RSA_free(rsa);

		if(retEr != 1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

		memset(encodeSign,'\0',1024);
	    base64Url_encode(encodeSign, sign, signLen);
	    return apr_pstrdup(p, encodeSign);

	}

	int comu_rsa256VerifyFromFile(apr_pool_t*p, unsigned char * data,int dataLen, unsigned char * publicKeyFile, char* encodedSign, char** error) {
		int retEr;
		unsigned char sign[1024];

		RSA* rsa = comu_createRSAFromFile(p, publicKeyFile, TRUE, error);
	    if(rsa==NULL) return FALSE;

	    // sha256
	    unsigned char hash[SHA256_DIGEST_LENGTH];

	    SHA256(data, dataLen, hash);

	    //  verification
		memset(sign,'\0',1024);
	    int signLen = base64Url_decode(sign, (char*)encodedSign, strlen(encodedSign));

	    retEr = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, rsa);
		RSA_free(rsa);

		if(retEr != 1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
		}

		return (retEr == 1) ?  TRUE : FALSE;
	}

	char* comu_rsaEncryptFromFile(apr_pool_t*p, unsigned char * data,int dataLen,unsigned char * publicKeyFile, char** error) {
		unsigned char encoded[4098];
		unsigned char  encrypted[4098]={};

		RSA* rsa = comu_createRSAFromFile(p, publicKeyFile, TRUE, error);
	    if(rsa==NULL) return NULL;

	    int retEr = RSA_public_encrypt(dataLen,data,encrypted,rsa,padding);
	    RSA_free(rsa);

		if(retEr == -1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

		memset(encoded,'\0',4098);
	    base64Url_encode(encoded, encrypted, retEr);
	    return apr_pstrdup(p, encoded);
	}

	char* comu_rsaDecryptFromFile(apr_pool_t*p, unsigned char * encrypted, unsigned char * privateKeyFile, char** error){
		unsigned char decrypted[4098]={};
		unsigned char decoded[4098];


		RSA* rsa = comu_createRSAFromFile(p, privateKeyFile, FALSE, error);
	    if(rsa==NULL) return NULL;

	    int decodedLen = base64Url_decode(decoded, (char*)encrypted, strlen(encrypted));

	    int  retEr = RSA_private_decrypt(decodedLen,decoded,decrypted,rsa,padding);
	    RSA_free(rsa);

		if(retEr == -1) {
			char errorBuffer[OAUTH_ERROR_STRING_MAX_LENGTH];
			ERR_error_string(ERR_get_error(), errorBuffer);
			if(error!=NULL) { *error = apr_pstrdup(p, errorBuffer); }
			return NULL;
		}

	    return apr_pstrdup(p, decrypted);
	}

	char* comu_rsaPrintModulusFromFile(apr_pool_t*p, unsigned char * publicKeyFile, int isPublic) {
		int retEr;
		unsigned char encoded[1024];
		unsigned char buf[1024];
		int len;
		char* error = NULL;

		RSA* rsa = comu_createRSAFromFile(p, publicKeyFile, isPublic, &error);
	    if(rsa==NULL) {
			RSA_free(rsa);
	    		return (error!=NULL) ? error : apr_pstrdup(p, "unable to create rsa");
	    }

		memset(buf,'\0',1024);
		len = BN_bn2bin(rsa->n, buf);
		if(len<0) {
			RSA_free(rsa);
			return apr_pstrdup(p, "unable to retrieve modulus");
		}

		memset(encoded,'\0',1024);
		len = base64Url_encode(encoded, buf, len);
		if(len<0) {
			RSA_free(rsa);
			return apr_pstrdup(p, "unable to encode modulus");
		}
		printf("modulus : %s\r\n", encoded);

		memset(buf,'\0',1024);
		len = BN_bn2bin(rsa->e, buf);
		if(len<0) {
			RSA_free(rsa);
			return apr_pstrdup(p, "unable to retrieve modulus");
		}

		memset(encoded,'\0',1024);
		len = base64Url_encode(encoded, buf, len);
		if(len<0) {
			RSA_free(rsa);
			return apr_pstrdup(p, "unable to encode exponent");
		}
		printf("exponent : %s\r\n", encoded);

		RSA_free(rsa);

		return NULL;
	}

	// generate base64Url encoded signature ( used in JWT)
	const char* comu_generateHS256Signature(apr_pool_t*p, char* payload, unsigned char* secretKey, char** error) {
		unsigned char out[EVP_MAX_MD_SIZE];
		unsigned int outlen;
		char* tmp;
		unsigned char encode[64];
		unsigned char* result = NULL;

		if(secretKey==NULL||payload==NULL) return NULL;

		ERR_clear_error();

		//Generate signature
		result = HMAC(EVP_sha256(), secretKey, strlen(secretKey), (const unsigned char*)payload, strlen(payload), out, &outlen);
		if(result==NULL) {
				return NULL;
		}

		memset(encode,'\0',64);
		base64Url_encode(encode, out, outlen);
		return apr_pstrdup(p, encode);
	}

	// verifies base64Url encoded signature ( used in JWT)
	int comu_verifyHS256Signature(apr_pool_t*p, char* payload, char* encodedSignature, unsigned char* secretKey, char** error) {
		unsigned char out[EVP_MAX_MD_SIZE];
		unsigned int outlen;
		char* tmp;
		unsigned char signature[64];
		unsigned char* result = NULL;

		if(secretKey==NULL||payload==NULL) return FALSE;

		ERR_clear_error();

		//Generate signature
			result = HMAC(EVP_sha256(), secretKey, strlen(secretKey), (const unsigned char*)payload, strlen(payload), out, &outlen);
		if(result==0) {
				return FALSE;
		}

		memset(signature,'\0',64);
		base64Url_decode(signature, (char*)encodedSignature, 64);
		return (memcmp(out, signature, outlen)==0);
	}

	// generate HMAC-Sha1 signature
	char* comu_generateHS1Signature(apr_pool_t* p, char* payload, unsigned char* secretKey, char** error) {
		unsigned char out[EVP_MAX_MD_SIZE];
		unsigned int outlen;
		char* tmp;
		unsigned char* result = NULL;
		int i; char *signature = NULL;

		if(secretKey==NULL||payload==NULL) return NULL;

		ERR_clear_error();

		//Generate signature
		result = HMAC(EVP_sha1(), secretKey, strlen(secretKey), (const unsigned char*)payload, strlen(payload), out, &outlen);
		if(result==NULL) {
				return NULL;
		}
		for(i=0;i<outlen;i++){
			  	tmp=apr_psprintf(p,"%02x", out[i]);
			  	if(i!=0) signature=apr_pstrcat(p,signature,tmp,NULL);
			  	else signature=apr_pstrdup(p,tmp);
	    }

		return signature;
	}

	/*
	 * initialize the crypto context in the server configuration record; the passphrase is set already
	 */
	apr_byte_t comu_aesCryptoInit(apr_pool_t*p, oidc_cipher_cfg *cfg,
			char** error) {

		if (cfg->encrypt_ctx != NULL)
			return TRUE;

		unsigned char *key_data = (unsigned char *) cfg->crypto_passphrase;
		int key_data_len = strlen(cfg->crypto_passphrase);

		unsigned int s_salt[] = { 41892, 72930 };
		unsigned char *salt = (unsigned char *) &s_salt;

		int i, nrounds = 5;
		unsigned char key[32], iv[32];

		/*
		 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
		 * nrounds is the number of times the we hash the material. More rounds are more secure but
		 * slower.
		 */
		i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data,
				key_data_len, nrounds, key, iv);
		if (i != 32) {
			if(error!=NULL) *error=apr_psprintf(cfg->p,  "key size must be 256 bits!");
			return FALSE;
		}

		cfg->encrypt_ctx = apr_palloc(cfg->p, sizeof(EVP_CIPHER_CTX));
		cfg->decrypt_ctx = apr_palloc(cfg->p, sizeof(EVP_CIPHER_CTX));

		/* initialize the encoding context */
		EVP_CIPHER_CTX_init(cfg->encrypt_ctx);
		if (!EVP_EncryptInit_ex(cfg->encrypt_ctx, EVP_aes_256_cbc(), NULL, key,
				iv)) {
			if(error!=NULL) *error=apr_psprintf(p,  "EVP_EncryptInit_ex on the encrypt context failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return FALSE;
		}

		/* initialize the decoding context */
		EVP_CIPHER_CTX_init(cfg->decrypt_ctx);
		if (!EVP_DecryptInit_ex(cfg->decrypt_ctx, EVP_aes_256_cbc(), NULL, key,
				iv)) {
			if(error!=NULL) *error=apr_psprintf(p,  "EVP_DecryptInit_ex on the decrypt context failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return FALSE;
		}

		return TRUE;
	}

	/*
	 * AES encrypt plaintext
	 */
	unsigned char *comu_aesEncrypt(apr_pool_t*p, oidc_cipher_cfg *cfg,
			unsigned char *plaintext, int *len, char** error) {

		if (comu_aesCryptoInit(p, cfg, error) == FALSE)
			return NULL;

		/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
		int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
		unsigned char *ciphertext = apr_palloc(p, c_len);

		/* allows reusing of 'e' for multiple encryption cycles */
		if (!EVP_EncryptInit_ex(cfg->encrypt_ctx, NULL, NULL, NULL, NULL)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_EncryptInit_ex failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		/* update ciphertext, c_len is filled with the length of ciphertext generated, len is the size of plaintext in bytes */
		if (!EVP_EncryptUpdate(cfg->encrypt_ctx, ciphertext, &c_len, plaintext,
				*len)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_EncryptUpdate failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		/* update ciphertext with the final remaining bytes */
		if (!EVP_EncryptFinal_ex(cfg->encrypt_ctx, ciphertext + c_len, &f_len)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_EncryptFinal_ex failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		*len = c_len + f_len;

		return ciphertext;
	}

	/*
	 * AES decrypt ciphertext
	 */
	unsigned char *comu_aesDecrypt(apr_pool_t*p, oidc_cipher_cfg *cfg,
			unsigned char *ciphertext, int *len, char** error) {

		if (comu_aesCryptoInit(p, cfg, error) == FALSE)
			return NULL;

		/* because we have padding ON, we must allocate an extra cipher block size of memory */
		int p_len = *len, f_len = 0;
		unsigned char *plaintext = apr_palloc(p, p_len + AES_BLOCK_SIZE);

		/* allows reusing of 'e' for multiple encryption cycles */
		if (!EVP_DecryptInit_ex(cfg->decrypt_ctx, NULL, NULL, NULL, NULL)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_DecryptInit_ex failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		/* update plaintext, p_len is filled with the length of plaintext generated, len is the size of ciphertext in bytes */
		if (!EVP_DecryptUpdate(cfg->decrypt_ctx, plaintext, &p_len, ciphertext,
				*len)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_DecryptUpdate failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		/* update plaintext with the final remaining bytes */
		if (!EVP_DecryptFinal_ex(cfg->decrypt_ctx, plaintext + p_len, &f_len)) {
			if(error!=NULL) *error=apr_psprintf(p, "EVP_DecryptFinal_ex failed: %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		*len = p_len + f_len;

		return plaintext;
	}

	/*
	 * cleanup the crypto context in the server configuration record
	 */
	apr_byte_t comu_aesCryptoDestroy(oidc_cipher_cfg *cfg) {

		if (cfg->encrypt_ctx == NULL)
			return TRUE;

		EVP_CIPHER_CTX_cleanup(cfg->encrypt_ctx);
		EVP_CIPHER_CTX_cleanup(cfg->decrypt_ctx);

		cfg->encrypt_ctx = NULL;
		cfg->decrypt_ctx = NULL;

		return TRUE;
	}

	char* cu_generateGuid(apr_pool_t* p){
	    apr_uuid_t uuid;
	    char buf[APR_UUID_FORMATTED_LENGTH + 1];

	    apr_uuid_get(&uuid);
	    apr_uuid_format(buf, &uuid);
		return apr_pstrdup(p,buf);
	}

	/*
	 * base64url encode a string
	 */
	int cu_base64urlEncode(apr_pool_t*p, char **dst, const char *src,
			int src_len, int remove_padding) {
		if ((src == NULL) || (src_len <= 0)) {
	//		printf("not encoding anything; src=NULL and/or src_len<1");
			return -1;
		}
		int enc_len = apr_base64_encode_len(src_len);
		char *enc = apr_palloc(p, enc_len);
		apr_base64_encode(enc, (const char *) src, src_len);
		int i = 0;
		while (enc[i] != '\0') {
			if (enc[i] == '+')
				enc[i] = '-';
			if (enc[i] == '/')
				enc[i] = '_';
			if (enc[i] == '=')
				enc[i] = ',';
			i++;
		}
		if (remove_padding) {
			/* remove /0 and padding */
			enc_len--;
			if (enc[enc_len - 1] == ',')
				enc_len--;
			if (enc[enc_len - 1] == ',')
				enc_len--;
			enc[enc_len] = '\0';
		}
		*dst = enc;
		return enc_len;
	}

	/*
	 * base64url decode a string
	 */
	int cu_base64urlDecode(apr_pool_t*p, char **dst, const char *src) {
		if (src == NULL) {
	//		printf("not decoding anything; src=NULL");
			return -1;
		}
		char *dec = apr_pstrdup(p, src);
		int i = 0;
		while (dec[i] != '\0') {
			if (dec[i] == '-')
				dec[i] = '+';
			if (dec[i] == '_')
				dec[i] = '/';
			if (dec[i] == ',')
				dec[i] = '=';
			i++;
		}
		switch (strlen(dec) % 4) {
		case 0:
			break;
		case 2:
			dec = apr_pstrcat(p, dec, "==", NULL);
			break;
		case 3:
			dec = apr_pstrcat(p, dec, "=", NULL);
			break;
		default:
			return 0;
		}
		int dlen = apr_base64_decode_len(dec);
		*dst = apr_palloc(p, dlen);
		return apr_base64_decode(*dst, dec);
	}

	/*
	 * encrypt and base64url encode a string
	 */
	int cu_encryptAndBase64urlEncode(apr_pool_t*p, oidc_cipher_cfg*cfg, char **dst,
			const char *src, char** error) {
		int crypted_len = strlen(src) + 1;
		unsigned char *crypted = comu_aesEncrypt(p, cfg, (unsigned char *) src, &crypted_len, error);
		if (crypted == NULL) {
	//		printf("cu_crypto_aes_encrypt failed");
			return -1;
		}
		return cu_base64urlEncode(p, dst, (const char *) crypted, crypted_len, 1);
	}

	/*
	 * decrypt and base64url decode a string
	 */
	int cu_base64urlDecodeAndDecrypt(apr_pool_t*p, oidc_cipher_cfg*cfg, char **dst,
			const char *src, char** error) {
		char *decbuf = NULL;
		int dec_len = cu_base64urlDecode(p, &decbuf, src);
		if (dec_len <= 0) {
			if(error!=NULL) *error = apr_pstrdup(p, "cu_base64urlDecode failed");
			return -1;
		}
		*dst = (char *) comu_aesDecrypt(p, cfg, (unsigned char *) decbuf,
				&dec_len, error);
		if (*dst == NULL) {
			if(error!=NULL) *error = apr_pstrdup(p, "comu_aesDecrypt failed");
			return -1;
		}
		return dec_len;
	}
