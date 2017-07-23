#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <rewrite_core.h>
#include <CuTest.h>
#include <common_utils.h>
#include <oidc_config_xml.h>
#include <shm_data.h>
#include <match_list.h>
#include "config-core/config_bindings_shm.h"
#include "doc_parser_utils.h"
#include "http-utils/http_client.h"
#include "template_engine.h"
#include "oidc_globals.h"
#include "oidc_config_core.h"
#include "oidc_config.h"

void rc_getInfoTest(mm_logger* logger, CuTest*tc){
//	char* version = rc_getInfo(logger->p);
//	CuAssertPtrNotNull(tc,version);
}
void rc_matchByStringsTest(mm_logger* logger, CuTest*tc){
	int matched = rc_matchByStrings(logger->p, "^/company", "/company/");
	CuAssert(tc, "rc_matchByStrings failed to match ", matched==0);
}
void rc_matchByStringsIgnoreCaseTest(mm_logger* logger, CuTest*tc){
	int matched = rc_matchByStringsIgnoreCase(logger->p, "^/company", "/Company/");
	CuAssert(tc, "rc_matchByStringsIgnoreCase failed to match ", matched==0);
}
void rc_matchByStringsReturnDetailsTest(mm_logger* logger, CuTest*tc){
	char* details = rc_matchByStringsReturnDetails(logger->p, "^/company", "/company/");
	CuAssertPtrEquals(tc,NULL,details); // null expected
}
void rc_matchByStringsPatternTest(mm_logger* logger, CuTest*tc){
	//http://proto.wsj.com/wsjacl/qa/rewrite-match?valueParam=%2Fdemographic%2Fuser%2Ftara&regexParam=%2Fuser%2F%28.*%29&templateParam=
	char* value ="/demographic/user/tara";
	char* regex = "/user/(.*)";
	array_header* matches=NULL;
	char* elt=NULL;
	int i=0;
	int ret=0;

	ret=rc_matchByStringsPattern(logger->p,regex,value,&matches);
	if(matches!=NULL){

		logging_printf(logger,"Found Matches (%d)\n",matches->nelts);
		
		if(matches->nelts>0){
			for(i=0;i<matches->nelts;i++){
				elt=cu_getElement(matches,i);
				logging_printf(logger,"$%d: %s\n",i,elt);
			}
		}
	}
}
void rc_isRegexValidTest(mm_logger* logger, CuTest*tc){
	int result = rc_isRegexValid(logger->p,"^/test");
	CuAssertIntEquals(tc,1,result);
}

static oauth_jwk* oauth_getSignatureValidationKey(pool*p, oauth_jwt_header* header, const char* issuer, void* data, char** error) {
	oidc_config* oauthConfig = (oidc_config *)data;

	int i;

	if(header==NULL||header->algorithm==NULL||oauthConfig==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "header or jwsKeys null"); }
		return NULL;
	}
	oauth_jwk* jwk =oauthutil_newJWKObj(p);

	if(header->keyID!=NULL) {
		oauth_jwskey* jwsKey = am_getJWSKeyByKeyID(oauthConfig->oidcProvider->jwsKeys, header->keyID);

		if(jwsKey==NULL) {
			if(error!=NULL) { *error = apr_pstrdup(p, "jwsKey by keyID not found"); }
			return NULL;
		}
		jwk->keyID = apr_pstrdup(p, jwsKey->id);
		jwk->use = apr_pstrdup(p, jwsKey->use);
		jwk->modulus = apr_pstrdup(p, jwsKey->modulus);
		jwk->exponent = apr_pstrdup(p, jwsKey->exponent);
	}else if(issuer!=NULL){
		relying_party* relyingParty = am_getRelyingPartyByClientID(oauthConfig->relyingPartyHash, issuer);
		if(relyingParty==NULL) {
			if(error!=NULL) { *error = apr_pstrdup(p, "relyingParty not configured"); }
			return NULL;
		}
		jwk->key = apr_pstrdup(p, relyingParty->clientSecret);
	}

	return jwk;
}

void oidc_loadConfFile_test(mm_logger* logger, CuTest*tc){
	pool* p=logger->p;
	shared_heap* sheap=NULL;
	char* error=NULL;
	int handlerResponseCode=-1;
	cbs_globals* globals=NULL;
	cfg_service_descriptor *rs=NULL; // in pool
	cfg_service_descriptor* svcdesc = cb_newServiceDescriptorObj(p);
	apr_hash_set(svcdesc->params, "config-xml", APR_HASH_KEY_STRING, "oidc-config.xml");
	void* userdata = NULL;

	djrglobals_setEnableUnnamedSHM("true");

	// create resource service.
	rs=cb_newServiceDescriptorObj(p);
	rs->uri=apr_pstrdup(p,"https://raw.githubusercontent.com/tarachandverma/nginx-openidc/master/example-conf/");
	rs->timeoutSeconds=5;

	sheap=shdata_sheap_make(p,200000,"./unit-test/oidc.shm");
	shdata_BeginTagging(sheap);
	shdata_OpenItemTag(sheap,"oidc_test");

	//build globals
	globals=(cbs_globals*)shdata_shpcalloc(sheap,sizeof(cbs_globals));
	globals->homeDir=shdata_32BitString_copy(sheap,"./unit-test");
	globals->resourceService=cbs_copyServiceDescripterOnSheap(p,sheap,rs);

	error=amc_initialize(p,sheap,globals,svcdesc, &userdata);
	CuAssertPtrEquals_Msg(tc,error,NULL,error);

	shdata_PublishBackSeg(sheap);
	shdata_syncself(p,sheap,NULL,NULL);

	oidc_config* actmap = NULL;
	error=amc_postRefresh(p,sheap, NULL, svcdesc,(void**)&actmap);
	CuAssertPtrNotNullMsg(tc,"Error : oidcConfig is null", actmap);

	am_printAll(p, actmap);

	const char* id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjA3M2EzMjA0ZWMwOWQwNTBmNWZkMjY0NjBkN2RkYWY0YjRlYzc1NjEifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLmludC5kb3dqb25lcy5jb20iLCJzdWIiOiIzNzY0NjQ1MGQxZGE1MzA1ZjQ0MDQwYmI3NTc5N2ViM2RhMjlmY2M5IiwiYXVkIjoiYlg0djBuMlJZc2E1YTZQSU9zSzBUaXBlS3ZwZnl0MkIiLCJleHAiOjE0NTMyNDE0NDcsImlhdCI6MTQ1MzIzNzg0NywiZW1haWwiOiJ0YXJhLmNoYW5kQGRqVGVzdC5jb20ifQ.GdjV0i80i28xULxzw_1ABiC7JC6aOQ0xnErM-h98niLuDtzp91HejscfCAuusbYyZeWWYaWl_QYKZyOm4o3eqITXpABUaPA8tfd1j5wYq4dpmskkTjmCnsoWBD5TSMxSu3SPWUL-RbLeftEvktoLQ_hRdbLoLryN9kB7qaHWC7k";

	if(id_token!=NULL) {
		oauth_jwt* jwt = oauthutil_parseIDToken(p, id_token, NULL, &error);
		CuAssert(tc,error, jwt!=NULL);

		oauthutil_printIDToken(p, jwt);

		oidc_cipher_cfg* cipherConfig = (oidc_cipher_cfg*)apr_palloc(p, sizeof(oidc_cipher_cfg));
		cipherConfig->crypto_passphrase = apr_pstrdup(p, "dowjones1");
		cipherConfig->decrypt_ctx=NULL;
		cipherConfig->encrypt_ctx=NULL;
		cipherConfig->p = p;

		const char* serializedClaim = "tarachandverma";
		int crypted_len = strlen(serializedClaim) + 1;

		// encrypt
		char *encrypted = "";
		int status = cu_encryptAndBase64urlEncode(p, cipherConfig, &encrypted, (unsigned char *) serializedClaim, &error);
		if(status>0){
			char* decrypted = "";
			status = cu_base64urlDecodeAndDecrypt(p, cipherConfig, &decrypted, encrypted, &error);
			printf("decrypted=%s\r\n", decrypted);
		}


	}

	apr_table_t* headers_in = apr_table_make(p, 1);

	char* sessionID = cookie_getCookie(p, headers_in, actmap->oidcSession);
	if(sessionID==NULL) {
		sessionID = cu_generateGuid(p);
		char* cookieDrop = cookie_cookieTemplate(p, actmap->oidcSession, sessionID, NULL);
		if(cookieDrop!=NULL){
			printf("cookieDrop=%s", cookieDrop);
			apr_table_add(headers_in, "Set-Cookie", cookieDrop);
		}
	}

}

static const char* oauthtest_getPublicKey(pool*p, oauth_jwt_header* header, const char* issuer, void* data, char** error) {
	const char* publicKey =
			"-----BEGIN PUBLIC KEY-----\n"\
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSfZyrbMLmDjA01Fim7l1YElwY\n"\
"CdxfOt6QpzHBglAmZvER93WjDwp2ewtkWnz3JDP94BtBeDKEEMGiFbNRMNo2Z4Va\n"\
"8Jai1Zjmbco4W+GvHUHBQ/On05dIeCe3B1FIPpyc+QaA8TqHUk9jUt6dStC+Tkdk\n"\
"i1293EDj+0ylFrylbwIDAQAB\n"\
"-----END PUBLIC KEY-----\n"
;
	oauth_jwk* jwk =oauthutil_newJWKObj(p);
	jwk->key = apr_pstrdup(p, publicKey);
	return jwk;
}

static void oauthutil_generateAndParseAndValidateIDToken_test(mm_logger* logger,CuTest*tc) {
	pool*p = logger->p;
	char* error = NULL;

	const char* privateKey =
			"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIICXwIBAAKBgQDSfZyrbMLmDjA01Fim7l1YElwYCdxfOt6QpzHBglAmZvER93Wj\n"\
"Dwp2ewtkWnz3JDP94BtBeDKEEMGiFbNRMNo2Z4Va8Jai1Zjmbco4W+GvHUHBQ/On\n"\
"05dIeCe3B1FIPpyc+QaA8TqHUk9jUt6dStC+Tkdki1293EDj+0ylFrylbwIDAQAB\n"\
"AoGBAL5GlJiWMbzbOJKZHiaQtUrHFf8Y8uAXDFiA+0ZtMVz1k5hlNS8YiqG96vdl\n"\
"oS+bx3AI5TqSmD+wEgoeScHsQmRlZvI9+WkOTCkaJhmhdINp32RDeEs6OQ0r3mxE\n"\
"EhsRS0qJHwYzv4nA8vS/mM3QohXJexvBA06T2aNsLdZ9zwr5AkEA9aPSy26dOF58\n"\
"IZg9bp/Gmr862J1v4gjpGcJh8JT1P1ZIuIDcgft7XG+572aJ3ATC/o3+4t27aRge\n"\
"Sn+WmN6FFQJBANteSBsC/ln9Vn4H1REE2tKsSwZymfRYrzYtDXwQ2snoEmMByvwe\n"\
"OIgHx+cCA9gqPxzZ8XlVgzHPHXadeAQ8qXMCQQCMdOp5zHw12UEdbJHkCZRks+gQ\n"\
"KKXrF7FCO3YJPQOm/c2DQpvT71qwlmo5S+aUWlytdcBDNQqOo23ep2oTa1mpAkEA\n"\
"yiuPCo3suiTXxJkVTXUK8qPlFREjP+VHvQcyaUfjS7c80tBBMa/sa7m4Cvd5cYwl\n"\
"1EIr4KXlnk8CGWIwzL7XbwJBAKa2ABDRGozckCNhtdoYp6OvB/uXO6sMC8NxYr4d\n"\
"gqIuOD/kdR3ILvuIKdk9DyEEZgGH1sbn4MW5dAvbqScSsqE=\n"\
"-----END RSA PRIVATE KEY-----\n"
;
	oauth_jwt_header* header = oauthutil_newJWTHeaderObj(p);
	header->algorithm = apr_pstrdup(p, "RS256");

	oauth_jwt_claim* claim = oauthutil_newJWTClaimObj(p);
	claim->issuer = apr_pstrdup(p, "https://login.wsj.com");
	claim->subject = apr_pstrdup(p, "tarachand.verma@gmail.com");
	claim->audience = apr_pstrdup(p, "test123");
	claim->issuedAt = time(NULL);
	claim->expiry = 600+time(NULL);
	// set optional params
	claim->options = apr_hash_make(p);
	apr_hash_set(claim->options,"nonce", APR_HASH_KEY_STRING, "n-0S6_WzA2Mj");

	char* IDTokenSerial = oauthutil_generateIDToken(p, header, claim, privateKey);

	CuAssert(tc,"Error: unable to generate IDToken ", IDTokenSerial!=NULL);

	printf("IDTokenSerial=%s\r\n", IDTokenSerial);

	// parse and test
	oauth_jwt* IDToken = oauthutil_parseAndValidateIDToken(p, IDTokenSerial, oauthtest_getPublicKey, NULL, &error);

	CuAssert(tc,error, IDToken!=NULL);

	oauthutil_printIDToken(p, IDToken);


}

static void oauthutil_parseAndValidateExpiredIDToken_test(mm_logger* logger,CuTest*tc) {
	pool*p = logger->p;
	char* error = NULL;

	const char* IDTokenSerial = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLndzai5jb20iLCJzdWIiOiJ0YXJhY2hhbmQudmVybWFAZ21haWwuY29tIiwibmJmIjoxNDI5NTcwNzE1LCJleHAiOjE0Mjk1NzQzMTUsImlhdCI6MTQyOTU3MDcxNSwianRpIjoiaWQxMjM0NTYiLCJ0eXAiOiJodHRwczovL2V4YW1wbGUuY29tL3JlZ2lzdGVyIn0.JDoWux28H1pELJi1Pw4co7LyMimQ0ouoV_-sSRgJlAfGrHp52elbF1aAtnT1gDK45e22quQP0cjDwvaQoW54Ii6YS4wOPxlZPvDWzcUX3ubhvoCUR5mbGH6nv1xT6JpKvVTvsZhlw2c9J9bspnokfDAO6dgwG9cBf8hQtdpzzDY";

	oauth_jwt* IDToken = oauthutil_parseAndValidateIDToken(p, IDTokenSerial, oauthtest_getPublicKey, NULL, &error);

	CuAssert(tc,error, IDToken==NULL);

}

typedef struct oauth_jws_uri{
	char* uri;
	int timeout;
}oauth_jws_uri;

static oauth_jwk* oauthtest_getGooglePublicKey(pool*p, oauth_jwt_header* header, const char* issuer, void* data, char** error) {
	oauth_jws_uri* jwsUri = (oauth_jws_uri*)data;
	int i;

	if(header==NULL||jwsUri==NULL||jwsUri->uri==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "header or jwsUri null"); }
		return NULL;
	}

	http_util_result* httpResult=hc_get_verbose(p, jwsUri->uri, jwsUri->timeout, NULL, NULL, error);
	if(httpResult==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "jwsUri response null"); }
		return NULL;
	}

	oauth_jwk* jwk =oauthutil_newJWKObj(p);

	Value* json = 	JSON_Parse(p, httpResult->data);
	if(json!=NULL){
		Value* array = JSON_GetObjectItem(json, "keys");
		if(array==NULL||JSON_GetItemType(array)!=JSON_Array) {
			if(error!=NULL) { *error = apr_pstrdup(p, "keys object is not array"); }
			return NULL;
		}

		int	arrSz = JSON_GetArraySize(array);

		// Retrieve item number "item" from array "array". Returns NULL if unsuccessful.
		for (i=0; i<arrSz; i++) {
			Value* element = JSON_GetArrayItem(array, i);
			Value* keyIDObj = JSON_GetObjectItem(element, "kid");
			const char* keyID = (keyIDObj) ? (char*)JSON_GetStringFromStringItem(keyIDObj) : NULL;
			if(keyID!=NULL&&(strcmp(keyID,header->keyID)==0)) {
				jwk->keyID = keyID;
				Value* val = JSON_GetObjectItem(element, "use");
				jwk->use = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
				val = JSON_GetObjectItem(element, "n");
				jwk->modulus = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
				val = JSON_GetObjectItem(element, "e");
				jwk->exponent = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
			}
		}
	}

	return jwk;
}

static void oauthutil_parseAndValidateGoogleIDToken_test(mm_logger* logger,CuTest*tc) {
	pool*p = logger->p;
	char* error = NULL;

	const char* googleIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3NWMyYzkwY2JhNzQxMTg3YjhkOTdkY2NiYmIwNGU3MGNlZmVjYzQifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTExNTUwNDI4NTcwMzg4OTk3NDc4IiwiYXpwIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJ0YXJhY2hhbmQudmVybWFAZG93am9uZXMuY29tIiwiYXRfaGFzaCI6IjdnWWVSS1RWZFNaSXhHZ2EzZWR5aEEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXVkIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaGQiOiJkb3dqb25lcy5jb20iLCJpYXQiOjE0Mjk3ODc5NTUsImV4cCI6MTQyOTc5MTU1NX0.TvMBglGs9gO3EwpubaZ1aC4MbozPQdeoidZzIC-OH1XoAPio5BCJK335K8BNFk_OEJwqYlENaLfMIio-EQ2BGNUSceb0cTjPAePe0XZ1ql8miz_IvUO1DUrS0N5oi4FIXZDFw3eO_WCxeaYkJ0wkQb3xZmZcFuYWE9UOlThW59k";
	oauth_jws_uri* jwsUri=(oauth_jws_uri*)apr_pcalloc(p, sizeof(oauth_jws_uri));
	jwsUri->uri = apr_pstrdup(p, "https://www.googleapis.com/oauth2/v3/certs");
	jwsUri->timeout = 10;

	oauth_jwt* jwt = oauthutil_parseAndValidateIDToken(p, googleIDToken, oauthtest_getGooglePublicKey, jwsUri, &error);

	CuAssert(tc, error, jwt==NULL); // expired ID token

//	oauthutil_printIDToken(p, jwt);
}

CuSuite* oidccore_GetSuite() {
  CuSuite* suite = CuSuiteNew();
  SUITE_ADD_TEST(suite, rc_getInfoTest);
  SUITE_ADD_TEST(suite, rc_matchByStringsTest);
  SUITE_ADD_TEST(suite, rc_matchByStringsIgnoreCaseTest);
  SUITE_ADD_TEST(suite, rc_matchByStringsReturnDetailsTest);
  SUITE_ADD_TEST(suite, rc_matchByStringsPatternTest);
  SUITE_ADD_TEST(suite, rc_isRegexValidTest);
  SUITE_ADD_TEST(suite, oidc_loadConfFile_test);
  SUITE_ADD_TEST(suite, oauthutil_generateAndParseAndValidateIDToken_test);
  SUITE_ADD_TEST(suite, oauthutil_parseAndValidateExpiredIDToken_test);
  SUITE_ADD_TEST(suite, oauthutil_parseAndValidateGoogleIDToken_test);
return suite;
}
