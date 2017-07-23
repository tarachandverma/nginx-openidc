#include <stdlib.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <stdio.h>
#include <assert.h>
#include "CuTest.h"
#include "json_parser.h"
#include "json_api.h"
#include "common_utils.h"

// Used by some code below as an example datatype.
struct record {const char *precision;double lat,lon;const char *address,*city,*state,*zip,*country; };

// Create a bunch of objects as demonstration.
void JSON_CreateObject_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	Value *root,*fmt,*img,*thm,*fld;char *out;int i;        // declare a few.

	// Here we construct some JSON standards, from the JSON site.

	// Our "Video" datatype:
	root=JSON_CreateObject(p);
	JSON_AddItemToObject(p,root, "name", JSON_CreateString(p,"Jack (\"Bee\") Nimble"));
	JSON_AddItemToObject(p,root, "format", fmt=JSON_CreateObject(p));
	JSON_AddStringToObject(p,fmt,"type",             "rect");
	JSON_AddNumberToObject(p,fmt,"width",            1920);
	JSON_AddNumberToObject(p,fmt,"height",           1080);
	JSON_AddFalseToObject (p,fmt,"interlace");
	JSON_AddNumberToObject(p,fmt,"frame rate",       24);

	out=JSON_Serialize(p,root);

	CuAssertPtrNotNullMsg(tc,"Failed to serialize data from JSON_CreateObject_test", out);

}

// Create a bunch of objects as demonstration.
void JSON_CreateArray_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	Value *root,*fmt,*img,*thm,*fld;char *out;int i;        // declare a few.

	// Our matrix:
	int numbers[3][3]={{0,-1,0},{1,0,0},{0,0,1}};
	root=JSON_CreateArray(p);
	for (i=0;i<3;i++) JSON_AddItemToArray(p,root,JSON_CreateIntArray(p,numbers[i],3));

	out=JSON_Serialize(p,root);

	CuAssertPtrNotNullMsg(tc,"Failed to serialize data from JSON_CreateArray_test", out);

}

// Create a bunch of objects as demonstration.
void JSON_CreateStringArray_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	Value *root,*fmt,*img,*thm,*fld;char *out;int i;        // declare a few.

	// Our "days of the week" array:
	const char *strings[7]={"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
	root=JSON_CreateStringArray(p,strings,7);

	out=JSON_Serialize(p,root);

	CuAssertPtrNotNullMsg(tc,"Failed to serialize data from JSON_CreateStringArray_test", out);

}

// Create a bunch of objects as demonstration.
void JSON_AddItemToObject_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	Value *root,*fmt,*img,*thm,*fld;char *out;int i;        // declare a few.

	// Our "gallery" item:
	int ids[4]={116,943,234,38793};
	root=JSON_CreateObject(p);
	JSON_AddItemToObject(p,root, "Image", img=JSON_CreateObject(p));
	JSON_AddNumberToObject(p,img,"Width",800);
	JSON_AddNumberToObject(p,img,"Height",600);
	JSON_AddStringToObject(p,img,"Title","View from 15th Floor");
	JSON_AddItemToObject(p,img, "Thumbnail", thm=JSON_CreateObject(p));
	JSON_AddStringToObject(p,thm, "Url", "http://www.example.com/image/481989943");
	JSON_AddNumberToObject(p,thm,"Height",125);
	JSON_AddStringToObject(p,thm,"Width","100");
	JSON_AddItemToObject(p,img,"IDs", JSON_CreateIntArray(p,ids,4));

	out=JSON_Serialize(p,root);
	CuAssertPtrNotNullMsg(tc,"Failed to serialize data from JSON_AddItemToObject_test", out);
}


// Create a bunch of objects as demonstration.
void JSON_AddItemToArray_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	Value *root,*fmt,*img,*thm,*fld;char *out;int i;        // declare a few.

	// Our array of "records":
	struct record fields[2]={
			{"zip",37.7668,-1.223959e+2,"","SAN FRANCISCO","CA","94107","US"},
			{"zip",37.371991,-1.22026e+2,"","SUNNYVALE","CA","94085","US"}};

	root=JSON_CreateArray(p);
	for (i=0;i<2;i++)
	{
			JSON_AddItemToArray(p,root,fld=JSON_CreateObject(p));
			JSON_AddStringToObject(p,fld, "precision", fields[i].precision);
			JSON_AddNumberToObject(p,fld, "Latitude", fields[i].lat);
			JSON_AddNumberToObject(p,fld, "Longitude", fields[i].lon);
			JSON_AddStringToObject(p,fld, "Address", fields[i].address);
			JSON_AddStringToObject(p,fld, "City", fields[i].city);
			JSON_AddStringToObject(p,fld, "State", fields[i].state);
			JSON_AddStringToObject(p,fld, "Zip", fields[i].zip);
			JSON_AddStringToObject(p,fld, "Country", fields[i].country);
	}

	out=JSON_Serialize(p,root);

	CuAssertPtrNotNullMsg(tc,"Failed to serialize data from JSON_AddItemToArray_test", out);

}

void jsonapi_deserializeJsonStringMap_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

    const char* requestBody = "{\"username\":\"testuser\",\"password\":\"password1\",\"savelogin\":\"true\",\"template\":\"default\", \"realm\":\"test\", \"url\":\"http%3A%2F%2Fonline.s.dev.wsj.com%2Fmyaccount\"}\r\n";

	apr_hash_t* params=jsonapi_deserializeJsonStringMap(p, requestBody);

	CuAssertPtrNotNullMsg(tc,"Unable to desrializeString map using jsonapi_deserializeJsonStringMap", params);

}

void jsonapi_getJsonIdentityFromParams_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

    const char* requestBody = "{\"username\":\"testuser\",\"password\":\"password1\",\"savelogin\":\"true\",\"template\":\"default\", \"realm\":\"test\", \"url\":\"http%3A%2F%2Fonline.s.dev.wsj.com%2Fmyaccount\"}\r\n";

	apr_hash_t* params=jsonapi_deserializeJsonStringMap(p, requestBody);

	CuAssertPtrNotNullMsg(tc,"Unable to desrializeString map using jsonapi_deserializeJsonStringMap", params);

	jsonIdentity* identity=jsonapi_getJsonIdentityFromParams(p, params);

	CuAssertPtrNotNullMsg(tc,"Unable to build json_identity in jsonapi_getJsonIdentityFromParams", params);

	//preconditions
	statusMessage* statusMsg=jsonapi_preconditionFailureStatus(p,identity);
	CuAssertPtrNotNullMsg(tc,"statusMsg is null", statusMsg);

	jsonapi_statusMessageAddEntry(p,statusMsg,"username","parameter","The user does not exist or password does not match.","invalid-credentials");
	int count = jsonapi_getStatusErrorCount(p,statusMsg->entries);
	CuAssertIntEquals(tc,1,count);

}

static jsonSession* jsonapiunittest_createMockJsonSession(pool*p){
	char *tmp;
	jsonSession* jsonSess=jsonapi_newJsonSessionObj(p);
	apr_hash_t* tokenMap=NULL;

	tokenMap=apr_hash_make(p);
	apr_hash_set(tokenMap,JSON_TOKEN_USER,APR_HASH_KEY_STRING,"dj_chandt");
	apr_hash_set(tokenMap,JSON_TOKEN_PASSWORD,APR_HASH_KEY_STRING,"password1");
	apr_hash_set(tokenMap,JSON_TOKEN_UUID,APR_HASH_KEY_STRING,"dj_chandt");
	apr_hash_set(tokenMap,JSON_TOKEN_TIMESTAMP,APR_HASH_KEY_STRING,apr_ltoa(p,time(NULL)));
	apr_hash_set(tokenMap,JSON_TOKEN_SAVE_LOGIN,APR_HASH_KEY_STRING,apr_pstrdup(p,"true"));
	apr_hash_set(tokenMap,JSON_TOKEN_REALM,APR_HASH_KEY_STRING,"default");
	apr_hash_set(tokenMap,JSON_TOKEN_TEMPLATE,APR_HASH_KEY_STRING,"default");
	jsonSess->token=astru_serializeStringMapEscapeQuote(p,tokenMap);

	jsonSess->profileMsg=jsonapi_newProfileMessageObj(p);

	tmp=apr_pstrdup(p,"success");
	jsonapi_profileMessageAddEntry(p,jsonSess->profileMsg, "result",tmp);

	tmp=SAFEDUP(p,"dj_chandt");
	jsonapi_profileMessageAddEntry(p,jsonSess->profileMsg, "username",tmp);

	tmp=SAFEDUP(p,"dj_chandt");
	jsonapi_profileMessageAddEntry(p,jsonSess->profileMsg, "uuid", tmp);

	return jsonSess;
}

void jsonapi_profileMessageToJson_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

	jsonSession* jsonSess = jsonapiunittest_createMockJsonSession(p);

	CuAssertPtrNotNullMsg(tc,"jsonSess is null", jsonSess);

	char* responseBody=jsonapi_profileMessageToJson(p, jsonSess->profileMsg);

	CuAssertPtrNotNullMsg(tc,"statusMsg is null", responseBody);

}

void jsonapi_statusMessageToJson_test(mm_logger* logger, CuTest*tc) {
	pool*p = logger->pool;

    const char* requestBody = "{\"username_missing\":\"testuser\",\"password_missing\":\"password1\",\"savelogin\":\"true\",\"template_missing\":\"default\", \"realm_missing\":\"test\", \"url_missing\":\"http%3A%2F%2Fonline.s.dev.wsj.com%2Fmyaccount\"}\r\n";

	apr_hash_t* params=jsonapi_deserializeJsonStringMap(p, requestBody);

	CuAssertPtrNotNullMsg(tc,"Unable to desrializeString map in jsonapi_statusMessageToJson_test", params);

	jsonIdentity* identity=jsonapi_getJsonIdentityFromParams(p, params);

	//preconditions
	statusMessage* statusMsg=jsonapi_preconditionFailureStatus(p,identity);
	CuAssertPtrNotNullMsg(tc,"statusMsg is null", statusMsg);

	char* responseBody=jsonapi_statusMessageToJson(p, statusMsg);

	CuAssertPtrNotNullMsg(tc,"statusMsg is null", responseBody);

}

CuSuite* jsonapi_GetSuite() {
  CuSuite* suite = CuSuiteNew();
  SUITE_ADD_TEST(suite, JSON_CreateObject_test);
  SUITE_ADD_TEST(suite, JSON_CreateArray_test);
  SUITE_ADD_TEST(suite, JSON_CreateStringArray_test);
  SUITE_ADD_TEST(suite, JSON_AddItemToObject_test);
  SUITE_ADD_TEST(suite, JSON_AddItemToArray_test);
  SUITE_ADD_TEST(suite, jsonapi_deserializeJsonStringMap_test);
  SUITE_ADD_TEST(suite, jsonapi_getJsonIdentityFromParams_test);
  SUITE_ADD_TEST(suite, jsonapi_profileMessageToJson_test);
  SUITE_ADD_TEST(suite, jsonapi_statusMessageToJson_test);

return suite;
}
