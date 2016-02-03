#ifndef __DJREWRITE_URL_UTILS__H_
#define __DJREWRITE_URL_UTILS__H_
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include "apache_typedefs.h"
#ifdef __cplusplus
	extern "C" {
#endif
int url_get_param(const char *queryString, const char *paramName, char *dest, int dlen);
char* url_getParam(pool* p, char* queryString,const char* name);

int url_decode(const char *src, char *dst, int dlen); 

int url_encode(const char *src, char *dst, int dlen);

long base64_encode (char *to, char *from, unsigned int len);
long base64_decode (char *to, char *from, unsigned int len);
char* url_addParam(pool* p, char* url, char* pName, char* pVal);

char* url_encode2(pool* p, char* src);
char* url_decode2(pool* p, char* src);
char* url_appendParamToQuery(pool*p, char*query, char*pName,char*pVal);

long base64Url_encode (char *to, char *from, unsigned int len);
long base64Url_decode (char *to, char *from, unsigned int len);

#ifdef __cplusplus
}
#endif
#endif
