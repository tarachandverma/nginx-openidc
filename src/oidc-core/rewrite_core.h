#ifndef __TCREWRITE_REWRITE_CORE__H_
#define __TCREWRITE_REWRITE_CORE__H_
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apache_typedefs.h>
#define REWRITE_CORE_VERSION	"1.0"

	char* rc_getInfo(pool* p);
	int   rc_matchByStrings(pool* p, char* regex, char* value);
	int   rc_matchByStringsIgnoreCase(pool* p, char* regex, char* value);
	char* rc_matchByStringsReturnDetails(pool* p, char* regex, char* value);
	int   rc_matchByStringsPattern(pool* p, char* regex, char* value, array_header** matches);
	char* rc_matchByStringsPatternReturnDetails(pool* p, char* regex, char* value, array_header** matches);
	int rc_isRegexValid(pool* p,char* regex);
#endif
