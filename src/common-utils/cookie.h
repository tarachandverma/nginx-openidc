#ifndef _COOKIE_H_
#define _COOKIE_H_
#ifdef __cplusplus
	extern "C" {
#endif
		
#include <sys/types.h>
#include <apache_mappings.h>
#include <shm_data.h>
#include <shm_apr.h>

typedef struct Cookie {
	char*	  	name;		// Cookie
	int	      	nameLen;	// Cookie name length
	int	      	age;		// in Days
	unsigned int  	httpOnly;	// httpOnly support.
	int  		secure;			// httpOnly; Secure support.
}Cookie;

//Creater methods
Cookie* cookie_newObj(pool*p);
Cookie* cookie_createCookieByName(pool*p, char*name);
Cookie* cookie_cookieDup(pool*p, Cookie*src);

//Accessor Methods
void cookie_setCookieName(pool*p, Cookie*cookie, char*name);
char* cookie_getCookieName(Cookie*cookie) ;
void cookie_setCookieLifeTime(Cookie* cookie, int lifeTime);
int cookie_getCookieLifeTime(Cookie* cookie);
void cookie_setCookieHttpOnlyflag(Cookie* cookie, unsigned int httpOnly);
unsigned int cookie_getCookieHttpOnlyflag(Cookie* cookie);
void cookie_setCookieSecureHttpOnlyflag(Cookie* cookie, int secure);

//Cookie sheap methods
Cookie* cookie_newShmObj(shared_heap*sheap);
Cookie* cookie_cookieShmDup(shared_heap*sheap, Cookie*src);

//Cookie utility methods
int cookie_convertDaysToSeconds(int days);
char* cookie_cookieTemplate(pool* p, Cookie* cookie, char *ivalue, char *iDomain);
char* cookie_cookieTemplateByName(pool* p,char* icookiename, char *ivalue, 
		char *idomain, long maxAge, unsigned int httpOnly);
char* cookie_cookieUntemplate(pool* p,char* src);
char* cookie_getGMTDate(pool* p, int secondsInFuture);
char *cookie_getCookie(pool* p, apr_table_t* headers_in, Cookie* cookie);
char *cookie_getCookieByName(pool* p, apr_table_t* headers_in, char *cookie_name, int cookie_name_len);
void cookie_deleteCookie(pool* p, apr_table_t* err_headers_out, Cookie* cookie, char* domain);
void cookie_deleteCookieByName(pool* p, apr_table_t* err_headers_out, char* cookie_name, char* domain);
char* cookie_parseCookie(pool* p, char* name, char* cookies);

#ifdef __cplusplus
	}
#endif
#endif //_COOKIE_H_
