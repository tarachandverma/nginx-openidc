#ifndef _COOKIE_C_
#define _COOKIE_C_

#include "cookie.h"
#include "url_utils.h"

//Creater methods
Cookie* cookie_newObj(pool*p){
	Cookie* ret=(Cookie*)apr_pcalloc(p,sizeof(Cookie));
	ret->name=NULL;
	ret->nameLen=0;
	ret->age=-1;
	ret->httpOnly=FALSE;
	ret->secure=FALSE;
	return ret;
}

Cookie* cookie_createCookieByName(pool*p, char*name) {
		Cookie* cookie = NULL;
		if(name){
			cookie = cookie_newObj(p);
			cookie->name= apr_pstrdup(p, name);
			cookie->nameLen=strlen(cookie->name);
		}
		return cookie;
}

Cookie* cookie_cookieDup(pool*p, Cookie*src){
	Cookie* ret=NULL;
	if(src){
		ret = cookie_newObj(p);
		ret->name=apr_pstrdup(p, src->name);
		ret->nameLen=src->nameLen;
		ret->age=src->age;
		ret->httpOnly=src->httpOnly;
		ret->secure=src->secure;
	}
	return ret;
}

//Accessor Methods
void cookie_setCookieName(pool*p, Cookie*cookie, char*name) {
	if(cookie && name){
		cookie->name= apr_pstrdup(p, name);
		cookie->nameLen=strlen(cookie->name);
	}
}

char* cookie_getCookieName(Cookie*cookie) {
	return cookie->name;
}

void cookie_setCookieLifeTime(Cookie* cookie, int lifeTime){
	cookie->age = lifeTime;
}

int cookie_getCookieLifeTime(Cookie* cookie){
	return cookie->age;
}

void cookie_setCookieHttpOnlyflag(Cookie* cookie, unsigned int httpOnly){
	cookie->httpOnly = httpOnly;
}

void cookie_setCookieSecureHttpOnlyflag(Cookie* cookie, int secure){
	cookie->secure = secure;
}

unsigned int cookie_getCookieHttpOnlyflag(Cookie* cookie){
	return cookie->httpOnly;
}

//Cookie sheap methods
Cookie* cookie_newShmObj(shared_heap*sheap){
        Cookie* ret=(Cookie*)shdata_shpalloc(sheap,sizeof(Cookie));
        ret->name=NULL;
        ret->nameLen=0;
        ret->age=-1;
        ret->httpOnly=FALSE;
        ret->secure=FALSE;
        return ret;
}

Cookie* cookie_cookieShmDup(shared_heap*sheap, Cookie*src){
	Cookie* ret=NULL;
	if(src) {
		ret = cookie_newShmObj(sheap);
		ret->name=shdata_32BitString_copy(sheap,src->name);
		ret->nameLen=src->nameLen;
		ret->age=src->age;
		ret->httpOnly=src->httpOnly;
		ret->secure=src->secure;
	}
	return ret;
}

//Cookie utility methods
char* cookie_cookieTemplateByName(pool* p,char* icookiename, char *ivalue, 
		char *idomain, long maxAge, unsigned int httpOnly) {
		char* ret=NULL;
		char* value=SAFESTRBLANK(ivalue),*domain=SAFESTRBLANK(idomain),*cookiename=SAFESTRBLANK(icookiename);
		int sz=0,ulen=0;
		char* encoded_url=NULL;
		
		sz=strlen(domain)+strlen(cookiename)+64;
		ulen=strlen(value)*3+1;
		
		encoded_url=apr_pcalloc(p,ulen);
		url_encode(value, encoded_url, ulen);
		sz+=strlen(encoded_url);
		
		ret=apr_pcalloc(p,sz);
		if (maxAge < 0) {
			sprintf(ret,
			"%s=%s; domain=%s; path=/",
		cookiename == NULL ? "" : cookiename,
		value == NULL ? "" : encoded_url, 
		domain == NULL ? "" : domain);
	} else {
		sprintf(ret, 
		"%s=%s; domain=%s; path=/; Expires=%s; max-age=%d%s",
		cookiename == NULL ? "" : cookiename,
		value == NULL ? "" : encoded_url, 
		domain == NULL ? "" : domain,
		cookie_getGMTDate(p,maxAge),
		maxAge,
		httpOnly == TRUE ? "; httpOnly" : "");
	}
	return ret;
}

//Assuming the cookie age in and needs to convert in seconds.
char* cookie_cookieTemplate(pool* p, Cookie* cookie, char *ivalue, char *idomain) {
	char* ret=NULL;
	char* value=SAFESTRBLANK(ivalue),*domain=SAFESTRBLANK(idomain);
	int sz=0,ulen=0;
	char* encoded_url=NULL;
	long maxAge=0;
	
	if(cookie==NULL) return NULL;
	maxAge = cookie_convertDaysToSeconds(cookie->age);
	
	sz=strlen(domain)+strlen(cookie->name)+96;
	ulen=strlen(value)*3+1;
	
	encoded_url=apr_pcalloc(p,ulen);
	url_encode(value, encoded_url, ulen);
	sz+=strlen(encoded_url);

	ret=apr_pcalloc(p,sz);
	if (maxAge < 0) {
		if(cookie->secure == TRUE) {
			sprintf(ret, "%s=%s; domain=%s; path=/%s",
			cookie->name == NULL ? "" : cookie->name,
			value == NULL ? "" : encoded_url, 
			domain == NULL ? "" : domain, "; httpOnly; Secure");			
		} else {
			sprintf(ret, "%s=%s; domain=%s; path=/%s",
			cookie->name == NULL ? "" : cookie->name,
			value == NULL ? "" : encoded_url, 
			domain == NULL ? "" : domain,
			cookie->httpOnly == TRUE ? "; httpOnly" : "");
		}
	} else {
		if(cookie->secure == TRUE) {
			sprintf(ret, "%s=%s; domain=%s; path=/; Expires=%s; max-age=%d%s",
			cookie->name == NULL ? "" : cookie->name,
			value == NULL ? "" : encoded_url, 
			domain == NULL ? "" : domain,
			cookie_getGMTDate(p,maxAge),
			maxAge, "; httpOnly; Secure");
		} else {
			sprintf(ret, "%s=%s; domain=%s; path=/; Expires=%s; max-age=%d%s",
			cookie->name == NULL ? "" : cookie->name,
			value == NULL ? "" : encoded_url, 
			domain == NULL ? "" : domain,
			cookie_getGMTDate(p,maxAge),
			maxAge,
			cookie->httpOnly == TRUE ? "; httpOnly" : "");			
		}
	}
	return ret;
}
char* cookie_cookieUntemplate(pool* p,char* name){
	char* ret=NULL;
	int rlen=0;
	if(name==NULL)return NULL;
	rlen=strlen(name)+1;
	ret=apr_pcalloc(p,rlen);
	url_decode(name,ret,rlen);
	return ret;
}

int cookie_convertDaysToSeconds(int days){
		if(days<0) return days;
		return days*86400;
}

char* cookie_getGMTDate(pool* p, int secondsInFuture){
	char buf[64];
	apr_time_t date=apr_time_now();
	date=date+(APR_USEC_PER_SEC*secondsInFuture);
	
	memset(buf,'\0',64);
	apr_ctime(buf,date);		
	return apr_pstrdup(p,buf);
}

char* cookie_parseCookie(pool* p, char* name, char* cookies){
	char *cursor, *strCookie, *cookiereturn,*cend, *cnamestart;
	int len,x,found=0;
	int cookieLen=0;
	
	if(cookies==NULL||name==NULL) return NULL;
	
	cend=cnamestart=cookiereturn=strCookie=NULL;
	cookieLen=strlen(name);
	strCookie=cookies;
	
	while(1){
		cnamestart=strstr(strCookie, name);	
		//printf("\n\nCycle:%s\n\n\n",cnamestart);
		if(cnamestart){
			cursor=cnamestart+cookieLen;
			//printf("cursorFOUND:%s\n",cursor);
			if(*cursor&&(*cursor=='='||*cursor==' ')){
				while(*cursor&&*cursor!='='){
					cursor++;
				}
				cursor++;
				//printf("\n\nCURSOR:%s\n\n",cursor);
				cend=strchr(cursor,';');
				
				if(cend){
					//printf("cend:%s\n",cend);
				}else{
					cend=strchr(cursor,'\0');
				}
				
				
				len=cend-cursor;
                            	cookiereturn=(char*)apr_palloc(p,len+1);
                            	strncpy(cookiereturn,cursor,len);
                            	cookiereturn[len]='\0';
				//printf("COOKIERETURN: [%s]\n",cookiereturn);
				break;
			}else{
				strCookie=cursor;
				//printf("cursor:%s\n",cursor);
			}
		}else{
			break;
		}
	}	
    return cookiereturn;
}

char *cookie_getCookie(pool* p, apr_table_t* headers_in, Cookie* cookie)
{
	char *cursor, *strCookie, *cookiereturn,*cend, *cnamestart;
	int len,x,found=0;
	cend=cnamestart=cookiereturn=strCookie=NULL;

        if (cookie==NULL||cookie->name == NULL||cookie->nameLen<0)
                return NULL;

	
        if ((strCookie = (char*)apr_table_get(headers_in, "Cookie")) != NULL)
        {
		while(1){
			cnamestart=strstr(strCookie, cookie->name);	
			//printf("\n\nCycle:%s\n\n\n",cnamestart);
			if(cnamestart){
				cursor=cnamestart+cookie->nameLen;
				//printf("cursorFOUND:%s\n",cursor);
				if(*cursor&&(*cursor=='='||*cursor==' ')){
					while(*cursor&&*cursor!='='){
						cursor++;
					}
					cursor++;
					//printf("\n\nCURSOR:%s\n\n",cursor);
					cend=strchr(cursor,';');
					
					if(cend){
						//printf("cend:%s\n",cend);
					}else{
						cend=strchr(cursor,'\0');
					}
					
					
					len=cend-cursor;
                                	cookiereturn=(char*)apr_palloc(p,len+1);
                                	strncpy(cookiereturn,cursor,len);
                                	cookiereturn[len]='\0';
					//printf("COOKIERETURN: [%s]\n",cookiereturn);
					break;
				}else{
					strCookie=cursor;
					//printf("cursor:%s\n",cursor);
				}
			}else{
				break;
			}
		}	
        }
    return cookiereturn;
}

char *cookie_getCookieByName(pool* p, apr_table_t* headers_in, char *cookie_name, int cookie_name_len)
{
	char *cursor, *strCookie, *cookiereturn,*cend, *cnamestart;
	int len,x,found=0;
	cend=cnamestart=cookiereturn=strCookie=NULL;

        if (cookie_name == NULL||cookie_name_len<0)
                return NULL;

	
        if ((strCookie = (char*)apr_table_get(headers_in, "Cookie")) != NULL)
        {
		while(1){
			cnamestart=strstr(strCookie, cookie_name);	
			//printf("\n\nCycle:%s\n\n\n",cnamestart);
			if(cnamestart){
				cursor=cnamestart+cookie_name_len;
				//printf("cursorFOUND:%s\n",cursor);
				if(*cursor&&(*cursor=='='||*cursor==' ')){
					while(*cursor&&*cursor!='='){
						cursor++;
					}
					cursor++;
					//printf("\n\nCURSOR:%s\n\n",cursor);
					cend=strchr(cursor,';');
					
					if(cend){
						//printf("cend:%s\n",cend);
					}else{
						cend=strchr(cursor,'\0');
					}
					
					
					len=cend-cursor;
                                	cookiereturn=(char*)apr_palloc(p,len+1);
                                	strncpy(cookiereturn,cursor,len);
                                	cookiereturn[len]='\0';
					//printf("COOKIERETURN: [%s]\n",cookiereturn);
					break;
				}else{
					strCookie=cursor;
					//printf("cursor:%s\n",cursor);
				}
			}else{
				break;
			}
		}	
        }
    return cookiereturn;
}
void cookie_deleteCookie(pool* p, apr_table_t* err_headers_out, Cookie* cookie, char* domain){
    char delstr[768];
    if(cookie!=NULL&&cookie->name!=NULL){
        sprintf(delstr,"%s=remove;domain=%s;path=/;Expires=Thu, 01-Jan-1970 00:00:10 GMT;max-age=0",
            cookie->name== NULL ? "" : cookie->name,
            domain == NULL ? "" : domain
            );
        apr_table_add(err_headers_out,"Set-Cookie",delstr);
    }
}

void cookie_deleteCookieByName(pool* p, apr_table_t* err_headers_out, char* cookie_name, char* domain){
    char delstr[768];
    if(cookie_name!=NULL){
        sprintf(delstr,"%s=remove;domain=%s;path=/;Expires=Thu, 01-Jan-1970 00:00:10 GMT;max-age=0",
            cookie_name== NULL ? "" : cookie_name,
            domain == NULL ? "" : domain
            );
        apr_table_add(err_headers_out,"Set-Cookie",delstr);
    }
}

#endif //_COOKIE_C_
