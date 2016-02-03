#include <oidc-core/rewrite_core.h>
#include "common_utils.h"
#include "url_utils.h"

#ifdef NGX_DJREWRITE_PCRE
    #include <pcre.h>
	#include <pcreposix.h>
	static void * iota_pcre_malloc(size_t size);
	static void iota_pcre_free(void *ptr);
	static pool* iota_pcre_malloc_init(pool *new_pool);
	static void iota_pcre_malloc_done(pool *old_pool);
#else // APACHE PCRE
	#include "httpd.h"

	#if (AP_SERVER_MINORVERSION_NUMBER == 2 || AP_SERVER_MINORVERSION_NUMBER == 4)
	
		#include <ap_config.h>
		#include <ap_regex.h>
	
		typedef ap_regex_t regex_t;
		typedef ap_regmatch_t regmatch_t;
	
		#define REG_ESPACE 			AP_REG_ESPACE
		#define REG_ICASE			AP_REG_ICASE
		#define regcomp(arg1,arg2,arg3)		ap_regcomp(arg1,arg2,arg3)
		#define regfree(arg1)			ap_regfree(arg1)
		#define regexec(arg1,arg2,arg3,arg4,arg5) 	ap_regexec(arg1,arg2,arg3,arg4,arg5)
		//apache2.2 has built-in pcre  but we don't know which version it it, 64-bit compiler stll needs the declaration.
		#ifdef __cplusplus
			extern "C" const char *pcre_version(void);
		#else
			extern const char *pcre_version(void);
		#endif
	
	#else //#if AP_SERVER_MINORVERSION_NUMBER
		#include <pcreposix.h>
	#endif //#ifdef AP_SERVER_MINORVERSION_NUMBER
#endif //#ifdef NGX_DJREWRITE_PCRE
		
			char* rc_getInfo(pool* p){
				return apr_pstrcat(p,"[",REWRITE_CORE_VERSION,"], PCRE ",pcre_version(),NULL);
			}
			int   rc_matchByStrings(pool* p, char* regex, char* value){
				int ret=0;
				regex_t *preg=NULL;


				//do regex match
				preg=apr_palloc(p,sizeof(regex_t));
		#ifdef NGX_DJREWRITE_PCRE
				// set custom pcre func for NGX_DJREWRITE_PCRE
				pool *ip = (pool *) iota_pcre_malloc_init(p);
		#endif
				ret=regcomp(preg,regex,0);
				if(ret!=0){
		#ifdef NGX_DJREWRITE_PCRE
					// reset pcre func for NGX_PCRE
					iota_pcre_malloc_done(ip);
		#endif
					return -555;
				}

				ret=regexec(preg,value,0,NULL,0);
				regfree(preg);

		#ifdef NGX_DJREWRITE_PCRE
				// reset pcre func for NGX_DJREWRITE_PCRE
				iota_pcre_malloc_done(ip);
		#endif
				return ret;
			}
			int   rc_matchByStringsIgnoreCase(pool* p, char* regex, char* value){
				int ret=0;
				regex_t *preg=NULL;


				//do regex match
				preg=apr_palloc(p,sizeof(regex_t));

		#ifdef NGX_DJREWRITE_PCRE
				// set custom pcre func for NGX_DJREWRITE_PCRE
				pool *ip = (pool *) iota_pcre_malloc_init(p);
		#endif

				ret=regcomp(preg,regex,REG_ICASE);
				if(ret!=0){
		#ifdef NGX_DJREWRITE_PCRE
					// reset pcre func for NGX_DJREWRITE_PCRE
					iota_pcre_malloc_done(ip);
		#endif
					return -555;
				}

				ret=regexec(preg,value,0,NULL,0);
				regfree(preg);
		#ifdef NGX_DJREWRITE_PCRE
				// reset pcre func for NGX_DJREWRITE_PCRE
				iota_pcre_malloc_done(ip);
		#endif
				return ret;
			}
			int rc_matchByStringsPattern(pool* p, char* regex, char* value, array_header** matches){
				int ret=0;
				regex_t *preg=NULL;
				regmatch_t pmatch[9];
				int i=0;

				memset(pmatch,-1, sizeof(pmatch));

				//match vars
				array_header* nmatches=NULL;
				char** foundPlace=NULL, *found=NULL;
				int chars=0;

				//do regex match
				preg=apr_palloc(p,sizeof(regex_t));

		#ifdef NGX_DJREWRITE_PCRE
				// set custom pcre func for NGX_DJREWRITE_PCRE
				pool *ip = (pool *) iota_pcre_malloc_init(p);
		#endif

				ret=regcomp(preg,regex,0);
				if(ret!=0){
		#ifdef NGX_DJREWRITE_PCRE
					// reset pcre func for NGX_DJREWRITE_PCRE
					iota_pcre_malloc_done(ip);
		#endif
					return -555;
				}
				if(matches!=NULL){
					ret=regexec(preg,value,9,pmatch,0);

					if(pmatch[0].rm_so!=-1){
						nmatches=apr_array_make(p,4,sizeof(char*));
						for(i=0;i<9;i++){
							if(pmatch[i].rm_so!=-1){
								chars=pmatch[i].rm_eo-pmatch[i].rm_so;
								found=apr_pstrndup(p,value+(int)pmatch[i].rm_so,chars);

								foundPlace=(char**)apr_array_push(nmatches);
								*foundPlace=found;
							}
						}

						*matches=nmatches;
					}
				}else{
					ret=regexec(preg,value,0,NULL,0);
				}
				regfree(preg);

		#ifdef NGX_DJREWRITE_PCRE
				// reset pcre func for NGX_DJREWRITE_PCRE
				iota_pcre_malloc_done(ip);
		#endif
				return ret;
			}
			char* rc_matchByStringsPatternReturnDetails(pool* p, char* regex, char* value, array_header** matches){
				int ret=0;

				ret=rc_matchByStringsPattern(p,regex,value,matches);
				if(ret==-555){
					return apr_pstrdup(p,"error - compiling regex");
				}

				if(ret!=0){
					if(ret==REG_ESPACE){
						return apr_pstrdup(p,"error - matching took excessive memory");
					}else{
						return apr_pstrdup(p,"NO MATCH");
					}
				}
				return NULL;
			}

			char* rc_matchByStringsReturnDetails(pool* p, char* regex, char* value){
				int ret=0;

				ret=rc_matchByStrings(p,regex,value);
				if(ret==-555){
					return apr_pstrdup(p,"error - compiling regex");
				}

				if(ret!=0){
					if(ret==REG_ESPACE){
						return apr_pstrdup(p,"error - matching took excessive memory");
					}else{
						return apr_pstrdup(p,"NO MATCH");
					}
				}
				return NULL;
			}

	int rc_isRegexValid(pool* p,char* regex){
		if(regex==NULL||rc_matchByStrings(p,regex,"")==-555){
			return 0;	
		}
		return 1;
	}			

#ifdef NGX_DJREWRITE_PCRE

pool* iota_pcre_pool=NULL;

static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);


/* XXX: work-around to nginx regex subsystem, must init a memory pool
 * * to use PCRE functions. As PCRE still has memory-leaking problems,
 * * and nginx overwrote pcre_malloc/free hooks with its own static
 * * functions, so nobody else can reuse nginx regex subsystem... */

static void * iota_pcre_malloc(size_t size)
{
	if (iota_pcre_pool) {
		return apr_palloc(iota_pcre_pool, size);
	}

	fprintf(stderr, "error: iota pcre malloc failed due to empty pcre pool");

	return NULL;
}


static void iota_pcre_free(void *ptr)
{
	if (iota_pcre_pool) {
		//apr_pool_clear(ptr);
		return;
	}

	fprintf(stderr, "error: iota pcre free failed due to empty pcre pool");
}


static pool* iota_pcre_malloc_init(pool *new_pool)
{
	pool* old_pool;

	if (pcre_malloc != iota_pcre_malloc) {

		iota_pcre_pool = new_pool;

		old_pcre_malloc = pcre_malloc;
		old_pcre_free = pcre_free;

		pcre_malloc = iota_pcre_malloc;
		pcre_free = iota_pcre_free;

		return NULL;
	}

	old_pool = iota_pcre_pool;
	iota_pcre_pool = new_pool;

	return old_pool;
}


static void iota_pcre_malloc_done(pool *old_pool)
{
    iota_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}

#endif /* NGX_DJREWRITE_PCRE */
