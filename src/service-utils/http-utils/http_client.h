#ifndef HTTP_CLIENT_H_
#define HTTP_CLIENT_H_
#ifdef __cplusplus
	extern "C" {
#endif
//apr stuff
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#define HTTP_USER_AGENT	"openidc-libcurl"
	typedef struct http_util_result {
	   char *data;
	   char *content_type; 
	   size_t size;
	   double totalTime;
	   long responseCode;
	   apr_pool_t *p;
	   apr_table_t* headers_out;
	}http_util_result;


	typedef struct http_ssl_options {
		char* certType;
		char* certFile;
		char* passPhrase;
		char* keyType;
		char* keyName;
		char* caCertFile;
	}http_ssl_options;
	
	http_ssl_options* hc_createNewHttpSSLOptions(apr_pool_t *p);
	
	void hc_cleanup();
	void hc_init();
	http_util_result* hc_post_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass,const char* postData,int postDataLen, apr_table_t * headers_in);
	http_util_result* hc_ssl_post_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass,const char* postData,int postDataLen, http_ssl_options* sslOptions, apr_table_t * headers_in);
	http_util_result* hc_get_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass, apr_table_t * headers_in,char** error);
	http_util_result* hc_get_verbose2(apr_pool_t *p,char* uri,long timeout,long connectionTimeout,char* userColonPass, apr_table_t * headers_in,char** error);
	http_util_result* hc_ssl_get_verbose(apr_pool_t *p,char* uri,long timeout,long connectionTimeout,char* userColonPass, http_ssl_options* sslOptions, apr_table_t * headers_in, char** error);
	http_util_result* hc_put_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass, char* putData);
	http_util_result* hc_put_verbose2(apr_pool_t *p,char* uri,long timeout,char* userColonPass, const char* putData,int putDataLen, apr_table_t * headers_in);
	http_util_result* hc_method(apr_pool_t *p,const char* methodName,char* uri,long timeout,char* userColonPass,const char* data,int dataLen, apr_table_t * headers_in);
	http_util_result* hc_delete_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass);
	http_util_result* hc_head_verbose(apr_pool_t *p,char* uri,long timeout,char* userColonPass,char** error);
	char* hc_getInfo(apr_pool_t* p);
	http_util_result* hc_get(apr_pool_t *p,char* uri,long timeout);
	int hc_is200_OK(http_util_result* ret);
	
#ifdef __cplusplus
	}
#endif	
#endif /*HTTP_CLIENT_H_*/
