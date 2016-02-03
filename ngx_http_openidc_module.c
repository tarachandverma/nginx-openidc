#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include "oidc_config.h"
#include "config_core.h"
#include "common_utils.h"
#include "http-utils/http_client.h"
#include "logging.h"
#include "url_utils.h"
#include "rewrite_core.h"
#include "oidc_version.h"
#include "oidc_globals.h"

#define MODULE_NAME_ACTION_MAPPINGS	"oidcConfig"
#define HOST_BUFSIZE	256
#define RBUF_SIZE				64000
#define OAUTH_IDTOKEN_MAX_SIZE		8192

// subrequest types
#define SUB_REQUEST_TYPE_UNKNOWS					0
#define SUB_REQUEST_TYPE_OAUTH_TOKEN				1
#define SUB_REQUEST_TYPE_AUTHENTICATE			2
#define SUB_REQUEST_TYPE_AUTHORIZE					3

typedef struct oidc_authz_sub_request_type{
	ngx_uint_t type;	// request type authenticate or token
	ngx_str_t uri;		// subrequest uri
	ngx_str_t content_type;		// requestBody content type
}oidc_authz_sub_request_type;

oidc_authz_sub_request_type oidc_authz_subrequest_type_oauth_token =
		{ SUB_REQUEST_TYPE_OAUTH_TOKEN, ngx_string("/internal/authZ/token"), ngx_string("application/x-www-form-urlencoded")};

oidc_authz_sub_request_type oidc_authz_subrequest_type_authenticate =
		{ SUB_REQUEST_TYPE_AUTHENTICATE, ngx_string("/internal/authZ/authenticate"), ngx_string("application/json")};

oidc_authz_sub_request_type oidc_authz_subrequest_type_authorize =
		{ SUB_REQUEST_TYPE_AUTHORIZE, ngx_string("/internal/authZ/authorize"), ngx_string("application/json")};

	#define ALLOC_IF_NULL(r) \
		{if(r->data==NULL) { r->data = (char*)apr_palloc(r->pool,RBUF_SIZE); memset(r->data,'\0', RBUF_SIZE);}}

	#define ngx_http_openidc_rprintf(r,arg1) \
		{char temp[6144]; sprintf(temp,arg1); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) { ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rprintf1(r,tem,arg1) \
		{char temp[6144]; sprintf(temp,tem,arg1); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) {ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rprintf2(r,tem,arg1,arg2) \
		{char temp[6144]; sprintf(temp,tem,arg1,arg2); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) {ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rprintf3(r,tem,arg1,arg2,arg3) \
		{char temp[6144]; sprintf(temp,tem,arg1,arg2,arg3); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) {ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rprintf4(r,tem,arg1,arg2,arg3,arg4) \
		{char temp[6144]; sprintf(temp,tem,arg1,arg2,arg3,arg4); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) {ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rprintf5(r,tem,arg1,arg2,arg3,arg4,arg5) \
		{char temp[6144]; sprintf(temp,tem,arg1,arg2,arg3,arg4,arg5); int cnt = strlen(temp); if(r->cur+cnt<RBUF_SIZE) {ALLOC_IF_NULL(r) memcpy(r->data+r->cur,temp, cnt); r->cur+=cnt;}}
	#define ngx_http_openidc_rputs(str,r) \
		{ if(str) { int cnt = strlen(str); if(r->cur<RBUF_SIZE) { ALLOC_IF_NULL(r) memcpy(r->data+r->cur,str, cnt); r->cur+=cnt;} } }


apr_pool_t* mainPool = NULL;
int initializedAPR = 0;

typedef struct {
  char*					homeDir;	
  char* 				logFile;
  char*				sheapMapFile;
  int					sheapPageSize;
  char* 				remotePath;
  char* 				remoteAuth;
  int					remotePathTimeout;
  char* 				passPhrase;
  char* 				oidcHeaderPrefix;
  char* 				oidcConfigFile;
  oidc_config* 		oidcConfig;
  config_core* 			configCore;
} Config;

typedef struct {
    ngx_str_t	homeDir;	
    ngx_str_t 	logFile;
    ngx_str_t 	sheapMapFile;
    ngx_int_t	sheapPageSize;
    ngx_str_t 	remotePath;
    ngx_str_t 	remoteAuth;
    ngx_int_t	remotePathTimeout;
    ngx_str_t 	passPhrase;
    ngx_str_t 	oidcHeaderPrefix;
    ngx_str_t 	oidcConfigFile;
    Config* config;
} ngx_http_openidc_srv_conf_t;

/** A structure that represents the current rewrite request */
typedef struct  {
    apr_pool_t *pool;
    char *connection_remote_ip;
    const char *hostname;
    apr_table_t *headers_in;
    apr_table_t *headers_out;
    apr_hash_t* variableHash;
    const char *handler;	/* What we *really* dispatch on */
    char *unparsed_uri;	
    char *uri;
    apr_uri_t parsed_uri;
    ngx_http_request_t*	httpRequest;
    char* data;
    long cur;
}ngx_http_openidc_request_t;

typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
    ngx_str_t 					responseBody;
    ngx_str_t 					responseType;
} ngx_http_openidc_subrequest_ctx_t;

static void *ngx_http_openidc_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_openidc_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_openidc_post_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_openidc_checkForAccess(ngx_http_request_t * httpRequest);
static ngx_int_t ngx_http_openidc_handler(ngx_http_request_t *r);
static void ngx_http_openidc_setActionHeaders(ngx_http_openidc_request_t*r, apr_table_t* headers, array_header* actionHeaders, template_engine* tengine, char* originUri, int addHeaderToHttpRequest);
static int ngx_http_openidc_execUri(ngx_http_openidc_request_t* r, char* uri,int isForward, int isPermanent, char* originUri);
static char* ngx_http_openidc_getPostEntity(ngx_http_openidc_request_t* r, long* sz);
static void ngx_http_openidc_deleteHeader(ngx_http_request_t *r, u_char *key);
static ngx_int_t ngx_http_openidc_setHeader(ngx_http_request_t *r, const char *key, const char *val);
static ngx_int_t ngx_http_openidc_deleteHeaderPart(ngx_list_t *l, ngx_list_part_t *cur, ngx_uint_t i);
static int oidc_index(ngx_http_openidc_request_t *r, Config* config);
static int oidc_version(ngx_http_openidc_request_t *r, Config* config);
static int oidc_rewrite_actionmappings(ngx_http_openidc_request_t *r, Config *config);
static int oidc_rewrite_match(ngx_http_openidc_request_t *r, Config *config);
static int oidc_rewrite_pageactions(ngx_http_openidc_request_t *r, Config *config);
static int oidc_config_core_status(ngx_http_openidc_request_t *r, Config *config);
static int oidc_headers(ngx_http_openidc_request_t *r, Config *config);
static char* ngx_http_openidc_getFullRequestUrl(ngx_http_openidc_request_t* r);
static ngx_int_t ngx_http_openidc_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);
static int ngx_http_openidc_set_id_token_header(ngx_http_request_t* r);
static ngx_int_t ngx_http_openidc_set_subrequest_post_body(ngx_http_request_t * r, ngx_http_request_t * sr, const char* requestBody, ngx_str_t contentType);
static ngx_int_t ngx_http_openidc_preAuthorize(ngx_http_openidc_request_t* r, Config* config);
static ngx_int_t ngx_http_openidc_create_post_subrequest(ngx_http_request_t * r, oidc_authz_sub_request_type sub_request_type, const char* requestBody);

ngx_str_t  ngx_http_openidc_content_length_header_key =
        ngx_string("Content-Length");
ngx_str_t  ngx_http_openidc_content_type_header_key =
        ngx_string("Content-Type");
ngx_str_t  ngx_http_openidc_content_type_formurlencoded =
        ngx_string("application/x-www-form-urlencoded");
ngx_str_t  ngx_http_openidc_content_type_json =
        ngx_string("application/json");

static void ngx_http_openidc_terminate() {
	if(mainPool) apr_pool_destroy(mainPool);
   apr_terminate();
}

static int ngx_http_openidc_die(int exitCode, const char *message, apr_status_t reason) {
    char msgbuf[80];
	apr_strerror(reason, msgbuf, sizeof(msgbuf));
	fprintf(stderr, "%s: %s (%d)\n", message, msgbuf, reason);
	exit(exitCode);
	return reason;
}

static void ngx_http_openidc_initializeAPR() {
	apr_status_t status;
	// Initialize library
	status = apr_initialize();
	if(status!=APR_SUCCESS) { ngx_http_openidc_die(-2, "Could not initialize", status); }
	atexit(ngx_http_openidc_terminate);
	
	// create mainPool
	status = apr_pool_create(&mainPool, NULL);
	if(status!=APR_SUCCESS) { ngx_http_openidc_die(-2, "Could not initialize main pool", status); }
	
	initializedAPR = 1;
}

static char *
ngx_http_openidc_set_home_dir(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t                  *value;
    
    value = cf->args->elts;
    
    sscf->homeDir = value[1];
//	printf("ngx_http_openidc_set_home_dir:%d", getpid());

    return NGX_CONF_OK;
}

static char *
ngx_http_openidc_set_log_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t                  *value, *url;
    
    value = cf->args->elts;
    url = &value[1];
    
    sscf->logFile = value[1];
//	printf("ngx_http_openidc_set_log_file:%d", getpid());

    return NGX_CONF_OK;
}

static char *
ngx_http_openidc_set_shm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t* value;
    int i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "file=", 5) == 0) {
        	 	 sscf->sheapMapFile.len = value[i].len - 5;
        	 	 sscf->sheapMapFile.data = value[i].data + 5;
        	 	 continue;
        }

        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
        		sscf->sheapPageSize= ngx_atoi(value[i].data + 5, value[i].len - 5);
            continue;
        }

    }

//	printf("ngx_http_openidc_set_shm:%d", getpid());

    return NGX_CONF_OK;
}

static char *
ngx_http_openidc_set_remote_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t* value;
    int i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "uri=", 4) == 0) {
        	 	 sscf->remotePath.len = value[i].len - 4;
        	 	 sscf->remotePath.data = value[i].data + 4;
        	 	 continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
        		sscf->remotePathTimeout= ngx_atoi(value[i].data + 8, value[i].len - 8);
            continue;
        }

        if (ngx_strncmp(value[i].data, "user:pass=", 10) == 0) {
        	 	 sscf->remoteAuth.len = value[i].len - 10;
        	 	 sscf->remoteAuth.data = value[i].data + 10;
        	 	 continue;
        }

    }

//	printf("ngx_http_openidc_set_remote_path:%d", getpid());

    return NGX_CONF_OK;
}

static char *
ngx_http_openidc_set_pass_phrase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t                  *value, *url;

    value = cf->args->elts;
    url = &value[1];

    sscf->passPhrase = value[1];
//	printf("ngx_http_openidc_set_pass_phrase:%d", getpid());

    return NGX_CONF_OK;
}

static char *
ngx_http_openidc_set_header_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t                  *value, *url;

    value = cf->args->elts;
    url = &value[1];

    sscf->oidcHeaderPrefix = value[1];
//	printf("ngx_http_openidc_set_header_prefix:%d", getpid());

    return NGX_CONF_OK;
}

typedef struct ce_error_list{
	apr_array_header_t* data;
}ce_error_list;

static ce_error_list* ce_newErrorListObj(pool* p){
	ce_error_list* ret=(ce_error_list*)apr_pcalloc(p,sizeof(ce_error_list));
	ret->data=apr_array_make(p,4,sizeof(char*));\
	return ret;
}

static void ce_addErrorWithType(pool* p, ce_error_list* elist, char* mtype, char* msg){
	char** place=NULL;
	char* item=NULL;
	
	if(elist==NULL||msg==NULL) return;

	if(mtype!=NULL){
		item=apr_pstrcat(p,"[",mtype,"] ",msg,NULL);	
	}else{
		item=apr_pstrdup(p,msg);
	}
	place=(char**)apr_array_push(elist->data);
	*place=item;
}

static void ce_printList(pool* p,ce_error_list* elist){
	int i=0;
	char* item=NULL;
	apr_array_header_t* arry=NULL;
	if(elist==NULL) return;
	
	arry=elist->data;
	for(i=0;i<arry->nelts;i++){
		item=cu_getElement(arry,i);
		printf("• %s\n",item);
	}
}

static int ce_hasErrors(ce_error_list* elist){
	return elist!=NULL&&elist->data->nelts>0;
}

static char* ngx_http_openidc_postRefreshBind(apr_pool_t* p,Config* config){
	if(config->configCore==NULL){
		return apr_pstrdup(p,"Config Core is NULL");
	}
	
	config->oidcConfig=(oidc_config*)configcore_getModuleConfigByName(config->configCore,MODULE_NAME_ACTION_MAPPINGS);
	if(config->oidcConfig==NULL){
		return apr_pstrcat(p,"! Missing Required Service Name:",MODULE_NAME_ACTION_MAPPINGS,NULL);
	}
	
	return NULL;
}

static void ngx_http_openidc_postConfigStarting(apr_pool_t* p, const char* defn_name, int is_virtual, Config* config){
	printf("\n¬ª¬ª¬ª Initializing(%s)%s \n",defn_name!=NULL?defn_name:"-",is_virtual?"**VIRTUAL**":"");
	printf("* Note: If initialization seems slow. Check your DNS. It may have become slow or unresponsive.\r\n");
	if(config->oidcConfigFile!=NULL){
		config_core* ccore=NULL;
		ce_error_list* errorList=NULL;
		char* error=NULL;
		char cbuf[APR_CTIME_LEN + 1];
		
		config->logFile = apr_pstrcat(p,config->homeDir,"/",config->logFile,NULL);
		
		lc_openLogFile(p,config->logFile);
		lc_truncateLogFile();
		apr_time_t t1 = apr_time_now();
		apr_ctime(cbuf, t1);
		lc_printLog("\n¬∞\t Initializing %s [%s]\n",VERSION_ID,cbuf);
		fflush(stdout);
		hc_init();
				
		//init Error Obj
		errorList=ce_newErrorListObj(p);
		
		//load crypto core
		lc_printLog("\r\n\r\n");
		ccore=configcore_newConfigCoreObj(p);
		ccore->globals->homeDir=apr_pstrdup(p,config->homeDir);
		ccore->globals->logsDir=apr_pstrcat(p,config->homeDir,"/logs",NULL);		
		ccore->refreshLogFile=apr_pstrdup(p,config->logFile);

		// shared memory
		ccore->sheapMapFile=apr_pstrdup(p,config->sheapMapFile);
		ccore->sheapPageSize=config->sheapPageSize;

		// remote path
		if(config->remotePath!=NULL) {
			ccore->globals->resourceService = cb_newServiceDescriptorObj(p);
			ccore->globals->resourceService->uri=apr_pstrdup(p,config->remotePath);
			ccore->globals->resourceService->userColonPass=apr_pstrdup(p,config->remoteAuth);
			ccore->globals->resourceService->timeoutSeconds=config->remotePathTimeout;
		}

		// oidc stuff
		ccore->passPhrase=apr_pstrdup(p,config->passPhrase);
		ccore->oidcHeaderPrefix=apr_pstrdup(p,config->oidcHeaderPrefix);
		ccore->oidcConfigFile=apr_pstrdup(p,config->oidcConfigFile);

		ce_addErrorWithType(p,errorList,"Config Core Load File",error);
		if(error==NULL){
			configcore_printConfigCoreDetails(p,ccore);
			error=configcore_initializeConfigCore(p,ccore);
			ce_addErrorWithType(p,errorList,"Config Core Init",error);
			config->configCore=ccore;
			lc_printLog("‚àö Config Core Initialized\n");
			
			lc_printLog("¬∞ Binding Config Core Services\n");
			error=ngx_http_openidc_postRefreshBind(p,config);
			ce_addErrorWithType(p,errorList,"Config Core Bind",error);
		}
		
		if(!ce_hasErrors(errorList)){
			long timeTakenMillis = ((apr_time_now() - t1) / 1000);
			lc_printLog("\r\n>> %s - SUCCESS - Configuration loaded successfully [time taken : %d milliseconds]<<\r\n",VERSION_ID,timeTakenMillis);
		}else{
			lc_printLog("\r\n>> %s - ERRORS - Please check with development support if its ok to continue deployment..<<\r\n\n\n",VERSION_ID);
			ce_printList(p,errorList);
		}
		lc_closeLogFile();	
	}else{
		printf("!\n!\n!\t%sModule Config un-initializable!\n",is_virtual?"**VIRTUAL** ":"");
		printf("!\tThis is usually because you are missing settings for the default host.\n!\n!\n\n");
	}
}


static char *
ngx_http_openidc_set_configcore_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_openidc_srv_conf_t *sscf = conf;

    ngx_str_t                  *value;
    
    value = cf->args->elts;
    
    sscf->oidcConfigFile = value[1];
//	printf("ngx_http_openidc_set_configcore_file:%d", getpid());
	if(!initializedAPR) {
		ngx_http_openidc_initializeAPR();
	}

	if(sscf->homeDir.data==NULL) {
//        ngx_log_error(NGX_LOG_ERR, cmd->log, 0, "rewrite home directory missing");
//        return NGX_ERROR;
	}
	sscf->config=ngx_pcalloc(cf->pool, sizeof(Config));
	sscf->config->homeDir=apr_pstrndup(mainPool, (char*)sscf->homeDir.data, sscf->homeDir.len);
	sscf->config->logFile=apr_pstrndup(mainPool, (char*)sscf->logFile.data, sscf->logFile.len);

	// shared memory
	sscf->config->sheapMapFile = (sscf->sheapMapFile.len>0)
			? apr_pstrndup(mainPool, (char*)sscf->sheapMapFile.data, sscf->sheapMapFile.len)
			: apr_pstrdup(mainPool, "/config.shm");

	sscf->config->sheapPageSize=(sscf->sheapPageSize>0) ? sscf->sheapPageSize : 64000;


	// remote path
	if(sscf->remotePath.len>0) {
		sscf->config->remotePath=apr_pstrndup(mainPool, (char*)sscf->remotePath.data, sscf->remotePath.len);
		sscf->config->remoteAuth = (sscf->remoteAuth.len>0)
				? apr_pstrndup(mainPool, (char*)sscf->remoteAuth.data, sscf->remoteAuth.len)
				: NULL;
		sscf->config->remotePathTimeout=(sscf->remotePathTimeout>0) ? sscf->remotePathTimeout : 10;
	}

	sscf->config->passPhrase = (sscf->passPhrase.len>0)
			? apr_pstrndup(mainPool, (char*)sscf->passPhrase.data, sscf->passPhrase.len)
			: NULL;

	sscf->config->oidcHeaderPrefix = (sscf->oidcHeaderPrefix.len>0)
			? apr_pstrndup(mainPool, (char*)sscf->oidcHeaderPrefix.data, sscf->oidcHeaderPrefix.len)
			: apr_pstrdup(mainPool, "X-OIDC-");

	sscf->config->oidcConfigFile = (sscf->oidcConfigFile.len>0)
			? apr_pstrndup(mainPool, (char*)sscf->oidcConfigFile.data, sscf->oidcConfigFile.len)
			: apr_pstrdup(mainPool, "oidc-config.xml");

    djrglobals_setEnableUnnamedSHM("true");

	ngx_http_openidc_postConfigStarting(mainPool,"authz_oidc",FALSE,sscf->config);

    return NGX_CONF_OK;
}
static ngx_command_t  ngx_http_openidc_commands[] = {
    { ngx_string("AUTHZOIDC_HomeDir"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_home_dir,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL }, 
    { ngx_string("AUTHZOIDC_LogFile"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_log_file,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },
	{ ngx_string("AUTHZOIDC_SharedMemory"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_shm,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },
	{ ngx_string("AUTHZOIDC_RemotePath"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE123,
	  ngx_http_openidc_set_remote_path,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },
	{ ngx_string("AUTHZOIDC_PassPhrase"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_pass_phrase,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },
	{ ngx_string("AUTHZOIDC_HeaderPrefix"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_header_prefix,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },
    { ngx_string("AUTHZOIDC_ConfigFile"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
	  ngx_http_openidc_set_configcore_file,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  0,
	  NULL },	  
      ngx_null_command
};

static ngx_http_module_t  ngx_http_openidc_module_ctx = {
    NULL,            						/* preconfiguration */
    ngx_http_openidc_post_config,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_openidc_create_srv_conf,          /* create server configuration */
    ngx_http_openidc_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_int_t ainit_master(ngx_log_t *log) {
//	printf("ainit_master:%d", getpid());
	return NGX_OK;
}

ngx_int_t ainit_module(ngx_cycle_t *cycle) {
//	printf("ainit_module:%d", getpid());
	return NGX_OK;
}

ngx_int_t ainit_process(ngx_cycle_t *cycle) {
//	printf("ainit_process:%d", getpid());
	return NGX_OK;
}

void aexit_process(ngx_cycle_t *cycle) {
	ngx_http_openidc_terminate();
//	printf("aexit_process:%d", getpid());
}

void aexit_master(ngx_cycle_t *cycle) {
	ngx_http_openidc_terminate();
//	printf("aexit_master:%d", getpid());
}


ngx_module_t  ngx_http_openidc_module = {
    NGX_MODULE_V1,
    &ngx_http_openidc_module_ctx,              /* module context */
    ngx_http_openidc_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ainit_master,                                  /* init master */
    ainit_module,                                  /* init module */
    ainit_process,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    aexit_process,                                  /* exit process */
    aexit_master,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_openidc_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_openidc_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_openidc_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }
//    printf("ngx_http_openidc_create_srv_conf:%p %d\r\n", sscf, getpid());
    return sscf;
}


static char *
ngx_http_openidc_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_openidc_srv_conf_t *prev = parent;
	ngx_http_openidc_srv_conf_t *conf = child;
	
	if(conf->homeDir.data==NULL) {
		conf->homeDir = prev->homeDir;
	}
	if(conf->logFile.data==NULL) {
		conf->logFile = prev->logFile;
	}
	if(conf->sheapMapFile.data==NULL) {
		conf->sheapMapFile = prev->sheapMapFile;
	}
	if(conf->sheapPageSize==0) {
		conf->sheapPageSize = prev->sheapPageSize;
	}
	if(conf->remotePath.data==NULL) {
		conf->remotePath = prev->remotePath;
	}
	if(conf->remoteAuth.data==NULL) {
		conf->remoteAuth = prev->remoteAuth;
	}
	if(conf->remotePathTimeout==0) {
		conf->remotePathTimeout = prev->remotePathTimeout;
	}
	if(conf->passPhrase.data==NULL) {
		conf->passPhrase = prev->passPhrase;
	}
	if(conf->oidcHeaderPrefix.data==NULL) {
		conf->oidcHeaderPrefix = prev->oidcHeaderPrefix;
	}
	if(conf->oidcConfigFile.data==NULL) {
		conf->oidcConfigFile = prev->oidcConfigFile;
	}
	if(conf->config==NULL) {
		conf->config = prev->config;
	}
//    printf("ngx_http_openidc_merge_srv_conf:%p %p %d\r\n", prev,conf,getpid());
    return NGX_CONF_OK;
}

static ngx_http_openidc_request_t* ngx_http_openidc_createRequest(apr_pool_t* p) {
	ngx_http_openidc_request_t* r = (ngx_http_openidc_request_t *) apr_pcalloc(p, sizeof(ngx_http_openidc_request_t));
    r->pool = p;
    r->connection_remote_ip=NULL;
    r->headers_in      = apr_table_make(r->pool, 12);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->variableHash = apr_hash_make(r->pool);
    //memset(r_buf,'\0', RBUF_SIZE);
    r->data=NULL;
    r->cur=0;
    return r;
}

static void ngx_http_openidc_setHeadersIn(ngx_http_request_t *httpRequest, ngx_http_openidc_request_t* r, char* headerPrefix) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;
    apr_pool_t* p = r->pool;
    apr_table_t* headersIn = r->headers_in;
    size_t prefixLen = (headerPrefix!=NULL) ? strlen(headerPrefix) : 0;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &httpRequest->headers_in.headers.part;
    h = part->elts;
 
    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }
 
            part = part->next;
            h = part->elts;
            i = 0;
        }
 
		if ( prefixLen>0 && prefixLen < h[i].key.len && (ngx_strcasestrn(h[i].key.data, headerPrefix, prefixLen-1)==h[i].key.data) ) {
			/* This is incompletion. */
			/*
			  h[i].hash = 0;
			  h[i].key.len = 0;
			  h[i].key.data = NULL;
			  h[i].value.len = 0;
			  h[i].value.data = NULL;
			*/
			ngx_http_openidc_deleteHeaderPart(&httpRequest->headers_in.headers, part, i);
		}else{
			char* key = apr_pstrndup(p, (char*)h[i].key.data, h[i].key.len);
			char* value = apr_pstrndup(p, (char*)h[i].value.data, h[i].value.len);
			apr_table_set(headersIn,key,value);
		}
    }
 
    /*
    No headers was found
    */
    return ;
}

ngx_int_t ngx_http_openidc_setHeaderInHeadersOut(ngx_http_request_t *r, const char *key, const char *val) {
    ngx_table_elt_t   *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.len = strlen(key);
    h->value.len = strlen(val);;

    h->key.data = ngx_pnalloc(r->pool,
                       h->key.len + 1 + h->value.len + 1 + h->key.len);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }

    h->value.data = h->key.data + h->key.len + 1;
    h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

    ngx_memcpy(h->key.data, key, h->key.len);
    h->key.data[h->key.len] = '\0';

    ngx_memcpy(h->value.data, val, h->value.len);
    h->value.data[h->value.len] = '\0';

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->hash = r->header_hash;

    return NGX_OK;
}

ngx_int_t ngx_http_openidc_setHeaderInHeadersIn(ngx_http_request_t *r, const char *keyStr, const char *valueStr) {
    ngx_table_elt_t   *h;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.len = strlen(keyStr);
    h->value.len = strlen(valueStr);;

    h->key.data = ngx_pnalloc(r->pool,
                       h->key.len + 1 + h->value.len + 1 + h->key.len);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }

    h->value.data = h->key.data + h->key.len + 1;
    h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

    ngx_memcpy(h->key.data, keyStr, h->key.len);
    h->key.data[h->key.len] = '\0';

    ngx_memcpy(h->value.data, valueStr, h->value.len);
    h->value.data[h->value.len] = '\0';

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->hash = r->header_hash;


    return NGX_OK;
}

static ngx_int_t ngx_http_openidc_post_config(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // check access phase
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_openidc_checkForAccess;

    // custom content generator handler
//    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
//    if (h == NULL) {
//        return NGX_ERROR;
//    }

//    *h = ngx_http_openidc_handler;

//    printf("ngx_http_openidc_post_config:%d\r\n", getpid());
    return NGX_OK;
}

static int ngx_http_openidc_addResponseHeaderCallback(void *rec, const char *keyStr, const char *valueStr){
	ngx_http_request_t *httpRequest = (ngx_http_request_t*)rec;
	if(keyStr&&valueStr&&httpRequest) {
	    ngx_http_openidc_setHeaderInHeadersOut(httpRequest, keyStr, valueStr);
	}
	return 1;
}

static ngx_int_t ngx_http_openidc_sendResponse(ngx_http_openidc_request_t* r) {
	
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    int dataLen=0;
    
	// return if contentType or body not found
	if(r->data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	
    /* set the 'Content-type' header */
	r->httpRequest->headers_out.content_type_len = sizeof("text/html") - 1;
	r->httpRequest->headers_out.content_type.len = sizeof("text/html") - 1;
	r->httpRequest->headers_out.content_type.data = (u_char *) "text/html";

    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->httpRequest->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;
    //r->data = apr_psprintf(workerPool, "r->handler=%s retCode=%d", r->handler, retCode); 
    /* adjust the pointers of the buffer */
	dataLen = strlen(r->data);
    b->pos = (u_char*)r->data;
    b->last = (u_char*)r->data + dataLen;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */

    /* set the status line */
    r->httpRequest->headers_out.status = NGX_HTTP_OK;
    r->httpRequest->headers_out.content_length_n = dataLen;
	 
    /* send the headers of your response */
    rc = ngx_http_send_header(r->httpRequest);

    if (rc == NGX_ERROR || rc > NGX_OK || r->httpRequest->header_only) {
        return rc;
    }

    /* send the buffer chain of your response */
    return ngx_http_output_filter(r->httpRequest, &out);			    
}

ngx_table_elt_t* ngx_http_openidc_lookupHeader(ngx_http_request_t *r, u_char *key) {
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    size_t len = strlen((char *)key);

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (len != h[i].key.len || ngx_strcasecmp(key, h[i].key.data) != 0) {
            continue;
        }
        return &h[i];
    }
    return NULL;
}

ngx_int_t ngx_http_openidc_setHeader(ngx_http_request_t *r, const char *key, const char *val) {
    ngx_table_elt_t   *h;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.len = strlen(key);
    h->value.len = strlen(val);;

    h->key.data = ngx_pnalloc(r->pool,
                       h->key.len + 1 + h->value.len + 1 + h->key.len);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }

    h->value.data = h->key.data + h->key.len + 1;
    h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

    ngx_memcpy(h->key.data, key, h->key.len);
    h->key.data[h->key.len] = '\0';

    ngx_memcpy(h->value.data, val, h->value.len);
    h->value.data[h->value.len] = '\0';

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->hash = r->header_hash;


    return NGX_OK;
}

/*
 * delete header part
 */
static ngx_int_t ngx_http_openidc_deleteHeaderPart(ngx_list_t *l,
                               ngx_list_part_t *cur,
                               ngx_uint_t i) {
    ngx_table_elt_t *elts = cur->elts;
    ngx_list_part_t *new, *part;

    if (i == 0) {
        cur->elts = (char *) cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            if (l->nalloc > 1) {
                l->nalloc--;
                return NGX_OK;
            }
            part = &l->part;
            while (part->next != cur) {
                if (part->next == NULL) {
                    return NGX_ERROR;
                }
                part = part->next;
            }
            part->next = NULL;
            l->last = part;
            return NGX_OK;
        }

        if (cur->nelts == 0) {
            part = &l->part;
            while (part->next != cur) {
                if (part->next == NULL) {
                    return NGX_ERROR;
                }
                part = part->next;
            }

            part->next = cur->next;
            return NGX_OK;
        }
        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        cur->nelts--;
        if (cur == l->last) {
            l->nalloc--;
        }
        return NGX_OK;
    }

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &elts[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    l->nalloc = new->nelts;

    cur->nelts = i;
    cur->next = new;
    if (cur == l->last) {
        l->last = new;
    }

    cur = new;
    return NGX_OK;
}

/*
 * delete header if exists
 */
void ngx_http_openidc_deleteHeader(ngx_http_request_t *r, u_char *key) {
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    size_t len = strlen((char *)key);

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (len == h[i].key.len && ngx_strcasecmp(key, h[i].key.data) == 0) {
            /* This is incompletion. */
            /*
              h[i].hash = 0;
              h[i].key.len = 0;
              h[i].key.data = NULL;
              h[i].value.len = 0;
              h[i].value.data = NULL;
            */
        	ngx_http_openidc_deleteHeaderPart(&r->headers_in.headers, part, i);
        }
    }
}

static const char *ngx_http_openidc_requestVar(ngx_http_openidc_request_t *r, const char* arg)
{
	char* start = NULL;
	if(arg==NULL) return NULL;

	if((start = strstr(arg, "HTTP_"))) {
		   return apr_table_get(r->headers_in, start+5);
	} else if(strcmp(arg,"REQ_URI")==0) {
		return r->uri;
	} else if(strcmp(arg,"REQ_UNPARSED_URI")==0) {
		return r->unparsed_uri;
	}else if(strcmp(arg,"REQ_URI_ENCODED")==0) {
		return url_encode2(r->pool, r->uri);
	} else if(strcmp(arg,"REQ_UNPARSED_URI_ENCODED")==0) {
		return url_encode2(r->pool, r->unparsed_uri);
	} else if(strcmp(arg,"REQ_QUERY")==0) {
		uri_components *url = &r->parsed_uri;
		return url_getParam(r->pool, url->query, arg);
	}
	return NULL;
}
static const char *ngx_http_openidc_serverVars(ngx_http_openidc_request_t *r, const char* arg)
{
	 return (arg!=NULL) ? apr_hash_get(r->variableHash, arg, APR_HASH_KEY_STRING) : NULL;
}
static const char *ngx_http_openidc_requestCookie(ngx_http_openidc_request_t *r, const char *arg)
{
	if(arg==NULL) return "(null)";
	const char *s = cookie_getCookieByName(r->pool, r->headers_in, arg, strlen(arg));
   if (s)
       return s;
   else
       return "(null)";
}

static const char *ngx_http_openidc_urlDecodeToken(ngx_http_openidc_request_t *r, const char *arg){
	return url_decode2(r->pool,(char*)arg);
}

static const char *ngx_http_openidc_urlEncodeToken(ngx_http_openidc_request_t *r, const char *arg){
	return url_encode2(r->pool,(char*)arg);
}

	typedef struct tag_handler{
		const char c;
		const char* (*func)(ngx_http_openidc_request_t*,const char* arg);
	}tag_handler;
	
	static const tag_handler tagHandlers[] = {
			{'r', ngx_http_openidc_requestVar},
			{'s', ngx_http_openidc_serverVars},
			{'c', ngx_http_openidc_requestCookie},
			{'u', ngx_http_openidc_urlDecodeToken},
			{'U', ngx_http_openidc_urlEncodeToken}
	};

static const char* ngx_http_openidc_getTagValue(char* s, ngx_http_openidc_request_t*r, char**next) {
	unsigned int i;
	char* arg = NULL, *end=NULL;
	s++;
    if (*s == '{') {
        if((end = strchr(s, '}'))!=NULL) {
	        arg = apr_pstrndup(r->pool, s+1, end-s-1);
	        s=end+1;	// pass by '}'
        }
    }
	for(i=0; i < sizeof(tagHandlers)/sizeof(tag_handler); i++ ){
		if(tagHandlers[i].c==*s) {
			*next = s+1; // pass by the current character.
			return (*tagHandlers[i].func)(r, arg);
		}
	}
	return NULL;
}

static char* ngx_http_openidc_parseString(pool*p, char*src, ngx_http_openidc_request_t *r){
	#define HDR_BUF_SIZE	4096
	if(src==NULL) return NULL;
	char*ret=(char*)apr_palloc(p, HDR_BUF_SIZE);
	char*q=ret;
	const char* str = NULL;
	
	while(*src!='\0'){
		if(*src=='%'&&(str = ngx_http_openidc_getTagValue(src, r, &src))){
			strcpy(q, str);
			q += strlen(str);
		}else{
			*q++=*src++;
		}
	}
	*q='\0';
	
	return ret;
}

static char* ngx_http_openidc_processTags(action_header *hdr, ngx_http_openidc_request_t *r, template_engine* tengine, char* originUri)
{
   char* hdrValue = ngx_http_openidc_parseString(r->pool, apr_pstrdup(r->pool, hdr->value), r);
	if(hdr->regex!=NULL&&hdrValue!=NULL){
		array_header* matches=NULL;
		rc_matchByStringsPattern(r->pool, hdr->regex, originUri, &matches);
		hdrValue=te_templateString(r->pool,tengine,hdrValue,matches);
	}
   return (hdrValue!=NULL) ? apr_pstrdup(r->pool, hdrValue) : "";
}

static void ngx_http_openidc_setActionHeaders(ngx_http_openidc_request_t*r, apr_table_t* headers, array_header* actionHeaders, template_engine* tengine, char* originUri, int addHeaderToHttpRequest){
   int i;
   char* headerValue=NULL;		
		if(actionHeaders==NULL||actionHeaders->nelts<0 || headers==NULL) return;

		for(i=0; i<actionHeaders->nelts; i++){
			action_header* hdr = (action_header*)cu_getElement(actionHeaders, i);
			if(hdr!=NULL){
				switch (hdr->action) {
				case header_add:
					headerValue = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
					apr_table_add(headers, hdr->name, headerValue);
					if(addHeaderToHttpRequest){
						ngx_http_openidc_setHeader(r->httpRequest, hdr->name, headerValue);
					}
					break;
				case header_append:
					headerValue = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
					apr_table_merge(headers, hdr->name, headerValue);
					if(addHeaderToHttpRequest){
						ngx_http_openidc_setHeader(r->httpRequest, hdr->name, headerValue);
					}
					break;
//				case header_merge:
//					val = apr_table_get(headers, hdr->name);
//					if (val == NULL) {
//						headerValue = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
//						apr_table_add(headers, hdr->name, headerValue);
//						if(addHeaderToHttpRequest){
//							ngx_http_openidc_setHeader(r->httpRequest, hdr->name, headerValue);
//						}
//					} else {
//						char *new_val = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
//						apr_size_t new_val_len = strlen(new_val);
//						int tok_found = 0;
//
//						/* modified version of logic in ap_get_token() */
//						while (*val) {
//							const char *tok_start;
//
//							while (*val && apr_isspace(*val))
//								++val;
//
//							tok_start = val;
//
//							while (*val && *val != ',') {
//								if (*val++ == '"')
//									while (*val)
//										if (*val++ == '"')
//											break;
//							}
//
//							if (new_val_len == (apr_size_t)(val - tok_start)
//									&& !strncmp(tok_start, new_val, new_val_len)) {
//								tok_found = 1;
//								break;
//							}
//
//							if (*val)
//								++val;
//						}
//
//						if (!tok_found) {
//							apr_table_merge(headers, hdr->name, new_val);
//						}
//					}
//					break;
				case header_set:
		            if (!strcasecmp(hdr->name, "Content-Type")) {
		            	char* content_type = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
		            	if(content_type!=NULL){
		            		r->httpRequest->headers_out.content_type.len = strlen(content_type);
		            		r->httpRequest->headers_out.content_type.data = (u_char *)content_type;
		            	}
		            }
		            headerValue = ngx_http_openidc_processTags(hdr, r, tengine, originUri);
					apr_table_set(headers, hdr->name, headerValue);
					if(addHeaderToHttpRequest){
						ngx_http_openidc_setHeader(r->httpRequest, hdr->name, headerValue);
					}
					break;
				case header_unset:
					apr_table_unset(headers, hdr->name);
					if(addHeaderToHttpRequest){
						ngx_http_openidc_deleteHeader(r->httpRequest,hdr->name);
					}
					break;
				case header_merge:
				case header_echo:
				case header_edit:
					apr_table_add(r->headers_out,"X-HEADER-OPERATION","not supported");
					break;					
				}  	  			
	  		}
		}
}

static int ngx_http_openidc_execCustomResponse(ngx_http_openidc_request_t *r, int responseCode, char* contentType, const char* responseBodyTemplate, template_engine* tengine) {

		if(responseBodyTemplate!=NULL){

			// process template
			char* responseBody = ngx_http_openidc_parseString(r->pool, apr_pstrdup(r->pool, responseBodyTemplate), r);
			/**
			 * Set the headers in response stream.
			 */
			apr_table_do(ngx_http_openidc_addResponseHeaderCallback, r->httpRequest, r->headers_out, NULL);
			if(responseBody!=NULL){ // have response data from proxy
			    ngx_int_t    rc;
			    ngx_buf_t   *b;
			    ngx_chain_t  out;

				// return if contentType or body not found
				if(contentType==NULL||responseBody==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

				rc = ngx_http_discard_request_body(r->httpRequest);
			    if (rc != NGX_OK) {
			        return rc;
			    }

			    /* set the 'Content-type' header */
			    r->httpRequest->headers_out.content_type_len = strlen(contentType);
			    r->httpRequest->headers_out.content_type.len = strlen(contentType);
			    r->httpRequest->headers_out.content_type.data = (u_char *)contentType;

			    /* allocate a buffer for your response body */
			    b = ngx_pcalloc(r->httpRequest->pool, sizeof(ngx_buf_t));
			    if (b == NULL) {
			        return NGX_HTTP_INTERNAL_SERVER_ERROR;
			    }

			    /* attach this buffer to the buffer chain */
			    out.buf = b;
			    out.next = NULL;
			    //r->data = apr_psprintf(workerPool, "r->handler=%s retCode=%d", r->handler, retCode);
			    /* adjust the pointers of the buffer */
			    b->pos = (u_char*)responseBody;
			    b->last = (u_char*)responseBody + strlen(responseBody);
			    b->memory = 1;    /* this buffer is in memory */
			    b->last_buf = 1;  /* this is the last buffer in the buffer chain */

			    /* set the status line */
			    r->httpRequest->headers_out.status = ( responseCode > 0 ) ? responseCode : NGX_HTTP_OK;
			    r->httpRequest->headers_out.content_length_n = strlen(responseBody);

			    /* send the headers of your response */
			    rc = ngx_http_send_header(r->httpRequest);

			    if (rc == NGX_ERROR || rc > NGX_OK || r->httpRequest->header_only) {
			        return rc;
			    }

			    /* send the buffer chain of your response */
			    return ngx_http_output_filter(r->httpRequest, &out);
			}
			return NGX_HTTP_OK;
		}
		return NGX_DECLINED;
 }

static int ngx_http_openidc_execPageAction(ngx_http_openidc_request_t *r, page_action* paction, char* originUri){
	char* destUri=NULL;
	array_header* matches=NULL;
	int ret=0;

//		AP_LOG_ERROR(r,"ngx_http_openidc_execPageAction");
	if(paction!=NULL){
		
			if(paction->isDebug==1){
				char buf[256];
				if(gethostname(buf,256)==0){
		 			apr_table_add(r->headers_out,"X-DEBUG-BOX-IDENT",apr_pstrdup(r->pool,buf));
				}   				
		}
		
		if (paction->requestHeaders!=NULL) {
			ngx_http_openidc_setActionHeaders(r, r->headers_in, paction->requestHeaders, paction->templateEngineRef, originUri, TRUE);
		}			

		if(paction->handler_internal!=NULL){
//				AP_LOG_ERROR1(r,"paction->handler_internal=%s",paction->handler_internal);
			r->handler=paction->handler_internal;
		}

		if(paction->uri!=NULL){
			
			char* paction_uri = paction->uri;

			//do url Templating
			//destUri
			if(paction->regex!=NULL){
				rc_matchByStringsPattern(r->pool, paction->regex, originUri, &matches);
				destUri=te_templateString(r->pool,paction->templateEngineRef,paction_uri,matches);
			}

			//ensure dest url is valid
			if(destUri==NULL){
				destUri=paction_uri;
			}
			
			//process dateTemplate
			if(paction->advancedTemplate==TRUE){
				destUri = ngx_http_openidc_parseString(r->pool, apr_pstrdup(r->pool, destUri), r);
			}

			if (paction->responseHeaders!=NULL) {
				ngx_http_openidc_setActionHeaders(r, r->headers_out, paction->responseHeaders, paction->templateEngineRef, originUri, FALSE);
			}
			ret = ngx_http_openidc_execUri(r,destUri,paction->isForward,paction->isPermanent,originUri);
			return ret;

		}else{	// allowing to set the response headers even if uri is not configured.
			if (paction->responseHeaders!=NULL) {
				ngx_http_openidc_setActionHeaders(r, r->headers_out, paction->responseHeaders, paction->templateEngineRef, originUri, FALSE);
			}
			if(paction->response!=NULL) {
				return ngx_http_openidc_execCustomResponse(r, paction->response->code, paction->response->contentType, paction->response->body, paction->templateEngineRef);
			}
		}
	}
	return NGX_DECLINED;
}

int ngx_http_openidc_execUri(ngx_http_openidc_request_t* r, char* uri,int isForward, int isPermanent, char* originUri) {
	if(uri!=NULL){
		//execute
		if(isForward){
			if(originUri!=NULL){
				ngx_http_openidc_setHeader(r->httpRequest, "X-MODAUTH-ORIGIN-URI", originUri);
			}
	//		if(r->filename!=NULL){
	//			apr_table_setn(r->headers_in, "X-MODAUTH-ORIGIN-FILENAME", r->filename);
	//		}
			int len = strlen(uri);
			u_char* ngxUri = ngx_palloc(r->httpRequest->pool, len + 1);
			ngx_cpystrn(ngxUri, (u_char*)uri, len + 1);
		    ngx_str_t internalRedirect = { len, ngxUri };			
			ngx_http_internal_redirect(r->httpRequest, &internalRedirect , &r->httpRequest->args);
			return NGX_HTTP_OK;
		}else if(isPermanent){
			apr_table_setn(r->headers_out, "Location", uri);
			return NGX_HTTP_MOVED_PERMANENTLY;
		}else {
			apr_table_setn(r->headers_out, "Location", uri);
			return NGX_HTTP_MOVED_TEMPORARILY;
		}
	}
	return NGX_DECLINED;	
}

static void ngx_oidc_body_handler ( ngx_http_request_t *r ) {
        ngx_int_t rc = NGX_OK;
 
     // TODO: Read request body here
     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r,0); 
    }
    
    return;
}

static ngx_int_t ngx_http_openidc_getPostEntityINT(ngx_http_request_t *r) {
    ngx_int_t                   rc;

    //TODO: Add handler
    rc = ngx_http_read_client_request_body(r, ngx_oidc_body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static char* ngx_http_openidc_getPostEntity(ngx_http_openidc_request_t* r, long* sz) {
	char* buf=NULL;
	
	ngx_http_openidc_getPostEntityINT(r->httpRequest);

	*sz = 0;
	
	return buf;
}

static char* ngx_http_openidc_getFullRequestUrl(ngx_http_openidc_request_t *req){
	uri_components *url = &req->parsed_uri;
	char* relativeUrl;

	char* scheme=(char*)apr_table_get(req->headers_in, "X-Forwarded-Proto");
	if(scheme==NULL) {
		scheme=(char*)apr_table_get(req->headers_in, "X-REQUEST-SCHEME");
	}

	if(((strcmp(scheme,"http")!=0&&url->port!=80)||(strcmp(scheme,"https")!=0&&url->port!=443))&&url->port_str!=NULL){
		relativeUrl=apr_pstrcat(req->pool,scheme,"://", req->hostname,":",url->port_str,req->unparsed_uri, NULL);
	}else{
		relativeUrl=apr_pstrcat(req->pool,scheme,"://", req->hostname,req->unparsed_uri, NULL);
	}

	return relativeUrl;
}

typedef int (*ngx_http_openidc_handler_func)(ngx_http_openidc_request_t*r, Config* config);

typedef struct ngx_http_openidc_handler_t{
	ngx_http_openidc_handler_func handlerFunc;
}ngx_http_openidc_handler_t;

static const ngx_http_openidc_handler_t ngx_http_oidcHandlers[] = {
		{oidc_index},
		{oidc_version},
		{oidc_rewrite_match},
		{oidc_rewrite_pageactions},
		{oidc_rewrite_actionmappings},
		{oidc_config_core_status},
		{oidc_headers}
};

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


static const char* oauth_toupper(pool*p, char* src) {
		if(src==NULL) return NULL;

	char* s = apr_pstrdup(p, src);
	char* cursor;
	for ( cursor = s; *cursor!='\0'; cursor++ ) {
		*cursor = toupper( (unsigned char)*cursor );
	}
	return s;
}

void ngx_http_openidc_addHeaderWithPrefix(ngx_http_openidc_request_t* r,
		char* headerPrefix, int addHeaderToHttpRequest,
		const char* header, const char* value) {
	if(headerPrefix!=NULL) {
		char* headerName = apr_psprintf(r->pool, "%s%s", headerPrefix, oauth_toupper(r->pool, (char*)header));
		apr_table_set(r->headers_in, headerName, value);
		if(addHeaderToHttpRequest) {
			ngx_http_openidc_setHeader(r->httpRequest, headerName, value);
		}
	}
}

void ngx_http_openidc_processState(ngx_http_openidc_request_t* r) {
	uri_components *url = &r->parsed_uri;
	char tmp[OAUTH_IDTOKEN_MAX_SIZE];

	// set session state
	if(url_get_param(url->query,(char*)"session_state", tmp,OAUTH_IDTOKEN_MAX_SIZE)>0){
		char* session_state = apr_pstrdup(r->pool,tmp);
		if(session_state!=NULL) {
			char* cookieDrop=cookie_cookieTemplateByName(r->pool, "session_state", session_state, NULL, -1, FALSE);
			if(cookieDrop!=NULL){
				apr_table_add(r->headers_out, "Set-Cookie", cookieDrop);
			}
		}
	}
}

static ngx_inline ngx_uint_t
ngx_http_openidc_hash_str(u_char *src, size_t n)
{
    ngx_uint_t  key;

    key = 0;

    while (n--) {
        key = ngx_hash(key, *src);
        src++;
    }

    return key;
}

#define ngx_http_openidc_hash_literal(s)                                        \
    ngx_http_openidc_hash_str((u_char *) s, sizeof(s) - 1)


static ngx_int_t
ngx_http_openidc_set_content_headers(ngx_http_request_t *r, off_t contentLength, ngx_str_t contentType)
{
    ngx_table_elt_t                 *h, *header;
    u_char                          *p;
    ngx_list_part_t                 *part;
    ngx_http_request_t              *pr;
    ngx_uint_t                       i;

    r->headers_in.content_length_n = contentLength;

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                sizeof(ngx_table_elt_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    // set content length
    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = ngx_http_openidc_content_length_header_key;
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    r->headers_in.content_length = h;

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    h->value.data = p;

    h->value.len = ngx_sprintf(h->value.data, "%O", contentLength) - h->value.data;

    h->hash = ngx_http_openidc_hash_literal("content-length");

    // set content-type
    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = ngx_http_openidc_content_type_header_key;
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->value = contentType;
    h->hash = ngx_http_openidc_hash_literal("content-type");
    r->headers_in.content_type = h;

    return NGX_OK;
}

int ngx_http_openidc_processRequest(ngx_http_openidc_request_t* r, config_core* 	configCore,
		oidc_config* oauthConfig, int addHeaderToHttpRequest, char* headerPrefix){

	if(oauthConfig==NULL||oauthConfig->oidcProvider==NULL) return NGX_DECLINED;

	if(oauthConfig->oidcProvider->issuer!=NULL) {
		apr_hash_set(r->variableHash,"issuer", APR_HASH_KEY_STRING, apr_pstrdup(r->pool, oauthConfig->oidcProvider->issuer));
	}
	if(oauthConfig->oidcProvider->authorizationEndpoint!=NULL) {
		apr_hash_set(r->variableHash,"authorization_endpoint", APR_HASH_KEY_STRING, apr_pstrdup(r->pool, oauthConfig->oidcProvider->authorizationEndpoint));
	}

    ngx_log_error(NGX_LOG_DEBUG, r->httpRequest->connection->log, 0, "oauth_processRequest");

	uri_components *url = &r->parsed_uri;
	char tmp[OAUTH_IDTOKEN_MAX_SIZE];
	int oidcSessionFound = FALSE;
	oauth_jwt_claim* claimObj = NULL;
	char* error = NULL;

	char* id_token=NULL;
	char* authHeader = (char*)apr_table_get(r->headers_in, "Authorization");
	if(authHeader==NULL) {
		if(url_get_param(url->query,(char*)"id_token",tmp,OAUTH_IDTOKEN_MAX_SIZE)>0){
			id_token = apr_pstrdup(r->pool,tmp);
		}
	}else{
		char* start = strstr(authHeader, "Bearer ");
		if(start!=NULL) {
			id_token = url_decode2(r->pool, start + 7);
		}
	}

	if(id_token!=NULL) {
		oauth_jwt* jwt = oauthutil_parseAndValidateIDToken(r->pool, id_token, oauth_getSignatureValidationKey, oauthConfig, &error);
		if(jwt==NULL||jwt->claim==NULL) {
			ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
			ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_parsing_failed");
			if(error!=NULL) { apr_table_add(r->headers_out, "X-OIDC-ERROR", error); }
			return NGX_DECLINED;
		}

		// check expiry
		if(oauthConfig->oidcSession->age>0) {
			jwt->claim->expiry = jwt->claim->issuedAt + (oauthConfig->oidcSession->age*86400);
		}

		if(configCore->cipherConfig!=NULL&&configCore->cipherConfig->crypto_passphrase!=NULL) {
			const char* serializedClaim = oauthutil_serializeJWTClaimNoEncoding(r->pool, jwt->claim);

			char* crypted = "";
			int status = cu_encryptAndBase64urlEncode(r->pool, configCore->cipherConfig, &crypted, (unsigned char *) serializedClaim, &error);
			if(status>0){
				char* cookieDrop=cookie_cookieTemplate(r->pool, oauthConfig->oidcSession, crypted, NULL);
				if(cookieDrop!=NULL){
					apr_table_add(r->headers_out, "Set-Cookie", cookieDrop);
				}
			}else{
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_parsing_failed");
				apr_table_add(r->headers_out, "X-OIDC-ERROR", "oidc_claim_invalid");
				return NGX_DECLINED;
			}
		}

		claimObj = jwt->claim;

		// set session state
		ngx_http_openidc_processState(r);
	}


	if(claimObj==NULL&&configCore->cipherConfig!=NULL&&configCore->cipherConfig->crypto_passphrase!=NULL) { // check for cookie
		char* oidc_session = cookie_getCookie(r->pool, r->headers_in, oauthConfig->oidcSession);
		if(oidc_session!=NULL) {
			char* decrypted = "";
			int status = cu_base64urlDecodeAndDecrypt(r->pool, configCore->cipherConfig, &decrypted, oidc_session, &error);
			if(status>0){
				claimObj = oauthutil_deserializeJWTClaimNoDecoding(r->pool, decrypted);
			}else{
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_session_expired");
				// delete current cookie
				cookie_deleteCookie(r->pool, r->headers_in, oauthConfig->oidcSession, NULL);
				return NGX_DECLINED;
			}
			oidcSessionFound = TRUE;
		}
	}

	if(claimObj!=NULL) {
		if(claimObj->expiry>apr_time_sec(apr_time_now())) {
			ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "success");

		// set headers
			if(claimObj->issuer!=NULL) {
				// validate issuer
				if(oauthConfig->oidcProvider->issuer!=NULL&&(strcmp(claimObj->issuer,oauthConfig->oidcProvider->issuer)!=0)) {
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_issuer_mismatch");
					apr_table_add(r->headers_out, "X-OIDC-ERROR", "oidc_issuer_mismatch");
					return NGX_DECLINED;
				}
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_ISSUER_HEADER, claimObj->issuer);
			}
			if(claimObj->subject!=NULL) {
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_SUBJECT_HEADER, claimObj->subject);
			}
			if(claimObj->audience!=NULL) {
				ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_AUDIENCE_HEADER, claimObj->audience);
			}
			if(claimObj->roles!=NULL) {
				char* rolesCsv = cu_serializeCsvFromStringArray(r->pool, claimObj->roles);
				if(rolesCsv!=NULL) {
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_ROLES_HEADER, rolesCsv);
				}
			}
			if(claimObj->options!=NULL) {
				//validate nonce
				char* oidcNonce = apr_hash_get(claimObj->options,"nonce", APR_HASH_KEY_STRING);
				char* rpSessionID = apr_table_get(r->headers_in, OIDC_RP_SESSIONID);
				if(oidcNonce!=NULL&&rpSessionID!=NULL&&(strcmp(oidcNonce,rpSessionID)!=0)) {
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_nonce_mismatch");
					apr_table_add(r->headers_out, "X-OIDC-ERROR", "oidc_nonce_mismatch");
					return NGX_DECLINED;
				}

				apr_hash_index_t *hi;
				char* name=NULL,*value=NULL;
				for (hi = apr_hash_first(r->pool, claimObj->options); hi; hi = apr_hash_next(hi)) {
					apr_hash_this(hi,(const void**)&name, NULL, (void**)&value);
					ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, name, value);
				}
			}
		}else{
			ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_STATUS_HEADER, "failure");
			ngx_http_openidc_addHeaderWithPrefix(r, headerPrefix, addHeaderToHttpRequest, OIDC_DESC_HEADER, "oidc_claim_expired");
			if(oidcSessionFound==TRUE) {
				cookie_deleteCookie(r->pool, r->headers_in, oauthConfig->oidcSession,NULL);
			}
		}
	}

	return NGX_DECLINED;
}

static ngx_int_t ngx_http_openidc_checkForAccess(ngx_http_request_t *httpRequest) {
    char* hostname=NULL;
    pool* p;
    
    // care about only primary request
    if (httpRequest != httpRequest->main) return NGX_DECLINED;
    
    ngx_http_openidc_srv_conf_t* conf =(ngx_http_openidc_srv_conf_t*) ngx_http_get_module_srv_conf(httpRequest, ngx_http_openidc_module);
    
	if(conf==NULL||conf->config==NULL||conf->config->configCore==NULL||conf->config->oidcConfig==NULL) return NGX_DECLINED;
	
    // create a request pool.
	if(apr_pool_create(&p, mainPool)!=APR_SUCCESS){
		return NGX_DECLINED;
	}
    
	//sync config core
	if(cfg_syncSelf(p,conf->config->configCore)>0){
		ngx_http_openidc_postRefreshBind(p,conf->config);
	}

	//set method type
	ngx_http_openidc_deleteHeader(httpRequest, (u_char *)"X-REQUEST-METHOD");
	char* method = apr_pstrndup(p, (char*)httpRequest->method_name.data, httpRequest->method_name.len);
	ngx_http_openidc_setHeader(httpRequest, "X-REQUEST-METHOD", method);

	//set scheme
	int isHttps = FALSE;
#if (NGX_SSL)
	if (httpRequest->connection->ssl&&httpRequest->connection->ssl->connection) {
		isHttps = TRUE;
	}
#endif
	ngx_http_openidc_deleteHeader(httpRequest, (u_char *)"X-REQUEST-SCHEME");
	ngx_http_openidc_setHeader(httpRequest, "X-REQUEST-SCHEME", (isHttps) ? "https" : "http");

	// create the request.
	ngx_http_openidc_request_t* r = ngx_http_openidc_createRequest(p);
	r->httpRequest = httpRequest;

	//set url
	char* uri = apr_pstrndup(r->pool, (char*)httpRequest->unparsed_uri.data, httpRequest->unparsed_uri.len);
	r->unparsed_uri = apr_pstrdup(r->pool, uri);
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    apr_uri_parse(r->pool, uri, &r->parsed_uri);
    r->uri = r->parsed_uri.path ? r->parsed_uri.path : apr_pstrdup(r->pool, "/");
    
	// set headers_in
	ngx_http_openidc_setHeadersIn(httpRequest, r, conf->config->configCore->oidcHeaderPrefix);

	 //set hostname
	ngx_table_elt_t* host = httpRequest->headers_in.host;
	if (host!=NULL) {
		hostname = apr_pstrndup(r->pool, (char*)host->value.data, host->value.len);
	}else{
		hostname = (char*)apr_table_get(r->headers_in, "Host");
	}
	r->hostname = hostname;
	 
	//client-ip
	char* xff = (char*)apr_table_get(r->headers_in, "X-Forwarded-For");
	if(xff==NULL) {
		struct sockaddr_in *sin = (struct sockaddr_in *) httpRequest->connection->sockaddr;
		if(sin!=NULL) {
			r->connection_remote_ip = apr_pstrdup(r->pool, inet_ntoa(sin->sin_addr));
		}else{
			r->connection_remote_ip = apr_pstrdup(r->pool, "127.0.0.1");
		}
	}else{
		char* second=NULL;
		char* srccpy = apr_pstrdup(r->pool, xff);
		r->connection_remote_ip = apr_strtok(srccpy, ",", &second);
	}

    // run preAuth
	int retCode = ngx_http_openidc_preAuthorize(r, conf->config);
	if(retCode!=NGX_DECLINED) {
		apr_pool_destroy(p);
		return retCode;
	}

	// generate unique sessionID;
	// TODO: needs to be replace with ACS session
	char* rpSessionID = cookie_getCookie(p, r->headers_in, conf->config->oidcConfig->rpSession);
	if(rpSessionID==NULL) {
		rpSessionID = cu_generateGuid(r->pool);
		char* cookieDrop = cookie_cookieTemplate(r->pool, conf->config->oidcConfig->rpSession, rpSessionID, NULL);
		if(cookieDrop!=NULL){
			apr_table_add(r->headers_out, "Set-Cookie", cookieDrop);
		}
	}
	apr_table_set(r->headers_in, OIDC_RP_SESSIONID, rpSessionID);
	ngx_http_openidc_setHeader(r->httpRequest, OIDC_RP_SESSIONID, rpSessionID);

	// Authorization phase
	retCode = ngx_http_openidc_processRequest(r, conf->config->configCore, conf->config->oidcConfig, TRUE, conf->config->configCore->oidcHeaderPrefix);
	if(retCode!=NGX_DECLINED) {
		apr_table_do(ngx_http_openidc_addResponseHeaderCallback, httpRequest, r->headers_out, NULL);
		retCode = ngx_http_openidc_sendResponse(r);
		apr_pool_destroy(p);
		return retCode;
	}

	// post Auth phase
	path_mapping* pathmapping=am_getPathMapping_PostAuth(r->pool,conf->config->oidcConfig,r->unparsed_uri,r->connection_remote_ip,r->headers_in,NULL);
	if(pathmapping!=NULL){
		page_action* action=am_getMatchingPageAction(r->pool,pathmapping->pmactions,r->unparsed_uri,r->connection_remote_ip,r->headers_in,NULL);
		char* originUri=ngx_http_openidc_getFullRequestUrl(r);
		retCode = ngx_http_openidc_execPageAction(r, action,originUri);
		apr_table_do(ngx_http_openidc_addResponseHeaderCallback, httpRequest, r->headers_out, NULL);
		if(action!=NULL&&action->handler_internal!=NULL) {
			r->handler = apr_pstrdup(r->pool, action->handler_internal);
			int i;
			int numHandlers=sizeof(ngx_http_oidcHandlers)/sizeof(ngx_http_openidc_handler_t);
			for(i=0; i<numHandlers; i++){
				retCode=(*ngx_http_oidcHandlers[i].handlerFunc)(r, conf->config);
				if(retCode!=NGX_DECLINED) {
					retCode = ngx_http_openidc_sendResponse(r);
					break;
				}
			}
		}
	}
	
	// release memory
	apr_pool_destroy(p);
	
	return retCode;
}

static ngx_int_t ngx_http_openidc_handler(ngx_http_request_t * httpRequest) {
	char* hostname;
    pool* p;
    int retCode = NGX_DECLINED;
    
	ngx_http_openidc_srv_conf_t* conf =(ngx_http_openidc_srv_conf_t*) ngx_http_get_module_srv_conf(httpRequest, ngx_http_openidc_module);
	
	if(conf==NULL||conf->config==NULL||conf->config->configCore==NULL) return NGX_DECLINED;
		
    // create a request pool.
	if(apr_pool_create(&p, mainPool)!=APR_SUCCESS){
		return NGX_DECLINED;
	}
    
	// create the request.
	ngx_http_openidc_request_t* r = ngx_http_openidc_createRequest(p);
	r->httpRequest = httpRequest;
	
	//set url
	char* uri = apr_pstrndup(r->pool, (char*)httpRequest->unparsed_uri.data, httpRequest->unparsed_uri.len);
	r->unparsed_uri = apr_pstrdup(r->pool, uri);
	
	if(rc_matchByStrings(p, "^/oidc", uri)!=0) {
		// release memory
		apr_pool_destroy(p);
		return NGX_DECLINED;
	}
	
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    apr_uri_parse(r->pool, uri, &r->parsed_uri);
    r->uri = r->parsed_uri.path ? r->parsed_uri.path : apr_pstrdup(r->pool, "/");
    
	// set headers_in
	ngx_http_openidc_setHeadersIn(httpRequest, r, conf->config->configCore->oidcHeaderPrefix);

	 //set hostname
	ngx_table_elt_t* host = httpRequest->headers_in.host;
	if (host!=NULL) {
		hostname = apr_pstrndup(r->pool, (char*)host->value.data, host->value.len);
	}else{
		hostname = (char*)apr_table_get(r->headers_in, "Host");
	}
	r->hostname = hostname;
	 
	//client-ip
	struct sockaddr_in *sin = (struct sockaddr_in *) httpRequest->connection->sockaddr;
	if(sin!=NULL) {
		r->connection_remote_ip = apr_pstrdup(r->pool, inet_ntoa(sin->sin_addr));
	}else{
		r->connection_remote_ip = apr_pstrdup(r->pool, "127.0.0.1");
	}
	
	//sync config core
	if(cfg_syncSelf(r->pool,conf->config->configCore)>0){
		ngx_http_openidc_postRefreshBind(r->pool,conf->config);
	}
	
	path_mapping* pathmapping=am_getPathMapping_PostAuth(r->pool,conf->config->oidcConfig,r->unparsed_uri,r->connection_remote_ip,r->headers_in,NULL);
	if(pathmapping!=NULL){
		page_action* action=am_getMatchingPageAction(r->pool,pathmapping->pmactions,r->unparsed_uri,r->connection_remote_ip,r->headers_in,NULL);
		if(action!=NULL&&action->handler_internal!=NULL) {
			r->handler = apr_pstrdup(r->pool, action->handler_internal);
			int i;
			int numHandlers=sizeof(ngx_http_oidcHandlers)/sizeof(ngx_http_openidc_handler_t);
			for(i=0; i<numHandlers; i++){
				int retCode=(*ngx_http_oidcHandlers[i].handlerFunc)(r, conf->config);
				if(retCode!=NGX_DECLINED) {
					retCode = ngx_http_openidc_sendResponse(r);
					break;
				}
			}
			
		}
	}
	
	// release memory
	apr_pool_destroy(p);
	
	return retCode;
	
}

int oidc_index(ngx_http_openidc_request_t *r, Config* config) {

	if (strcmp(r->handler, "oidc_index")) {
		return NGX_DECLINED;
	}

	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>Tool Index</TITLE></HEAD>\n");
	ngx_http_openidc_rputs("<BODY>\n",r);
	ngx_http_openidc_rprintf(r,"<LEFT><H1>Tool Index</H1></LEFT><BR>\n");
	ngx_http_openidc_rputs("<TABLE align='left'><tr>",r);
	ngx_http_openidc_rputs("<td valign='top'><table><tr><td><b><font color='green'>Handlers</font></b></td></tr>",r);
	ngx_http_openidc_rputs("<TR><TD><a href='/oidc/version'>Version Details</a></TD></TR>",r);
    ngx_http_openidc_rputs("<TR><TD><a href='/oidc/config-status'>ConfigCore Details</a></TD></TR>",r);
	ngx_http_openidc_rputs("<TR><TD><a href='/oidc/rewrite-pageactions'>PostAuth Actions Details</a></TD></TR>",r);
	ngx_http_openidc_rputs("<TR><TD><a href='/oidc/rewrite-actionmappings'>OIDC Config Details</a></TD></TR>",r);
    ngx_http_openidc_rputs("<TR><TD><a href='/oidc/headers'>Show Headers</a></TD></TR>",r);
	ngx_http_openidc_rputs("</table>",r);
	ngx_http_openidc_rputs("</td>",r);

	ngx_http_openidc_rputs("</table>",r);

	ngx_http_openidc_rputs("</td>",r);

	ngx_http_openidc_rputs("</tr></TABLE>",r);

	ngx_http_openidc_rputs("</BODY></HTML>",r);
    return NGX_OK;
}

int oidc_version(ngx_http_openidc_request_t *r, Config* config){
	
    if (strcmp(r->handler, "oidc_version")) {
            return NGX_DECLINED;
    }

	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>Version Info</TITLE></HEAD>\n");
	ngx_http_openidc_rputs("<BODY>\n",r);
	
	ngx_http_openidc_rputs("<TABLE>",r);
	ngx_http_openidc_rprintf(r,"<TR><TD colspan='2'><b>Version Info</b></td></tr>\n");
	ngx_http_openidc_rprintf1(r,"<TR><TD>Module: </td><td>%s</td></tr>\n",VERSION_ID);
	ngx_http_openidc_rprintf1(r,"<TR><TD>LibCurl: </td><td>%s</td></tr>\n",hc_getInfo(r->pool));
	ngx_http_openidc_rprintf1(r,"<TR><TD>RewriteCore: </td><td>PCRE/%s</td></tr>\n",rc_getInfo(r->pool));
	ngx_http_openidc_rprintf1(r,"<TR><TD>Server: </td><td>%s</td></tr>\n",NGINX_VER);
	ngx_http_openidc_rputs("</TABLE>",r);
	return NGX_OK;
}

/*
 * Rewrite Handlers
 */
static void rewrite_pageaction_display(ngx_http_openidc_request_t *r,page_action* pa,match_list* ml){
	if(pa!=NULL){
		ngx_http_openidc_rprintf1(r,"<td>%s",pa->id);
		if(ml&&ml->name!=NULL){
			ngx_http_openidc_rprintf1(r,"<br/>MatchList:%s",ml->name);
		}
		ngx_http_openidc_rprintf(r,"</td>");
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",pa->handler_internal);
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",SAFESTR(pa->uri));
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",SAFESTR(pa->regex));
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",pa->isForward!=1?"false":"true");
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",pa->isPermanent!=1?"false":"true");
		ngx_http_openidc_rprintf1(r,"<td>%s</td>",pa->description);
	}else{
		ngx_http_openidc_rputs("<td colspan='5'>&nbsp</td>",r);
	}
}

static const char* authzoidc_getActionStr(header_actions action) {
	if (action==header_add)
		return "add";
    else if (action==header_set)
		return "set";
    else if (action==header_append)
		return "append";
    else if (action==header_merge)
		return "merge";
    else if (action==header_unset)
		return "unset";
    else if (action==header_echo)
		return "echo";
    else if (action==header_edit)
		return "edit";
	return "null";
}

void authzoidc_displayActionHeader(ngx_http_openidc_request_t*r, action_header* hdr) {
	
	if(hdr==NULL) return;
	
	if(hdr->action==header_unset) {
		ngx_http_openidc_rprintf2(r,"<tr><td>&nbsp;&nbsp;</td><td><li>%s&nbsp;{%s}</td></tr>",
				authzoidc_getActionStr(hdr->action),hdr->name);
	}
	else {
		if(hdr->regex!=NULL) {
			ngx_http_openidc_rprintf4(r,"<tr><td>&nbsp;&nbsp;</td><td><li>%s&nbsp;{%s:%s}&nbsp;regex:%s</td></tr>",
					authzoidc_getActionStr(hdr->action),hdr->name, hdr->value, hdr->regex);
		}else{
			ngx_http_openidc_rprintf3(r,"<tr><td>&nbsp;&nbsp;</td><td><li>%s&nbsp;{%s:%s}</td></tr>",
					authzoidc_getActionStr(hdr->action),hdr->name, hdr->value);
		}
	}
}

static void rewrite_pageaction_displayAll(ngx_http_openidc_request_t *r,page_action* pa){
	int i=0;
	array_header* arry=NULL;
	if(pa!=NULL){
		ngx_http_openidc_rputs("<table>",r);
		ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td><strong>%s</strong>",SAFESTR(pa->id));
		if(pa->isDebug==1){ngx_http_openidc_rprintf(r," <font color='maroon'>DEBUG</font> ");}
		if(pa->description!=NULL){ngx_http_openidc_rprintf1(r," [%s]</td></tr>",pa->description);}else{ngx_http_openidc_rprintf(r,"</td></tr>");}
		
		if(pa->regex!=NULL){ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>Regex: %s</td></tr>",SAFESTR(pa->regex));}
		if(pa->handler_internal!=NULL){ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>Handler: %s</td></tr>",pa->handler_internal);}
		if(pa->response!=NULL){ngx_http_openidc_rprintf3(r,"<tr><td>&nbsp;</td><td>Response[%d:%s]: <xmp>%s</xmp></td></tr>",pa->response->code, pa->response->contentType, pa->response->body);}
		if(pa->uri!=NULL) { ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>Uri:%s</td></tr>",pa->uri); }
		ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>isForward: %s</td></tr>",pa->isForward!=1?"false":"true");
		ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>isPermanent: %s</td></tr>",pa->isPermanent!=1?"false":"true");
		if(pa->advancedTemplate==TRUE){
			ngx_http_openidc_rprintf(r,"<tr><td>&nbsp;</td><td>advancedTemplate: true</td></tr>");
		}
		if(pa->requestHeaders!=NULL){
			ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>RequestHeaders[%d]</td></tr>",pa->requestHeaders->nelts);
			for(i=0; i<pa->requestHeaders->nelts; i++){
				action_header* hdr = (action_header*)cu_getElement(pa->requestHeaders, i);
				authzoidc_displayActionHeader(r,hdr);
			}
		}			
		if(pa->responseHeaders!=NULL){
			ngx_http_openidc_rprintf1(r,"<tr><td>&nbsp;</td><td>ResponseHeaders[%d]</td></tr>",pa->responseHeaders->nelts);
			for(i=0; i<pa->responseHeaders->nelts; i++){
				action_header* hdr = (action_header*)cu_getElement(pa->responseHeaders, i);
				authzoidc_displayActionHeader(r,hdr);
			}
		}
		ngx_http_openidc_rputs("</table>",r);
	}else{
		ngx_http_openidc_rputs("NULL",r);
	}
	
}
	
static void authzoidc_errorMessage(ngx_http_openidc_request_t *r){
	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>Rewrite Page Actions - NULL</TITLE></HEAD>\n");
	ngx_http_openidc_rprintf(r,"<body>ActionMappings are NULL</body>\n");
	ngx_http_openidc_rprintf(r,"</html>\n");
}

static void authzoidc_pathmappings_displayMatchList(ngx_http_openidc_request_t *r,array_header* arr){
	int i=0;
	match_list* list=NULL;
	if(arr!=NULL&&arr->nelts>0){
		ngx_http_openidc_rprintf(r,"<br/>MatchLists:");
		for(i=0;i<arr->nelts;i++){
			list=(match_list*)cu_getElement(arr,i);
			if(i!=0){ngx_http_openidc_rprintf(r,",");}
			ngx_http_openidc_rprintf1(r,"%s",list->name);
		}
	}
}

static void authzoidc_pathmappings_display(ngx_http_openidc_request_t *r,array_header* arr,char* name){
	int x=0;
	path_mapping* pmap=NULL;
	int i=0;
	pathmapping_action* pmaction=NULL;
	
	ngx_http_openidc_rprintf2(r,"<br><b><font color='blue'>Path Mappings - %s (%d)</font></b>",name,arr->nelts);
	if(name,arr->nelts>0){
		ngx_http_openidc_rputs("<TABLE border='1'>",r);
		ngx_http_openidc_rputs("<tr><td>Path Regex</td><td>ID</td><td>handler</td><td>uri</td><td>Regex</td><td>isForward</td><td>isPermanent</td><td>Description</td></tr>",r);
		for(x=0;x<arr->nelts;x++){
			pmap=(path_mapping*)cu_getElement(arr,x);
			if(pmap->pmactions!=NULL&&pmap->pmactions->nelts>0){
				for(i=0;i<pmap->pmactions->nelts;i++){
					if ( pmap->ignoreCase==TRUE ) {
						ngx_http_openidc_rprintf1(r,"<tr><td><b>%s</b><br>IgnoreCase=true</br>",pmap->pathRegex);
					}else{
						ngx_http_openidc_rprintf1(r,"<tr><td><b>%s</b>",pmap->pathRegex);
					}
					authzoidc_pathmappings_displayMatchList(r,pmap->matchLists);
					ngx_http_openidc_rprintf(r,"</td>");
					pmaction=(pathmapping_action*)cu_getElement(pmap->pmactions,i);
					rewrite_pageaction_display(r,pmaction->action,pmaction->matchList);
					ngx_http_openidc_rputs("</td></tr>",r);
				}
			}
		}
		ngx_http_openidc_rputs("</TABLE>",r);
	}
}


static void authzoidc_pathmapping_display_withnote(ngx_http_openidc_request_t *r,path_mapping* pathMap,page_action*action,char* note, apr_time_t startTime){
		
		if(pathMap!=NULL){
				ngx_http_openidc_rprintf2(r,"<tr><td>%s</td><td>%d us</td>",note, apr_time_now()-startTime);
				ngx_http_openidc_rprintf1(r,"<td><font color='darkgreen'>%s</font>",pathMap->pathRegex);
				authzoidc_pathmappings_displayMatchList(r,pathMap->matchLists);
				ngx_http_openidc_rprintf(r,"</td>");
				rewrite_pageaction_display(r,action,NULL);
		}else{
				ngx_http_openidc_rprintf1(r,"<tr><td>%s</td><td>(Default)</td>",note);
				rewrite_pageaction_display(r,NULL,NULL);
		}
		ngx_http_openidc_rputs("</tr>",r);
}


static int authzoidc_printTableCallBack(void *rec, const char *key, const char *value){
		ngx_http_openidc_request_t *r=(ngx_http_openidc_request_t*)rec;
		if(strstr(key,"Cookie")==0) {
			ngx_http_openidc_rprintf2(r,"<tr><td>%s = </td><td>%s</td></tr>\r\n",key,value);
		}
		return 1;
	}
static void authzoidc_printTable(ngx_http_openidc_request_t *r,apr_table_t* table){
	if(table!=NULL&&!apr_is_empty_table(table)){
		ngx_http_openidc_rputs("<TABLE><tr><td valign='top'>Table Headers:</td><td><table>",r);
		apr_table_do(authzoidc_printTableCallBack,(void*)r,table,NULL);
		ngx_http_openidc_rputs("</table></td></tr></TABLE>",r);
	}
}
	
static int authzoidc_pathMatchSection(ngx_http_openidc_request_t *r, Config* config){
	oidc_config* actm=config->oidcConfig;
	uri_components *url = &r->parsed_uri;
	path_mapping* pathMap=NULL;
	char* pathParam=NULL;
	char* overlayParam=NULL;
	char* headersInParam=NULL;
	char* ipParam=NULL;
	apr_table_t* headers_in=NULL, *r_headers=NULL;
	page_action*action=NULL;
	apr_time_t startTime;
	
	if(actm==NULL){
		authzoidc_errorMessage(r);
		return NGX_OK;
	}
	pathParam=url_getParam(r->pool,url->query,"pathParam");
	
	headersInParam=url_getParam(r->pool,url->query,"headersInParam");
		
	ipParam=url_getParam(r->pool,url->query,"ipParam");
	if(ipParam==NULL){
		ipParam=r->connection_remote_ip;
	}
	
	ngx_http_openidc_rputs("Check Path Mapping:<br>",r);
	ngx_http_openidc_rputs("<form><table>",r);
	ngx_http_openidc_rprintf1(r,"<tr><td>IP:</td><td><input type='text' name='ipParam' size='30'  value='%s'></td></tr>\r\n",SAFESTRBLANK(ipParam));
	ngx_http_openidc_rprintf1(r,"<tr><td>Path:</td><td><input type='text' name='pathParam' size='80' value='%s'/></td></tr>",SAFESTRBLANK(pathParam));
	ngx_http_openidc_rprintf1(r,"<tr><td valign='top'>HeadersIn:</td><td><textarea name='headersInParam' cols='60' rows='4'>%s</textarea></td></tr>\r\n",SAFESTRBLANK(headersInParam));
	ngx_http_openidc_rputs("<tr><td colspan='2'><INPUT type='submit' value='Match' /></td></tr>\n",r);
	ngx_http_openidc_rputs("</table></form>\n",r);
	if(pathParam!=NULL){
		headers_in=cu_parseNvpTableFromCsv(r->pool,"\n",":",headersInParam);
		if(overlayParam!=NULL){
			if(headers_in!=NULL){
				//headers_in=apr_table_overlay(r->pool,headers_in,r->headers_in);
				//apr_table_compress(headers_in,APR_OVERLAP_TABLES_SET);
				r_headers=apr_table_copy(r->pool,r->headers_in);
				apr_table_overlap(r_headers,headers_in,APR_OVERLAP_TABLES_SET);
				headers_in=r_headers;
			}else{
				headers_in=r->headers_in;
			}
		}
		
		ngx_http_openidc_rputs("<TABLE border='1' cellspacing='0' bordercolor='blue'>",r);

		//postauth
		startTime=apr_time_now();
		pathMap=am_getPathMapping_PostAuth(r->pool,actm,pathParam,ipParam,headers_in,NULL);
		if(pathMap!=NULL){
			action=am_getMatchingPageAction(r->pool,pathMap->pmactions,r->unparsed_uri,ipParam,headers_in,NULL);
			if(action!=NULL){authzoidc_pathmapping_display_withnote(r,pathMap,action,"PostAuth",startTime);}
		}
					
		ngx_http_openidc_rputs("</TABLE>",r);
		authzoidc_printTable(r,headers_in);
	}
	
	
	return 1;
}
static char* authzoidc_getMatchIpDetails(pool*p,match_ip*ip){
	char* ipDetails;
	
	if(ip==NULL||ip->ip==NULL)	return NULL;
	
	ipDetails=apr_pstrdup(p,ip->ip);
	if(ip->negate==TRUE){ipDetails=apr_pstrcat(p,ipDetails,"\tnegate=true",NULL);}
	if(ip->isRegex==FALSE){ipDetails=apr_pstrcat(p,ipDetails,"\tisregex=false",NULL);};
	
	return ipDetails;
}
static char* authzoidc_getMatchPathDetails(pool*p,match_path*path){
	char* pathDetails;
	
	if(path==NULL||path->path==NULL)	return NULL;
	
	pathDetails=apr_pstrdup(p,path->path);
	if(path->negate==TRUE){pathDetails=apr_pstrcat(p,pathDetails,"\tnegate=true",NULL);}
	
	return pathDetails;
}	
static char* authzoidc_getHeaderDetails(pool*p,match_list_header*hdr){
	char* hdrDetails;
	
	if(hdr==NULL)	return NULL;
	
	hdrDetails=apr_pstrcat(p,hdr->name,"=",hdr->value,NULL);
	if(hdr->delimAnd){hdrDetails=apr_pstrcat(p,hdrDetails,"\tdelimAnd=\"",hdr->delimAnd,"\"",NULL);}
	if(hdr->negate==TRUE){hdrDetails=apr_pstrcat(p,hdrDetails,"\tnegate=true",NULL);}
	if(hdr->isRegex==FALSE){hdrDetails=apr_pstrcat(p,hdrDetails,"\tisregex=false",NULL);};
	
	return hdrDetails;
} 

static char* authzoidc_timeString(pool*p, time_t t, const char* def){
	if(t<=0) return (char*)def;
	char tmp[40]={0};
	ctime_r(&t, tmp);
	return apr_psprintf(p, "%s[%d]", tmp, t);
}

static char* authzoidc_getEventColor(pool*p, match_event*e){
	char*color=NULL;
	time_t currentTime = time(NULL);
	
	if(( e->start < currentTime ) 
					&& ( currentTime < ( (e->end>0) ? e->end : TIME_MAX) )){
		color =  apr_pstrdup(p, "green");
	}else if(e->start > currentTime){//Future events
		color =  apr_pstrdup(p, "yellow");
	}else{//Past events
		color =  apr_pstrdup(p, "red");
	}
	return color;
}

static void authzoidc_printMatchListMatch(ngx_http_openidc_request_t *r,match_list_match* match){
	int i=0;
	//match_list_match_nvp* nvp=NULL;
	match_list_header* hdr=NULL;
	match_list_env* env=NULL;
	if(match==NULL) return;
	ngx_http_openidc_rprintf(r,"<table><tr><td valign='top'><li/></td>");
	if(match->cascade==FALSE){
		ngx_http_openidc_rprintf(r,"<td valign='top'>Cascade:</td><td align='left'>false</td></tr><tr><td>&nbsp;</td>");
	}		
	if(match->host!=NULL){
		ngx_http_openidc_rprintf1(r,"<td valign='top'>Host:</td><td align='left'>%s</td></tr><tr><td>&nbsp;</td>", match->host);
	}		
	if(match->ip!=NULL){
		ngx_http_openidc_rprintf1(r,"<td valign='top'>IP:</td><td align='left'>%s</td></tr><tr><td>&nbsp;</td>",
				authzoidc_getMatchIpDetails(r->pool,match->ip));
	}
	if(match->path!=NULL){
		ngx_http_openidc_rprintf1(r,"<td valign='top'>Path:</td><td align='left'>%s</td></tr><tr><td>&nbsp;</td>",
				authzoidc_getMatchPathDetails(r->pool,match->path));
	}
	if(match->event!=NULL){
		ngx_http_openidc_rprintf3(r, "<td valign='top'>Event:</td><td valign='top'><font color='%s'><li/></td><td><table><tr><td><i/>Start:</td><td>%s</td><td><i/>End:</td><td>%s</td></font></tr></tr></table></td></tr><td>&nbsp;</td>",
				authzoidc_getEventColor(r->pool, match->event),
				authzoidc_timeString(r->pool, match->event->start, "Unknown"),
				authzoidc_timeString(r->pool, match->event->end, "Never") );
	}		
	if(match->headerList!=NULL&&match->headerList->nelts>0){
		ngx_http_openidc_rprintf(r,"<td valign='top'>Headers:</td><td>");
		ngx_http_openidc_rprintf(r,"<table>");
		for(i=0;i<match->headerList->nelts;i++){
			hdr=(match_list_header*)cu_getElement(match->headerList,i);
			ngx_http_openidc_rprintf1(r,"<tr><td valign='top'>%s</td></tr>",authzoidc_getHeaderDetails(r->pool,hdr));
		}
		ngx_http_openidc_rprintf(r,"</table>");
		ngx_http_openidc_rprintf(r,"</td></tr>");
	}
	ngx_http_openidc_rprintf(r,"</table>");
}
static void authzoidc_matchLists(ngx_http_openidc_request_t *r,oidc_config* actm){
	match_list* list=NULL;
	shapr_hash_index_t * hi=NULL;
	match_list_match* match=NULL;
	int i=0;
	void* val=NULL;
	unsigned int cnt=0;
	
	ngx_http_openidc_rputs("<TABLE>",r);
	cnt=shapr_hash_count(actm->match_lists);
	ngx_http_openidc_rprintf1(r,"<tr><td colspan='4'><font color='maroon'><strong>MatchLists [%d]:</strong></font></td></tr>",cnt);
	if(cnt>0){
		for (hi = shapr_hash_first(r->pool,actm->match_lists); hi; hi = shapr_hash_next(hi)) {
	           shapr_hash_this(hi, NULL, NULL, &val);
	     	   if(val!=NULL){
	     		  list=(match_list*)val;
	     		  ngx_http_openidc_rprintf1(r,"<tr><td width='15'>&nbsp;</td><td>&nbsp;</td><td valign='top'>%s</td><td>",list->name);
	     		  
	     		  ngx_http_openidc_rputs("<table>",r);
	     		  for(i=0;i<list->list->nelts;i++){
	     			  match=(match_list_match*)cu_getElement(list->list,i);
	     			  ngx_http_openidc_rputs("<tr><td>",r);
	     			 authzoidc_printMatchListMatch(r,match);
	     			  ngx_http_openidc_rputs("</td></tr>",r);
	     		  }
	     		  ngx_http_openidc_rputs("</table>",r);
	     		  ngx_http_openidc_rputs("</td></tr>",r);
	     	   }
		}
	}
	ngx_http_openidc_rputs("</TABLE>",r);
}

static void authzoidc_displayTemplateEngine(ngx_http_openidc_request_t *r,template_engine* tengine){
	shapr_hash_index_t* hi;
	template_eng_livetemplate* lt=NULL;
	void* val, * key;
	
	ngx_http_openidc_rputs("<TABLE>",r);
	ngx_http_openidc_rprintf1(r,"<tr><td>Template Engine:</td><td>%s</td></tr>",tengine!=NULL?"VALID":"FAIL");
	if(tengine!=NULL){
		
		ngx_http_openidc_rputs("<tr><td colspan='2'><TABLE>",r);
		ngx_http_openidc_rprintf(r,"<tr><td>Token:</td><td> Description</td><td> Test Result</td></tr>");
		for(hi=shapr_hash_first(r->pool,tengine->templateHash);hi;hi=shapr_hash_next(hi)){
			shapr_hash_this(hi,(const void**)&key,NULL,&val);
			lt=(template_eng_livetemplate*)val;
			if(lt->engineTemplate!=NULL){
				ngx_http_openidc_rprintf2(r,"<tr><td><li/> %s:</td><td> %s</td></tr>",lt->engineTemplate->id,lt->engineTemplate->description);
			}else{
				ngx_http_openidc_rprintf(r,"<tr><td colspan='3'><li/> NULL Template</td></tr>");
			}
		}
		ngx_http_openidc_rputs("<TABLE></td></tr>",r);
		
	}
	ngx_http_openidc_rputs("<TABLE>",r);
}

  int oidc_rewrite_actionmappings(ngx_http_openidc_request_t *r, Config *config) {

	  if (strcmp(r->handler, "oidc_rewrite_actionmappings")) {
                return NGX_DECLINED;
        }

	oidc_config* actm=config->oidcConfig;
	int i=0;
	pathmapping_action* pmaction=NULL;
	array_header* arr;
	
	if(actm==NULL){
		authzoidc_errorMessage(r);
		return NGX_OK;
	}
	
	
	//begin logic
	
	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>OIDC Config</TITLE></HEAD>\n");
	ngx_http_openidc_rputs("<BODY>\n",r);

	if(actm->oidcProvider!=NULL) {
		ngx_http_openidc_rprintf(r,"<TABLE><tr><td><font color='black'><strong>OIDCProvider</strong></font></td></tr>");
		ngx_http_openidc_rprintf1(r,"<tr><td>MetadataUrl</td><td>%s</td></tr>",actm->oidcProvider->metadataUrl);
		ngx_http_openidc_rprintf1(r,"<tr><td>Issuer</td><td>%s</td></tr>",actm->oidcProvider->issuer);
		ngx_http_openidc_rprintf1(r,"<tr><td>AuthorizationEndpoint</td><td>%s</td></tr>",actm->oidcProvider->authorizationEndpoint);
		ngx_http_openidc_rprintf1(r,"<tr><td>JwksUri</td><td>%s</td></tr></TABLE>",actm->oidcProvider->jwksUri);
	}

	ngx_http_openidc_rprintf(r,"<TABLE><tr><td><font color='black'><strong>Session</strong></font></td></tr>");
	ngx_http_openidc_rprintf2(r,"<tr><td>RelyingParty</td><td>name=%s</td><td>expiry(days)=%d</td></tr>",actm->rpSession->name, actm->rpSession->age);
	ngx_http_openidc_rprintf2(r,"<tr><td>OIDCProvider</td><td>name=%s</td><td>expiry(days)=%d</td></tr></TABLE>",actm->oidcSession->name, actm->oidcSession->age);

	authzoidc_displayTemplateEngine(r,actm->templateEngine);
	
	//do path matching
	authzoidc_pathMatchSection(r,config);
	
	authzoidc_pathmappings_display(r,actm->path_mappings->postauth,"PostAuth");
	
	//display matchlists
	authzoidc_matchLists(r,actm);

//	authzoidc_printTable(r,r->headers_in);

	ngx_http_openidc_rputs("</BODY>",r);
	ngx_http_openidc_rputs("</HTML>\n",r);

	return NGX_OK;
}
 
  int oidc_rewrite_pageactions(ngx_http_openidc_request_t *r, Config *config) {
	if (strcmp(r->handler, "oidc_rewrite_pageactions")) {
                return NGX_DECLINED;
        }

	shapr_hash_index_t * hi=NULL;
	void* val=NULL;
	const void *key=NULL;
	page_action* paction=NULL;
	oidc_config* actm=config->oidcConfig;
	uri_components *url = &r->parsed_uri;
	
	
	if(actm==NULL){
		authzoidc_errorMessage(r);
		return NGX_OK;
	}
	
	//begin logic
	
	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rputs("<HEAD><TITLE>Rewrite Page Actions</TITLE></HEAD>\n",r);
	ngx_http_openidc_rputs("<BODY>\n",r);
	
	ngx_http_openidc_rputs("<TABLE border='0'>",r);
	ngx_http_openidc_rputs("<tr><td>&nbsp</td><td>",r);
	for (hi = shapr_hash_first(r->pool,actm->page_actions); hi; hi = shapr_hash_next(hi)) {
           shapr_hash_this(hi, &key, NULL, &val);
     	   if(key!=NULL&&val!=NULL){
     	   		paction=(page_action*)val;
     	   		rewrite_pageaction_displayAll(r,paction);
     	   		ngx_http_openidc_rputs("<br>",r);
//	        		ngx_http_openidc_rprintf1(r,"<td>%s</td>",key);
        	}
	}
	ngx_http_openidc_rputs("</td></tr></TABLE>",r);
	
	ngx_http_openidc_rputs("</BODY>",r);
	ngx_http_openidc_rputs("</HTML>\n",r);
	return NGX_OK;

}
 
 int oidc_rewrite_match(ngx_http_openidc_request_t *r, Config *config) {
	if (strcmp(r->handler, "oidc_rewrite_match")) {
                return NGX_DECLINED;
        }

	char* regexParam=NULL, *valueParam=NULL, *templateParam=NULL;
	uri_components *url = &r->parsed_uri;
	char* rcoreRet=NULL;
	
	apr_time_t startTime;
	
	//rewrite vars to support templating
	array_header* pmatches=NULL;
	char* elt=NULL;
	int i=0;
	
	//begin logic
	
	regexParam=url_getParam(r->pool,url->query,"regexParam");
	valueParam=url_getParam(r->pool,url->query,"valueParam");
	templateParam=url_getParam(r->pool,url->query,"templateParam");
	//display
	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rputs("<HEAD><TITLE>Rewrite Match Testing</TITLE></HEAD>\n",r);
	ngx_http_openidc_rputs("<BODY>\n",r);
	ngx_http_openidc_rputs("<TABLE>",r);
	ngx_http_openidc_rprintf1(r,"<tr><td>RewriteCore: </td><td>%s</td></tr>",rc_getInfo(r->pool));
	ngx_http_openidc_rputs("<form>",r);
	ngx_http_openidc_rputs("<tr><td>Value(Url): </td><td>",r);
	ngx_http_openidc_rprintf1(r,"<input type='text' value='%s' name='valueParam' size='180'/>\r\n",
			(valueParam!=NULL) ? cu_nonHtmlToHtmlChar(r->pool, valueParam) : SAFESTRBLANK(valueParam));
	ngx_http_openidc_rputs("</td></tr>\r\n",r);
	ngx_http_openidc_rputs("<tr><td>Regex: </td><td>",r);
	ngx_http_openidc_rprintf1(r,"<input type='text' value='%s' name='regexParam' size='180'/>\r\n",
			(regexParam!=NULL) ? cu_nonHtmlToHtmlChar(r->pool, regexParam) : SAFESTRBLANK(regexParam));
	ngx_http_openidc_rputs("</td></tr>\r\n",r);
	ngx_http_openidc_rputs("<tr><td>Template: </td><td>",r);
	ngx_http_openidc_rprintf1(r,"<input type='text' value='%s' name='templateParam' size='180'/>\r\n",SAFESTRBLANK(templateParam));
	ngx_http_openidc_rputs("</td></tr>\r\n",r);
	ngx_http_openidc_rputs("<tr><td></td><td><INPUT type='submit' value='go!' /></td></tr>\r\n</form>",r);
	
	if(regexParam!=NULL&&valueParam!=NULL){
		startTime=apr_time_now();
		
		rcoreRet=rc_matchByStringsPatternReturnDetails(r->pool,regexParam,valueParam,&pmatches);
		startTime=apr_time_now()-startTime;
		ngx_http_openidc_rprintf1(r,"<tr><td>Result: (%ld usecs)</td><td>",startTime);
		if(rcoreRet!=NULL){
			ngx_http_openidc_rprintf1(r,"FAILURE: %s</td></tr>",rcoreRet);
		}else{
			ngx_http_openidc_rputs("SUCCESS</td></tr>",r);
		}
		if(templateParam!=NULL){
			ngx_http_openidc_rprintf1(r,"<tr><td></strong>Template Engine String</strong>:</td><td>%s</td></tr>",SAFESTR(te_templateString(r->pool,config->oidcConfig->templateEngine,templateParam,pmatches)));
		}
		
		if(pmatches!=NULL){
			
			ngx_http_openidc_rprintf1(r,"<tr><td colspan='2'></strong>Found Matches (%d)</strong></td></tr>",pmatches->nelts);
			
			if(pmatches->nelts>0){
				ngx_http_openidc_rprintf(r,"<tr><td>&nbsp</td><td><table>");
				for(i=0;i<pmatches->nelts;i++){
					elt=cu_getElement(pmatches,i);
					ngx_http_openidc_rprintf2(r,"<tr><td><strong>$%d: </strong></td><td>%s</td></tr>",i,
							cu_nonHtmlToHtmlChar(r->pool, elt));
				}
				ngx_http_openidc_rprintf(r,"</table></td></tr>");
			}
		}
	}
	
	ngx_http_openidc_rputs("</TABLE>",r);
	ngx_http_openidc_rputs("</BODY>",r);
	ngx_http_openidc_rputs("</HTML>\n",r);
	return NGX_OK;
}

 static int oidc_section_SharedHeap(const char* title, ngx_http_openidc_request_t *r,shared_heap* sheap){
 	shared_page* pg;
 	segment_header* seg;
 	int x;
 	if(sheap!=NULL){
 		ngx_http_openidc_rprintf1(r,"\n<TR><TD colspan='2'><b>Shared Heap Page - %s </b></TD></TR>",title);
 		ngx_http_openidc_rprintf1(r,"<TR><TD>TimeStamp: </TD><TD>%s</TD></TR>",ctime(&(sheap->timestamp)));
 		ngx_http_openidc_rprintf1(r,"<TR><TD>FlipCount: </TD><TD>%d</TD></TR>",sheap->flipcount);
 		ngx_http_openidc_rprintf1(r,"<TR><TD>Cursor byte: </TD><TD>%d</TD></TR>",shdata_cursor(sheap));
 		
 		ngx_http_openidc_rprintf1(r,"<TR><TD>Local Seg: </TD><TD>%d</TD></TR>",sheap->local_segment);
 		ngx_http_openidc_rprintf1(r,"<TR><TD>apr_shm_t* valid: </TD><TD>%s</TD></TR>",sheap->shm_main==NULL?"FALSE":"TRUE");
 		ngx_http_openidc_rprintf(r,"<TR><TD colspan='2'>&nbsp;<TD></TR>");
 		if(sheap->page!=NULL){
 			pg=sheap->page;
 			ngx_http_openidc_rprintf(r,"\n<TR><TD colspan='2'><b>------Shared Portion--|</b></TD></TR>");
 			ngx_http_openidc_rprintf(r,"\n<TR><TD colspan='2'>");
 			
 			ngx_http_openidc_rprintf(r,"<TABLE>");
 			ngx_http_openidc_rprintf1(r,"\t<TR><TD width='5'>&nbsp;</TD><TD>TimeStamp: </TD><TD>%s</TD></TR>",ctime(&(pg->timestamp)));
 			ngx_http_openidc_rprintf1(r,"\t<TR><TD width='5'>&nbsp;</TD><TD>SegmentSize: </TD><TD>%d</TD></TR>",pg->segmentsize);
 			ngx_http_openidc_rprintf1(r,"\t<TR><TD width='5'>&nbsp;</TD><TD>FlipCount: </TD><TD>%d</TD></TR>",pg->flipcount);
 			ngx_http_openidc_rprintf1(r,"\t<TR><TD width='5'>&nbsp;</TD><TD>ItemsMax: </TD><TD>%d</TD></TR>",pg->itemmax);
 			ngx_http_openidc_rprintf2(r,"\t<TR><TD width='5'>&nbsp;</TD><TD>Front/Back Segment: <TD>%d/%d</TD></TR>",pg->frontsegment,pg->backsegment);
 			seg=&(sheap->page->segments[sheap->page->frontsegment]);
 			
 			ngx_http_openidc_rprintf1(r,"\t<TR><TD width='5'>&nbsp;</TD><TD colspan='2'>* Items(%d)---</TD></TR>",seg->itemcount);
 			ngx_http_openidc_rprintf(r,"\t<TR><TD width='5'>&nbsp;</TD><TD colspan='2'>");
 				if(seg->itemcount>0){
 				ngx_http_openidc_rprintf(r,"\t\t<TABLE>");
 				for(x=0;x<seg->itemcount;x++){	
 				ngx_http_openidc_rprintf1(r,"<TR><TD>ID: </TD><TD>%s</TD></TR>",seg->items[x].ITEMID);
 				ngx_http_openidc_rprintf1(r,"<TR><TD>INFO: </TD><TD>%s</TD></TR>",seg->items[x].INFO);
 				ngx_http_openidc_rprintf1(r,"<TR><TD>Offset: </TD><TD>%d</TD>",seg->items[x].offset);
 				ngx_http_openidc_rprintf1(r,"<TR><TD>Size: </TD><TD>%d</TD>",seg->items[x].size);
 				}
 				ngx_http_openidc_rprintf(r,"\t\t</TABLE>");
 				}
 			ngx_http_openidc_rprintf(r,"\t</TD></TR>");
 			ngx_http_openidc_rprintf(r,"\t</TABLE>");
 			ngx_http_openidc_rprintf(r,"\n</TD></TR>");
 			
 		}
 	}else{
 		ngx_http_openidc_rprintf1(r,"\n<TR><TD colspan='2'>Shared Heap - %s - NULL</TD></TR>",title);
 	}
 	return 1;
 }

 int oidc_showHeaders(ngx_http_openidc_request_t *r, Config* config){

	oidc_config* actm=config->oidcConfig;

	if(actm==NULL){
		authzoidc_errorMessage(r);
		return NGX_OK;
	}


	//begin logic

	ngx_http_openidc_rputs("<HTML>\n",r);
	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>Headers</TITLE></HEAD>\n");
	ngx_http_openidc_rputs("<BODY>\n",r);

	authzoidc_printTable(r,r->headers_in);

	ngx_http_openidc_rputs("</BODY>",r);
	ngx_http_openidc_rputs("</HTML>\n",r);

	return NGX_OK;
}

 int oidc_headers(ngx_http_openidc_request_t *r, Config *config) {
 	if (strcmp(r->handler, "oidc_headers")) {
                 return NGX_DECLINED;
         }
 	return oidc_showHeaders(r,config);
 }
 
int oidc_config_core_status(ngx_http_openidc_request_t *r, Config *config) {

 	if (strcmp(r->handler, "oidc_config_core_status")) {
 		return NGX_DECLINED;
 	}

 	ngx_http_openidc_rputs("<HTML>\n",r);
 	ngx_http_openidc_rprintf(r,"<HEAD><TITLE>Config Core Status</TITLE></HEAD>\n");
 	ngx_http_openidc_rputs("<BODY>\n",r);
 	ngx_http_openidc_rputs("<TABLE width='100%'>",r);
 	ngx_http_openidc_rprintf1(r,"<tr><td>HomeDir: </td><td>%s</td></tr>",SAFESTR(config->homeDir));
 	ngx_http_openidc_rprintf1(r,"<tr><td>ConfigFile: </td><td>%s</td></tr>",SAFESTR(config->oidcConfigFile));
 	ngx_http_openidc_rprintf1(r,"<tr><td>LogFile: </td><td>%s</td></tr>",SAFESTR(config->logFile));
 	if(config->configCore!=NULL){
 		int i=0;
 		config_core* core=config->configCore;

 		ngx_http_openidc_rprintf(r,"<tr><td colspan='2' align='left'><strong>Globals</strong></td></tr>");
 		ngx_http_openidc_rprintf1(r,"<tr><td>HomeDirectory: </td><td>%s</td></tr>",SAFESTR(core->globals->homeDir));
 		ngx_http_openidc_rprintf1(r,"<tr><td>PassPhrase: </td><td>%s</td></tr>", core->passPhrase ? "non null" : "NULL");

 		ngx_http_openidc_rprintf1(r,"<tr><td>DisableProcessRecovery: <td>%s</td></tr>",BOOLTOSTR(core->disableProcessRecovery));
 		ngx_http_openidc_rprintf1(r,"<tr><td>OIDCHeaderPrefix: <td>%s</td></tr>",SAFESTR(core->oidcHeaderPrefix));

 		ngx_http_openidc_rprintf(r,"<tr><td colspan='2' align='left'><strong>AutoRefresh settings</strong></td></tr>");
 		ngx_http_openidc_rprintf1(r,"<tr><td>RefreshWaitSeconds: <td>%d</td></tr>",core->refreshWaitSeconds);
 		
 		if(core->globals->resourceService!=NULL){
 	 		ngx_http_openidc_rprintf(r,"<tr><td colspan='2' align='left'><strong>Resource Service</strong></td></tr>");
 			ngx_http_openidc_rprintf1(r,"<tr><td>Url: </td><td>%s</td></tr>",SAFESTR(core->globals->resourceService->uri));
 			ngx_http_openidc_rprintf1(r,"<tr><td>Timeout: </td><td>%d</td></tr>",core->globals->resourceService->timeoutSeconds);
 		}

 		oidc_section_SharedHeap("Config Core",r,config->configCore->sheap);
 	}else{
 		ngx_http_openidc_rprintf(r,"<tr><td>ConfigCore: </td><td>NULL</td></tr>");
 	}
 	ngx_http_openidc_rputs("</TABLE>",r);
 	ngx_http_openidc_rputs("</BODY></HTML>",r);
 	return NGX_OK;
 }
 
static ngx_int_t ngx_http_openidc_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_http_request_t          *pr;
    ngx_http_openidc_subrequest_ctx_t* ctx;

    pr = r->parent;

    ctx = ngx_http_get_module_ctx(pr, ngx_http_openidc_module);
    ctx->done = 1;
    ctx->status = r->headers_out.status;
    ctx->responseType = r->headers_out.content_type;
    ctx->subrequest = r;

    char tmp[8192]={0};
    memcpy(tmp, r->upstream->buffer.pos, r->upstream->buffer.last - r->upstream->buffer.pos);
    printf("%s:%d body=[%s]\n", __FILE__, __LINE__, tmp);

    size_t bodylen = r->upstream->buffer.last - r->upstream->buffer.pos;
    ctx->responseBody.data = ngx_palloc(r->pool, bodylen);
    ctx->responseBody.len  = bodylen;
    memcpy(ctx->responseBody.data, r->upstream->buffer.pos, bodylen);

    return NGX_OK;
}

static int ngx_http_openidc_set_id_token_header(ngx_http_request_t*	httpRequest){

	// process module context
	ngx_http_openidc_subrequest_ctx_t* ctx = ngx_http_get_module_ctx(httpRequest, ngx_http_openidc_module);
    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == NGX_HTTP_FORBIDDEN||ctx->status == NGX_HTTP_BAD_REQUEST) {
            return ctx->status;
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
        		ngx_http_request_t* sr = ctx->subrequest;

        		ngx_table_elt_t* h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            if (h) {
            		ngx_table_elt_t   *ho = ngx_list_push(&httpRequest->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = *h;

                httpRequest->headers_out.www_authenticate = ho;
            }

            return ctx->status;
        }

        if (ctx->status >= NGX_HTTP_OK && ctx->status < NGX_HTTP_SPECIAL_RESPONSE) {
        		pool* p = NULL;
			if(apr_pool_create(&p, mainPool)!=APR_SUCCESS){
				return NGX_DECLINED;
			}
			// read id_token
            char* responseBody = apr_pstrndup(p, ctx->responseBody.data, ctx->responseBody.len);
            if(responseBody!=NULL) {
				Value* json = JSON_Parse(p, responseBody);
				if(json!=NULL) {
					Value* idTokenObj = JSON_GetObjectItem(json, "id_token");
					if(idTokenObj!=NULL) {
						char* id_token = JSON_GetStringFromStringItem(idTokenObj);
						if(id_token!=NULL) {
							ngx_http_openidc_setHeader(httpRequest, "Authorization", apr_pstrcat(p, "Bearer ", id_token, NULL));
						}
					}
				}
            }
            apr_pool_destroy(p);

        }

        ngx_log_error(NGX_LOG_ERR, httpRequest->connection->log, 0, "auth request unexpected status: %d", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_openidc_set_subrequest_post_body(ngx_http_request_t * r, ngx_http_request_t * sr, const char* requestBody, ngx_str_t  contentType) {
	if(requestBody==NULL) return NGX_ERROR;

	ngx_http_request_body_t     *rb = NULL;
	ngx_buf_t                   *b;

	// set method
	sr->method = NGX_HTTP_POST;
	sr->method_name.data = (u_char *)"POST ";
	sr->method_name.len = 4;

	// create request body
	rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
	if (rb == NULL) {
		return NGX_ERROR;
	}

	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return NGX_ERROR;
	}

	b->temporary = 1;
	/* b->memory = 1; */
	b->start = b->pos = requestBody;
	b->end = b->last = requestBody + strlen(requestBody);

	rb->bufs = ngx_alloc_chain_link(r->pool);
	if (rb->bufs == NULL) {
		return NGX_ERROR;
	}

	rb->bufs->buf = b;
	rb->bufs->next = NULL;

	rb->buf = b;

	/* set the 'Content-type' header */
	ngx_int_t rc = ngx_http_openidc_set_content_headers(sr, rb->buf ? ngx_buf_size(rb->buf) : 0, contentType);
	if (rc != NGX_OK) {
		return NGX_ERROR;
	}

	sr->request_body = rb;

	return NGX_OK;
}

static ngx_int_t ngx_http_openidc_preAuthorize(ngx_http_openidc_request_t* r, Config* config) {
    ngx_http_post_subrequest_t *psr;
    ngx_http_request_t *sr;
    ngx_int_t rc;
	uri_components *url = &r->parsed_uri;
	char tmp[OAUTH_IDTOKEN_MAX_SIZE];
	oidc_config* 	oidcConfig = config->oidcConfig;

    ngx_http_openidc_subrequest_ctx_t* ctx = ngx_http_get_module_ctx(r->httpRequest, ngx_http_openidc_module);
    if (ctx != NULL) {

        ngx_chain_t out;
        int bodylen;
        ngx_buf_t* b;
        ngx_int_t ret;

        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == NGX_HTTP_FORBIDDEN||ctx->status == NGX_HTTP_BAD_REQUEST) {
            return ctx->status;
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
        		ngx_http_request_t* sr = ctx->subrequest;

        		ngx_table_elt_t* h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            if (h) {
            		ngx_table_elt_t   *ho = ngx_list_push(&r->httpRequest->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = *h;

                r->httpRequest->headers_out.www_authenticate = ho;
            }

            return ctx->status;
        }

        if (ctx->status == NGX_HTTP_OK){
            // print
            char tmp[8192]={0};
            memcpy(tmp, ctx->responseBody.data, ctx->responseBody.len);
            printf("%s:%d body=[%s]\n", __FILE__, __LINE__, tmp);

            char* responseBody = apr_pstrndup(r->pool, ctx->responseBody.data, ctx->responseBody.len);
            if(responseBody!=NULL) {
				Value* json = JSON_Parse(r->pool, responseBody);
				if(json!=NULL) {
					Value* idTokenObj = JSON_GetObjectItem(json, "id_token");
					if(idTokenObj!=NULL) {
						char* id_token = JSON_GetStringFromStringItem(idTokenObj);
						if(id_token!=NULL) {
							apr_table_set(r->headers_in, "Authorization", apr_pstrcat(r->pool, "Bearer ", id_token, NULL));
						}
					}
				}
            }
        }

        // default
        ngx_http_finalize_request(r->httpRequest, ctx->status);
        return ctx->status;

    }else if(url_get_param(url->query, (char*)"code", tmp, OAUTH_IDTOKEN_MAX_SIZE)>0){
		char* authorizationCode = apr_pstrdup(r->pool, tmp);
		relying_party* relyingParty = am_getRelyingPartyByHost(r->pool, oidcConfig->relyingPartyHash, r->hostname);
		if(relyingParty!=NULL) {
			char* requestBody = apr_pstrcat(r->pool,
					"grant_type=authorization_code",
					"&code=", authorizationCode,
					"&client_id=", relyingParty->clientID,
					"&client_secret=", relyingParty->clientSecret,
					NULL);

			ngx_int_t rc = ngx_http_openidc_create_post_subrequest(r->httpRequest, oidc_authz_subrequest_type_oauth_token, requestBody);
			if (rc != NGX_OK) {
				return rc;
			}
			return NGX_AGAIN;
		}
    }

    	 return NGX_DECLINED;
}

static ngx_int_t
ngx_http_openidc_create_post_subrequest(ngx_http_request_t * r, oidc_authz_sub_request_type sub_request_type, const char* requestBody) {
    ngx_http_post_subrequest_t *psr;
    ngx_http_request_t *sr;
    ngx_int_t rc;

    // create new context
    ngx_http_openidc_subrequest_ctx_t* ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_openidc_subrequest_ctx_t));
	if (ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_openidc_module);

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_openidc_subrequest_post_handler;
    psr->data = ctx;

    ngx_str_t subrequest_uri = sub_request_type.uri;
    printf("subrequest_uri=%s\n", (const char*)subrequest_uri.data);
    printf("requestBody=%s\n", requestBody);

    rc = ngx_http_subrequest(r, &subrequest_uri, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* allocate a buffer for your response body */
    rc = ngx_http_openidc_set_subrequest_post_body(r, sr, requestBody, sub_request_type.content_type);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}

