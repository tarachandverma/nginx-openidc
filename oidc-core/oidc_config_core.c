#include "oidc_config.h"
#include "oidc_config_core.h"
#define PARAM_CONFIG_XML	"config-xml"
#define PARAM_IS_REFRESH	"initialized"
	char* amc_initialize(pool* p,shared_heap* sheap,cbs_globals* globals,cfg_service_descriptor* svcdesc,void** userdata){
		char* result=NULL;
		char* error=NULL;
		char* isRefresh=NULL;
		char* configFile=NULL;
		char* param_configFile=(char*)apr_hash_get(svcdesc->params,PARAM_CONFIG_XML,APR_HASH_KEY_STRING);
		if(param_configFile==NULL){
			return apr_pstrcat(p,"Missing service param:",PARAM_CONFIG_XML,NULL);
		}
		//get Latest Action Mappings Resource
		configFile=cbs_getRemoteResourcePath(p,globals,param_configFile,&error);
		if(configFile==NULL){
			configFile=cbs_getLocalResourcePath(p, globals,param_configFile,NULL);
		}
		
		result=am_build(p,sheap,(apr_hash_get(svcdesc->params,PARAM_IS_REFRESH,APR_HASH_KEY_STRING)!=NULL),globals,configFile);
		if(result!=NULL){
			return apr_pstrcat(p,"Problem loading action-mappings : ",result,NULL);
		}		
		
		apr_hash_set(svcdesc->params,PARAM_IS_REFRESH,APR_HASH_KEY_STRING,apr_pstrdup(p,"TRUE"));
		return NULL;
	}
	char* amc_refresh(pool* p,shared_heap* sheap,cbs_globals* globals,cfg_service_descriptor* svcdesc,void** userdata){
			return amc_initialize(p,sheap,globals,svcdesc,userdata);
	}
	
	char* amc_postRefresh(pool* p,shared_heap* sheap, cfg_globals* globals,cfg_service_descriptor* svcdesc,void** userdata){
		oidc_config* mappings=NULL;
		mappings=am_fetchFromSheap(sheap);
		if(mappings==NULL){
			return apr_pstrdup(p,"Action Mappings unable to be retrieved from sheap");
		}
		*userdata=mappings;
		return NULL;	
	}


