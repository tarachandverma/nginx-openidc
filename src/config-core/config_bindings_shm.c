#include <apache_mappings.h>
#include <shm_data.h>
#include <shm_apr.h>
#include <common_utils.h>
#include <http-utils/http_client.h>
#include <config-core/config_bindings.h>
#include <config-core/config_bindings_shm.h>

#define SHEAP_ITEM_ID_CONFIG_CORE_GLOBALS "CONFIG_CORE_GLOBALS"

	shapr_hash_t* cbs_copyParamsOnSheap(pool*p, shared_heap*sheap, apr_hash_t*params){	
		apr_hash_index_t* hi=NULL;
		char* val, *key;
		char* shmVal, *shmKey;
		shapr_hash_t* ret= shapr_hash_make(sheap);
		for (hi = apr_hash_first(p, params); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi,(const void**)(&key),NULL,(void**)(&val));
			shmKey=shdata_32BitString_copy(sheap,key);
			shmVal=shdata_32BitString_copy(sheap,val);
			shapr_hash_set(sheap,ret,shmKey,APR_HASH_KEY_STRING,shmVal);
		}
		return ret;
	}
	
	cbs_service_descriptor* cbs_copyServiceDescripterOnSheap(pool*p, shared_heap* sheap,cfg_service_descriptor* sd){
		if(sd==NULL) return NULL;
		cbs_service_descriptor* ret=(cbs_service_descriptor*)shdata_shpcalloc(sheap,sizeof(cbs_service_descriptor));
		ret->id=shdata_32BitString_copy(sheap,sd->id);
		ret->name=shdata_32BitString_copy(sheap,sd->name);
		ret->uri=shdata_32BitString_copy(sheap,sd->uri);
		ret->userColonPass=shdata_32BitString_copy(sheap,sd->userColonPass);
		ret->timeoutSeconds=sd->timeoutSeconds;
		ret->params=cbs_copyParamsOnSheap(p, sheap,sd->params);
		return ret;
	}
	
	cbs_globals* cbs_copyGlobalsOnSheap(pool*p, shared_heap* sheap, cfg_globals* globals, int isRefresh){
		
		shdata_OpenItemTag(sheap,SHEAP_ITEM_ID_CONFIG_CORE_GLOBALS);
		
		cbs_globals* ret=(cbs_globals*)shdata_shpcalloc(sheap,sizeof(cbs_globals));
		ret->homeDir=shdata_32BitString_copy(sheap,globals->homeDir);
		ret->logsDir=shdata_32BitString_copy(sheap,globals->logsDir);
		ret->resourceService=cbs_copyServiceDescripterOnSheap(p,sheap,globals->resourceService);
		ret->isRefresh = isRefresh;
		shdata_CloseItemTagWithInfo(sheap,"Config Core Globals");
		return ret;
	}

	char* cbs_getRemoteResourcePath(pool* p, cbs_globals* globals,char* resource,char**details){
		char* ret=NULL,*reqUri;
		cbs_service_descriptor* rs=NULL;
		int responseCode=-1;
		pool* tp;
		apr_finfo_t finfo;
		apr_status_t rv;
		char* localPath=NULL;
		
		if(resource==NULL) return NULL;
		
		if(globals->resourceService!=NULL){
			rs=globals->resourceService;
			//setup filepool
			if(apr_pool_create(&tp,p)!=APR_SUCCESS){
				if(details!=NULL){
					*details=apr_pstrdup(p,"Failure to create subpool");
				}
				return NULL;
			}
			
			//try to load from local name space.
			reqUri=apr_pstrcat(p,rs->uri,"/",resource,NULL);
			ret=cb_writeRemoteResourceToDisk(p,globals->homeDir,reqUri,resource,rs->timeoutSeconds,rs->userColonPass,tp,details,&responseCode);
			
			apr_pool_destroy(tp);
		}
		
		return ret;
	}

	char* cbs_getLocalResourcePath(pool* p, cbs_globals* globals,char* resource,char**details){
		if(resource==NULL){return NULL;}
		return apr_pstrcat(p,globals->homeDir,"/",resource,NULL);
	}

	
	
