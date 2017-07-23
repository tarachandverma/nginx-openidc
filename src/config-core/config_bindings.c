#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <config-core/config_bindings.h>
#include <common_utils.h>
#include <http-utils/http_client.h>
#include "rewrite_core.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <dlfcn.h>

#define URI_POSTFIX_AUTOREFRESH_TIMESTAMP		"autoRefreshTimestamp.txt"

	cfg_service_descriptor* cb_newServiceDescriptorObj(pool* p){
		cfg_service_descriptor* ret=(cfg_service_descriptor*)apr_palloc(p,sizeof(cfg_service_descriptor));
		ret->id=NULL;
		ret->name=NULL;
		ret->uri=NULL;
		ret->userColonPass=NULL;
		ret->timeoutSeconds=2;
		ret->params=apr_hash_make(p);
		return ret;
	}

	cfg_globals* cb_newGlobalsObj(pool* p){
		cfg_globals* ret=(cfg_globals*)apr_pcalloc(p,sizeof(cfg_globals));
		ret->homeDir=NULL;
		ret->logsDir=NULL;
		ret->resourceService=NULL;
		return ret;
	}
	char* cb_initGlobals(pool* p,cfg_globals* globals){
		if(globals->logsDir!=NULL){
			apr_dir_make_recursive(globals->logsDir,APR_OS_DEFAULT,p);
		}
		return NULL;
	}
	
	char* cb_writeRemoteResourceToDisk(pool* p, char* homeDir, char* reqUri, char* resource, long timeoutSeconds, char* userColonPass,
			apr_pool_t* tp, char**details, int* responseCode){
		char* ret=NULL, * bakFile=NULL,* filename=NULL;
		http_util_result* result=NULL;
		//file vars
		apr_file_t* file=NULL;
		apr_status_t status;
		apr_size_t file_written;
		char* errorMsg=NULL;
	
		if(resource==NULL) return NULL;
		
		result=hc_get_verbose(p,reqUri,timeoutSeconds,userColonPass,NULL,&errorMsg);

		if(hc_is200_OK(result)){
				//write file to filesystem
			if(result->size>0){
				bakFile=apr_pstrcat(tp,homeDir,"/",resource,".part",NULL);
				status=apr_file_open(&file,bakFile,APR_WRITE|APR_CREATE|APR_TRUNCATE,APR_OS_DEFAULT,tp);
				if(apr_file_write_full(file,result->data,result->size,&file_written)==APR_SUCCESS){
					filename=apr_pstrcat(p,homeDir,"/",resource,NULL);
					apr_file_close(file);
					if(apr_file_rename(bakFile,filename,tp)==APR_SUCCESS){
						ret=filename;
					}
				}else{				
					apr_file_close(file);
					if(details!=NULL){
						*details=apr_pstrcat(p,"Failure to write file:",SAFESTR(bakFile),NULL);
					}
				}
			}
		}else{
			if(details!=NULL){
				*details=apr_pstrcat(p,"Failure to write file (Response Code!=200): ",SAFESTR(resource),",",SAFESTR(errorMsg),NULL);
			}
			if(responseCode!=NULL&&result!=NULL){
				*responseCode=result->responseCode;
			}
		}
		
		return ret;
	}

	int cb_canAutoRefreshNow(pool* p, cfg_service_descriptor* resourceService, time_t lastRefreshTimestamp, time_t currentTimestamp, char* namespace,char**error){
		http_util_result* httpResult=NULL;
		char* endptr=NULL;
		char* reqQuery=NULL;
		long long value=-1;
		
		if(resourceService==NULL) return FALSE;
		
		reqQuery=apr_pstrcat(p,resourceService->uri,namespace,"/",URI_POSTFIX_AUTOREFRESH_TIMESTAMP,NULL);
		httpResult=hc_get_verbose2(p,reqQuery,resourceService->timeoutSeconds,5,resourceService->userColonPass,NULL,error);
		
		if(httpResult==NULL||httpResult->data==NULL||!hc_is200_OK(httpResult)) return FALSE;
		
		time_t autoRefreshTimestamp = cu_dateStringToSeconds(httpResult->data);
		
		if(autoRefreshTimestamp<0 || currentTimestamp<autoRefreshTimestamp) return FALSE;

		return TRUE;
	}
