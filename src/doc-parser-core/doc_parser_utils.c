#include <doc_parser_utils.h>
#include "apr_lib.h"
#include "apr_strings.h"

	char* docp_getRemoteResourcePath(pool* p, char* resource,
			cbs_service_descriptor *rs,char* homeDir,char**details){
		char* ret=NULL,*reqUri;
		apr_pool_t* tp;
		char* fileName=NULL;
		if(resource==NULL) return NULL;
		
		if(rs!=NULL){
			//setup filepool
			if(apr_pool_create(&tp,p)!=APR_SUCCESS){
				if(details!=NULL){
					*details=apr_pstrdup(p,"Failure to create subpool");
				}
				return NULL;
			}		
			//load remote path.
			reqUri=apr_pstrcat(p,rs->uri,"/",resource,NULL);
			fileName=(char*)apr_filepath_name_get(resource);
			ret=cb_writeRemoteResourceToDisk(p,homeDir,reqUri,fileName,rs->timeoutSeconds,rs->userColonPass,tp,details,NULL);		
			apr_pool_destroy(tp);
		}
		return ret;
	}
	char* docp_getRemoteResourcePathEx(pool* p, char* resourceUri, char* homeDir,char**details){
		char* ret=NULL,*reqUri;
		apr_pool_t* tp;
		char* fileName=NULL;
		apr_finfo_t finfo;
		apr_status_t rv;
		char* localPath=NULL;

		if(resourceUri!=NULL){
			//setup filepool
			if(apr_pool_create(&tp,p)!=APR_SUCCESS){
				if(details!=NULL){
					*details=apr_pstrdup(p,"Failure to create subpool");
				}
				return NULL;
			}		
			//load remote path.
			fileName=(char*)apr_filepath_name_get(resourceUri);
			ret=cb_writeRemoteResourceToDisk(p, homeDir,resourceUri,fileName,20,NULL,tp,details,NULL);
			apr_pool_destroy(tp);
		}
		return ret;
	}	
	char* docp_getLocalResourcePath(pool*p,char* resource,char* homeDir){
		if(resource==NULL){return NULL;}
		return apr_pstrcat(p,homeDir,"/",apr_filepath_name_get(resource),NULL);
	}
