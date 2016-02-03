#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "xml_core.h"
#include "config_messaging_parsing.h"
#include "common_utils.h"
#include "oidc_version.h"
	
	typedef struct cfgm_parse_bundle{
		char* tmp;
		cfgm_wire_message* msg;
	}cfgm_parse_bundle;
		
		
	/**
	 * Begin Wire Message Code
	 */
	static cfgm_wire_header* cfgm_newWireHeaderBlank(pool* p){	
		cfgm_wire_header* ret=(cfgm_wire_header*)apr_palloc(p,sizeof(cfgm_wire_header));
		ret->nodeName=NULL;
		ret->componentId=NULL;
		ret->version=NULL;
		return ret;
	} 
	cfgm_wire_header* cfgm_newWireHeader(pool* p){
		int i;
		char buf[128];
		
		//for second ip get test		
		cfgm_wire_header* ret=cfgm_newWireHeaderBlank(p);
		if(gethostname(buf,128)==0){
			ret->nodeName=apr_pstrdup(p,buf);
		}
		ret->componentId=apr_pstrdup(p,MODULE_COMPONENT_ID);
		ret->version=apr_pstrdup(p,MODULE_VERSION_ID);

		return ret; 
	}
	cfgm_wire_message* cfgm_newWireMessage(pool* p,cfgm_wire_header* header){
		char buf[64];
		cfgm_wire_message* ret=(cfgm_wire_message*)apr_palloc(p,sizeof(cfgm_wire_message));
		ret->type=NULL;
		ret->header=header;
		ret->params=apr_hash_make(p);
				
		sprintf(buf,"%d",getpid());
		apr_hash_set(ret->params,"pid",APR_HASH_KEY_STRING,apr_pstrdup(p,buf));
		
		return ret;
	}
	cfgm_wire_message* cfgm_newWireMessageType(pool* p,const char* type,cfgm_wire_header* header){
		cfgm_wire_message* ret=cfgm_newWireMessage(p,header);
		ret->type=apr_pstrdup(p,type);
		return ret;
	}
	
	char* cfgm_serializeMessage(apr_pool_t* p, cfgm_wire_message* msg){
		apr_hash_index_t *hi;
		char* name=NULL,*value=NULL;
		char* ret=NULL;
		apr_pool_t* subp=NULL;
		

		if(msg==NULL) return NULL;
		if(apr_pool_create(&subp,p)!=APR_SUCCESS){
			return NULL;	
		}
		ret=apr_pstrcat(subp,"<message type=\"",msg->type,"\"",NULL);
		if(msg->header!=NULL){
			if(msg->header->nodeName!=NULL){
				ret=apr_pstrcat(subp,ret," node=\"",msg->header->nodeName,"\"",NULL);	
			}
			if(msg->header->componentId!=NULL){
				ret=apr_pstrcat(subp,ret," com=\"",msg->header->componentId,"\"",NULL);
			}
			if(msg->header->version!=NULL){
				ret=apr_pstrcat(subp,ret," ver=\"",msg->header->version,"\"",NULL);
			}
		}
		ret=apr_pstrcat(subp,ret,">\n",NULL);
		for (hi = apr_hash_first(subp, msg->params); hi; hi = apr_hash_next(hi)) {
        	apr_hash_this(hi,(const void**)&name, NULL, (void**)&value);
        	ret=apr_pstrcat(subp,ret,"\t<param name=\"",name,"\"><![CDATA[",value,"]]></param>\n",NULL);
        }
        
        //make last concat to non temporary memory pool
		ret=apr_pstrcat(p,ret,"</message>",NULL);
		//destroy temporary memeory pool
		apr_pool_destroy(subp);
		return ret;        		
	}
	
