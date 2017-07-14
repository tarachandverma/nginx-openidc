#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include "config_core.h"
#include "xml_core.h"
#include "common_utils.h"
#include "oidc_globals.h"
#include "config_bindings_shm.h"
#include "oidc_version.h"
#include "logging.h"

	config_core* configcore_newConfigCoreObj(pool* p){
		config_core* ret=(config_core*)apr_palloc(p,sizeof(config_core));
		ret->globals=cb_newGlobalsObj(p);
		ret->oidcConfigFile=apr_pstrdup(p,"oidc-config.xml");
		ret->service=cb_newServiceDescriptorObj(p);
		ret->service->id=apr_pstrdup(p,"OIDC-CONFIG");
		ret->service->name=apr_pstrdup(p,"oidcConfig");
		apr_hash_set(ret->service->params,"config-xml",APR_HASH_KEY_STRING,ret->oidcConfigFile);
		ret->sheapMapFile=apr_pstrdup(p, "/configcore.shm");
		ret->sheapPageSize=64000;
		ret->sheap=NULL;
		ret->serviceConfig=NULL;
		ret->passPhrase=NULL;
		ret->disableProcessRecovery=FALSE;
		ret->oidcHeaderPrefix=apr_pstrdup(p, "X-OIDC-");
		ret->refreshWaitSeconds=0;
		ret->cipherConfig = (oidc_cipher_cfg*)apr_palloc(p, sizeof(oidc_cipher_cfg));
		ret->cipherConfig->crypto_passphrase = NULL;
		ret->cipherConfig->decrypt_ctx=NULL;
		ret->cipherConfig->encrypt_ctx=NULL;
		ret->cipherConfig->p = p;
		return ret;		
	}
	
	typedef struct cfg_bundle{
		config_core* cc;
		void* userdata, *userdata2;
	}cfg_bundle;
	
	static int cfg_setCCAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		return 1;
	}
	static int cfg_setCCDisableProcessRecoveryBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		int len;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		
		bundle->cc->disableProcessRecovery=STRTOBOOL(body);
		return 1;
	}
	static int cfg_setCCHeaderPrefixBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		int len;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		
		bundle->cc->oidcHeaderPrefix=apr_pstrdup(p, body);
		return 1;
	}
	static int cfg_setCCRefreshWaitSecondsBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		int len;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		if(body!=NULL) {
			bundle->cc->refreshWaitSeconds=atol(body);
		}
		return 1;
	}	
	static int cfg_setCCPassPhraseBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		int len;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		
		bundle->cc->passPhrase=apr_pstrdup(p,body);
		if(bundle->cc->passPhrase) {
			bundle->cc->cipherConfig->crypto_passphrase=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int cfg_setCCOIDCConfigFileBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		int len;
		cfg_bundle* bundle=(cfg_bundle*)userdata;

		bundle->cc->oidcConfigFile=apr_pstrdup(p,body);
		if(bundle->cc->oidcConfigFile!=NULL){
			apr_hash_set(bundle->cc->service->params,"config-xml",APR_HASH_KEY_STRING,bundle->cc->oidcConfigFile);
		}
		return 1;
	}
	static int cfg_setCCSheapMapFileBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		bundle->cc->sheapMapFile=apr_pstrdup(p,body);
		return 1;
	}
	static int cfg_setCCSheapPageSizeBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		bundle->cc->sheapPageSize=atoi(body);
		return 1;
	}
	
	static int cfg_setResourceServiceAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		cfg_service_descriptor* svc=NULL;
		
		svc=bundle->cc->globals->resourceService=cb_newServiceDescriptorObj(p);
		svc->id=apr_pstrdup(p,"RESOURCE_SERVICE");
		svc->name=apr_pstrdup(p,"RESOURCE_SERVICE");
  		return 1;
	}
	static int cfg_setResourceServiceUriBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		cfg_service_descriptor* svc=bundle->cc->globals->resourceService;
		if(svc!=NULL){
			svc->uri=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int cfg_setResourceServiceParamAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		bundle->userdata2=NULL;
		for (i = 0; attributes[i]; i += 2) {
			if(strcmp(attributes[i],"name")==0){
				bundle->userdata2=(void*)apr_pstrdup(p,attributes[i + 1]);
			} 		
  		}
		return 1;
	}
	static int cfg_setResourceServiceTimeoutBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		cfg_service_descriptor* svc=bundle->cc->globals->resourceService;
		if(svc!=NULL){
			svc->timeoutSeconds=atol(body);
		}
		return 1;
	}
	static int cfg_setResourceServiceUserColonPassBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		cfg_bundle* bundle=(cfg_bundle*)userdata;
		cfg_service_descriptor* svc=bundle->cc->globals->resourceService;
		if(svc!=NULL){
			svc->userColonPass=apr_pstrdup(p,body);
		}
		return 1;
	}

	char* configcore_loadConfigCoreFile(pool* p, char* file, config_core* conf){
		char* result=NULL;
		XmlCore* xCore;
		
		cfg_bundle* bundle=(cfg_bundle*)apr_palloc(p,sizeof(cfg_bundle));
		bundle->userdata=NULL;
		bundle->userdata2=NULL;
		bundle->cc=conf;
		
		xCore=xc_getXmlCore(p);
		xc_addXPathHandler(xCore,"/config-core",0,cfg_setCCAttributes,NULL,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/sheapMapFile",0,NULL,cfg_setCCSheapMapFileBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/sheapPageSize",0,NULL,cfg_setCCSheapPageSizeBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/disableProcessRecovery",0,NULL,cfg_setCCDisableProcessRecoveryBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/oidcHeaderPrefix",0,NULL,cfg_setCCHeaderPrefixBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/refreshWaitSeconds",0,NULL,cfg_setCCRefreshWaitSecondsBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/passPhrase",0,NULL,cfg_setCCPassPhraseBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/oidcConfigFile",0,NULL,cfg_setCCOIDCConfigFileBody,NULL, bundle);
		
		xc_addXPathHandler(xCore,"/config-core/resourceService",0,cfg_setResourceServiceAttributes,NULL,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/resourceService/uri",0,NULL,cfg_setResourceServiceUriBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/resourceService/timeoutSeconds",0,NULL,cfg_setResourceServiceTimeoutBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/resourceService/userColonPass",0,NULL,cfg_setResourceServiceUserColonPassBody,NULL, bundle);
		xc_addXPathHandler(xCore,"/config-core/resourceService/param",0,cfg_setResourceServiceParamAttributes,cfg_setResourceServiceTimeoutBody,NULL, bundle);
		
		result=xc_beginParsingTextResponse(xCore,file);
		
		
		return result;	
	}
	
	static int cfg_onSheapPageFlip(pool* p, shared_heap* sheap, void* userdata){
		config_core* configCore=(config_core*)userdata;
		int i=0;
		cfg_service_descriptor* svc=NULL;
		char* error=NULL;
		void* moduleConfig=NULL;

		svc=configCore->service;
		error=amc_postRefresh(p,configCore->sheap,configCore->globals,svc,&moduleConfig);
		if(error==NULL){
			//set as post initialized
			if(moduleConfig!=NULL){
				if(svc->name!=NULL){
					configCore->serviceConfig = moduleConfig;
				}
			}
		}
		return 1;
	}
	int cfg_syncSelf(apr_pool_t* pool,config_core* configCore){
		int ret=0;
		if(configCore!=NULL&&(ret=shdata_syncself(pool,configCore->sheap,cfg_onSheapPageFlip,configCore))==2){
			return 1;	
		}
		return 0;
	}
	
	static void* cfg_initMessaging(pool* p, void* userdata){
		config_core* configCore=(config_core*)userdata;
		return (void*)NULL;
	}
	
	static char* cfg_refreshConfigCore(pool* p,config_core* conf){
		int i;
		cfg_service_descriptor* svc=NULL;
		void* moduleConfig=NULL;
		char* error=NULL;
//		alerts_core* alertsCore=NULL;
//		diagnostics_core* diagCore=NULL;	
		cbs_globals* cbshmGlobals=NULL;
		char cbuf[APR_CTIME_LEN + 1];
		long timeTakenMillis;
		
		lc_openLogFile(p,conf->refreshLogFile);
		lc_rotateLogFile();
		
		apr_time_t t1 = apr_time_now();
		apr_ctime(cbuf, t1);
		lc_printLog("\n\t Refreshing config [%s]\n", cbuf); fflush(stdout);
		
		if(conf->service!=NULL){
			
			shdata_BeginTagging(conf->sheap);
			
			//duplicate cfg_globals and globals on sheap
			cbshmGlobals=cbs_copyGlobalsOnSheap(p,conf->sheap,conf->globals,TRUE);		

			svc=conf->service;
			error=amc_refresh(p,conf->sheap,cbshmGlobals,svc,&moduleConfig);
			if(error!=NULL){
				return apr_pstrcat(p,"[",svc->id,"] Service failed to refresh: ",error,NULL);
			}else{
				//set as initialized
				if(moduleConfig!=NULL){
					if(svc->name!=NULL){
						conf->serviceConfig  = moduleConfig;
					}
				}
			}
			//publish bash segment
			if(error==NULL){
				shdata_PublishBackSeg(conf->sheap);
				cfg_syncSelf(p,conf);
			}
		}
		timeTakenMillis = ((apr_time_now() - t1) / 1000);
		lc_printLog("\n\t Refresh complete [time taken : %d milliseconds]\n", timeTakenMillis); fflush(stdout);
		lc_closeLogFile();
		return error;	
	}
	
	static char* cfg_handleMessageRecieved(pool* p, cfgm_connection* cmConn,cfgm_wire_message* msg,void* localConfig, void* userdata){
		char* result=NULL;
		config_core* configCore=(config_core*)userdata;

		//now we can do out actions that we would like to do...like refresh the config core:)
		if(cfgm_isRefreshMessage(msg)){
			result=cfg_refreshConfigCore(p,configCore);
			if(result==NULL){
				lc_printLog("Refresh succeded\n"); fflush(stdout);
			}else{
				lc_printLog("Refresh failed:%s\n", result); fflush(stdout);
			}
		}
		return NULL;
	}
		
	char* configcore_initializeConfigCore(pool* p,config_core* conf){
		int i=0;
		cfg_service_descriptor* svc=NULL;
		char* error=NULL;
		char* sheapfile=apr_pstrcat(p,conf->globals->homeDir,conf->sheapMapFile,NULL);
		void* moduleConfig=NULL;
		char* errorRet=NULL;
		cbs_globals* cbshmGlobals=NULL;
		char buf[100];
		apr_status_t status=0;

		lc_printLog("Initializing Config Core \n\r");
		lc_printLog("\tSetup filesystem");
		cb_initGlobals(p,conf->globals);
		
		
		lc_printLog("\tSheapFile:\t%s\n",sheapfile);
		lc_printLog("\tSheapPageSize:\t%d\n",conf->sheapPageSize);
		conf->sheap=shdata_sheap_make(p, conf->sheapPageSize,sheapfile);
		if(conf->sheap==NULL){
			return apr_pstrdup(p,"Could not create Config Core shared heap");	
		}
		shdata_BeginTagging(conf->sheap);
			
		//duplicate cfg_globals on sheap and merge global options. 
		cbshmGlobals=cbs_copyGlobalsOnSheap(p,conf->sheap,conf->globals,FALSE);

		if(conf->service!=NULL){
			lc_printLog("\tService Init-\n");

			svc=conf->service;
			if(svc->name!=NULL){
				lc_printLog("\t\t%s [%s] Initializing...\n",svc->id, SAFESTRBLANK(svc->name));
			}else{
				lc_printLog("\t\t%s Initializing...\n",svc->id);
			}
			fflush(stdout);
			error=amc_initialize(p,conf->sheap,cbshmGlobals,svc,&moduleConfig);
			if(error!=NULL){
				if(errorRet==NULL){
					errorRet=apr_pstrdup(p,"�");
				}else{
					errorRet=apr_pstrcat(p,errorRet,"\r\n�",NULL);
				}
				errorRet=apr_pstrcat(p,errorRet,"[",svc->id,"] Service failed to initialize: ",error,NULL);
			}else{
				//set as initialized
				if(moduleConfig!=NULL){
					//set config by name
					if(svc->name!=NULL){
						conf->serviceConfig = moduleConfig;
					}
				}
			}
			fflush(stdout);

			//publish bash segment
			lc_printLog("\tPublishing Config Core Sheap...");
			fflush(stdout);
			shdata_PublishBackSeg(conf->sheap);
			lc_printLog("OK\r\n");
			cfg_syncSelf(p,conf);
			
			if(conf->refreshWaitSeconds>0) {

				lc_printLog("\tStarting Config Core Realm Process:\n");
				lc_closeLogFile();//closing before forking
				cfgm_initializeMessagingLoop(p, conf->globals->logsDir,NULL, conf,
						cfg_initMessaging,cfg_handleMessageRecieved,
						conf->disableProcessRecovery);
				lc_openLogFile(p,conf->refreshLogFile);
			}
			
			
		}
		return errorRet;
	}
	
	static void cfg_printServiceDescriptor(pool* p, cfg_service_descriptor*svc){
		apr_hash_index_t *hi;
		char *name,*val;
		if(svc!=NULL){
			if(svc->name!=NULL){
				lc_printLog("\t�\t%s [%s]\n",svc->id,svc->name);	
			}else{
				lc_printLog("\t�\t%s\n",svc->id);
			}
			lc_printLog("\t\tUri:\t%s\n",svc->uri);
			lc_printLog("\t\tTimeoutSeconds:\t%d\n",svc->timeoutSeconds);
			for (hi = apr_hash_first(p, svc->params); hi; hi = apr_hash_next(hi)) {
				apr_hash_this(hi,(const void**)&name, NULL, (void**)&val);
				lc_printLog("\t\t%s:\t%s\n",name,val);
			}
			lc_printLog("\r\n");
		}else{
			lc_printLog("!!! SERVICE IS NULL\n");	
		}
	}
	void configcore_printConfigCoreDetails(pool* p,config_core* conf){
//		apr_hash_index_t *hi;
		cfg_service_descriptor* svc=NULL;
//		char *name,*val;
		int i=0;
		if(conf==NULL){
			lc_printLog("Config-Core: NULL!!\n");
			return;
		}
		lc_printLog("Config-Core:\n");
		lc_printLog("�\tGlobals-\n");
		lc_printLog("\t\tHomeDir:%s\n",conf->globals->homeDir);
		lc_printLog("\t\tOIDCHeaderPrefix:%s\n",conf->oidcHeaderPrefix);
		lc_printLog("\t\tEnableUnnamedSHM:%d\n",djrglobals_isUnnamedSHMEnabled());
		lc_printLog("\t\tConfigCheckPhaseDelaySec:%d\n",djrglobals_getConfigCheckPhaseDelaySec());
		
		lc_printLog("�\tSystem Services-\n");
		
		if(conf->globals->resourceService!=NULL){
			cfg_printServiceDescriptor(p,conf->globals->resourceService);
		}else{
			lc_printLog("�\tResourceService: NOT ACTIVATED\n");	
		}
		
		lc_printLog("\t\tSheapMapFile:%s\n",conf->sheapMapFile);
		lc_printLog("\t\tSheapPageSize:%d\n",conf->sheapPageSize);
		lc_printLog("\t\tPassPhrase:%s\n",conf->passPhrase);
		if(conf->service!=NULL){
			lc_printLog("�\tServices-\n");		
			svc=conf->service;
			cfg_printServiceDescriptor(p,svc);
		}
		
	}
	
	void* configcore_getModuleConfigByName(config_core* conf,char* name){
		return conf->serviceConfig;
	}

