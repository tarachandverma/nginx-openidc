#ifndef __TCREWRITE_CONFIG_CORE__H_
#define __TCREWRITE_CONFIG_CORE__H_

#include <sys/types.h>
#include "apache_typedefs.h"
#include "shm_apr.h"
#include "config_bindings.h"
#include "oidc_config_core.h"
#include "config_messaging.h"
#include "config_bindings_shm.h"
#include "common_utils.h"

	typedef struct config_core{
		cfg_globals* globals;
		cfg_service_descriptor* service;
		shared_heap* sheap;
		char* sheapMapFile;
		int sheapPageSize;
		void* serviceConfig;
		char* passPhrase;
		char* refreshLogFile;
		int disableProcessRecovery;
		char* oidcHeaderPrefix;
		int refreshWaitSeconds;
		char* oidcConfigFile;
		oidc_cipher_cfg* cipherConfig;
	}config_core;
	
	config_core* configcore_newConfigCoreObj(pool* p);
	char* configcore_loadConfigCoreFile(pool* p, char* file, config_core* conf);
	char* configcore_initializeConfigCore(pool* p,config_core* conf);
	void configcore_printConfigCoreDetails(pool* p,config_core* conf);
	int cfg_syncSelf(apr_pool_t* pool,config_core* configCore);
	void* configcore_getModuleConfigByName(config_core* conf,char* name);

#endif

