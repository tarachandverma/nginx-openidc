#ifndef __TCREWRITE_CONFIG_BINDINGS__H_
#define __TCREWRITE_CONFIG_BINDINGS__H_

#include <sys/types.h>
#include "apache_typedefs.h"

	typedef struct cfg_service_descriptor{
		char* id;
		char* name;
		char* uri;
		char* userColonPass;
		long timeoutSeconds;
		apr_hash_t * params;
	}cfg_service_descriptor;

	// old version of cfg_globals (pool version).
	typedef struct cfg_globals{
		char* homeDir;
		char* logsDir;
		cfg_service_descriptor* resourceService;
	}cfg_globals;
	
	cfg_service_descriptor* cb_newServiceDescriptorObj(pool* p);
	cfg_globals* cb_newGlobalsObj(pool* p);
	char* cb_initGlobals(pool* p,cfg_globals* globals);
	char* cb_writeRemoteResourceToDisk(pool* p, char* homeDir, char* reqUri, char* resource, 
			long timeoutSeconds, char* userColonPass, apr_pool_t* tp, char**details, int* responseCode);
	int cb_canAutoRefreshNow(pool* p, cfg_service_descriptor* resourceService, time_t lastRefreshTimestamp, time_t currentTimestamp, char* namespace,char**error);
#endif

