#ifndef CONFIG_BINDINGS_SHM_H_
#define CONFIG_BINDINGS_SHM_H_
#include <shm_data.h>
#include <shm_apr.h>
#include <config-core/config_bindings.h>

	typedef struct cbs_service_descriptor{
		char* id;
		char* name;
		char* uri;
		char* userColonPass;
		long timeoutSeconds;
		shapr_hash_t * params;
	}cbs_service_descriptor;
		
	typedef struct cbs_globals{
		char* homeDir;
		char* logsDir;
		cbs_service_descriptor* resourceService;
		int isRefresh;
	}cbs_globals;
	
	cbs_globals* cbs_copyGlobalsOnSheap(pool*p, shared_heap* sheap, cfg_globals* globals, int isRefresh);
	char* cbs_getRemoteResourcePath(pool* p, cbs_globals* globals,char* resource,char**details);
	char* cbs_getLocalResourcePath(pool* p, cbs_globals* globals,char* resource,char**details);
#endif /*CONFIG_BINDINGS_SHM_H_*/
