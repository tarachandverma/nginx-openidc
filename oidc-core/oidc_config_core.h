#ifndef __TCREWRITE_ACTION_MAPPINGS_CORE__H_
#define __TCREWRITE_ACTION_MAPPINGS_CORE__H_
#include "apache_typedefs.h"
#include "config_bindings_shm.h"
	char* amc_initialize(pool* p,shared_heap* sheap,cbs_globals* globals,cfg_service_descriptor* svcdesc,void** userdata);
	char* amc_refresh(pool* p,shared_heap* sheap,cbs_globals* globals,cfg_service_descriptor* svcdesc,void** userdata);
	char* amc_postRefresh(pool* p,shared_heap* sheap,cfg_globals* globals,cfg_service_descriptor* svcdesc,void** userdata);
#endif
