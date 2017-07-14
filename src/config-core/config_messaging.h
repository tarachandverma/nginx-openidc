#ifndef __TCREWRITE_CONFIG_MESSAGING__H_
#define __TCREWRITE_CONFIG_MESSAGING__H_

#include <sys/types.h>
#include "apache_typedefs.h"
#include <config-core/config_messaging_parsing.h>
#include "apr_thread_proc.h"
	
	typedef struct cfgm_connection{
		cfgm_wire_header* wireHeader;
	}cfgm_connection;
		
	typedef char* (*cfgm_message_recieved_func) (pool*,cfgm_connection*,cfgm_wire_message*,void*, void*);
	typedef void* (*cfgm_init_messaging_func)(pool*,void*);

	apr_proc_t* cfgm_initializeMessagingLoop(pool* p, char* homeDir, void* messageBroker, void* userdata,
			cfgm_init_messaging_func initFunc, cfgm_message_recieved_func msgRecFunc,
			int disableProcessRecovery);
	cfgm_connection* cfgm_newConnectionObj(pool* p);
	int cfgm_isRefreshMessage(cfgm_wire_message* msg);
		
#endif

