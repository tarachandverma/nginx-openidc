#ifndef __TCREWRITE_CONFIG_MESSAGING_PARSING__H_
#define __TCREWRITE_CONFIG_MESSAGING_PARSING__H_

#include <sys/types.h>
#include "apache_typedefs.h"
	typedef struct cfgm_wire_header{
		char* nodeName;
		char* componentId;
		char* version;
	}cfgm_wire_header;
	
	typedef struct cfgm_wire_message{
		char* type;
		cfgm_wire_header* header;
		apr_hash_t* params;
	}cfgm_wire_message;
	
	cfgm_wire_header* cfgm_newWireHeader(pool* p);
	cfgm_wire_message* cfgm_newWireMessage(pool* p,cfgm_wire_header* header);
	cfgm_wire_message* cfgm_newWireMessageType(pool* p,const char* type,cfgm_wire_header* header);
	char* cfgm_serializeMessage(apr_pool_t* p, cfgm_wire_message* msg);
#endif

