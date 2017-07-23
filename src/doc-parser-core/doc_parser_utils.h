#ifndef DOC_PARSER_UTILS_H_
#define DOC_PARSER_UTILS_H_
#include <config-core/config_bindings_shm.h>
	char* docp_getRemoteResourcePath(pool* p, char* resource,cbs_service_descriptor *rs,char* homeDir,char**details);
	char* docp_getLocalResourcePath(pool*p,char* resource,char* homeDir);
	char* docp_getRemoteResourcePathEx(pool* p, char* resourceUri, char* homeDir,char**details);
#endif /*DOC_PARSER_UTILS_H_*/
