#ifndef __DJREWRITE_ACTION_MAPPINGS_XML__H_
#define __DJREWRITE_ACTION_MAPPINGS_XML__H_
#include "apache_typedefs.h"
#include "oidc_core_constants.h"
#include "cookie.h"

	typedef struct action_header_xml{
		char* name;
		char* value;
		char* regex;
		header_actions action;
	}action_header_xml;
	
	// custom response
	typedef struct action_response_xml{
		int code;
		char* contentType;
		char* body;
	}action_response_xml;
	
	typedef struct page_action_xml{
		char *id,*directory,*description;		
		char* regex;
		char* handler;
		array_header* responseHeaders;		// array of action_header_xml*
		array_header* requestHeaders;		// array of action_header_xml*
		action_response_xml* response;		// custom response		
		char* uri;
		int isDebug:1, isForward:1,isPermanent:1,advancedTemplate:1,isForbidden:1;
	}page_action_xml;
	
	typedef struct pathmapping_action_xml{
		char *id;
		char* matchList;//matchlist name
	}pathmapping_action_xml;
		
	typedef struct path_mapping_xml{
		char* pathRegex;
		int ignoreCase;
		array_header*  postAuthActions;
		array_header* matchLists;
	}path_mapping_xml;

	typedef struct relying_party_xml{
		char* description;
		char *clientID;
		char* clientSecret;
		char* domain;
		int 	validateNonce;
	}relying_party_xml;

	typedef struct oidc_provider_xml{
		char* metadataUrl;
	}oidc_provider_xml;

	typedef struct oidc_config_xml{
		int uid;					// unique id for document
		apr_hash_t* page_actions_hash;
		array_header* path_mappings_arr;
		array_header* match_list_arr;
		Cookie*				rpSession;
		Cookie*				oidcSession;
		apr_hash_t* relyingPartyHash;
		oidc_provider_xml* oidcProvider;
	}oidc_config_xml;
	
	oidc_config_xml* amx_newObj(pool* p);
	char* amx_loadConfFile(pool* p, char* file, oidc_config_xml* conf);
	void amx_printAll(pool* p,oidc_config_xml* conf);
	
#endif
