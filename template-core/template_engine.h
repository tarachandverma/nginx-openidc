#ifndef TEMPLATE_ENGINE_H_
#define TEMPLATE_ENGINE_H_
#include <apache_typedefs.h>
#include <shm_apr.h>
#include <shm_data.h>
#include "config_bindings.h"
#include "template_handler_url.h"
#include "config_bindings_shm.h"

typedef char* (*tengine_template_init)(pool*,shared_heap*,cbs_globals*,void**);
typedef char* (*tengine_template_getToken)(pool*,void*,char*);

typedef struct template_engine{
	shapr_hash_t* templateHash;
}template_engine;

typedef struct template_eng_template{
	char* id;
	char* description;
	tengine_template_init initFunc;
	tengine_template_getToken tokenFunc;
}template_eng_template;


typedef struct template_eng_livetemplate{
	void* config;
	template_eng_template* engineTemplate;
}template_eng_livetemplate;

template_engine* te_newEngineObj(shared_heap* sheap);

char* te_initialize(pool* p,shared_heap* sheap,cbs_globals* globals,template_engine* teng);

char* te_getToken(pool* p, template_engine* tengine,char* tid, char* src);

char* te_templateString(pool* p,template_engine* tengine,char* sourcestr,array_header* matches);

static const template_eng_template template_eng_templates[]={
		{"U","Url Encode",NULL,temphand_url_encodeToken},
		{"u","Url Decode",NULL,temphand_url_decodeToken},
		{"B","Url Encode",NULL,temphand_base64_encodeToken},
		{"b","Url Decode",NULL,temphand_base64_decodeToken}	
};
#endif /*TEMPLATE_CORE_H_*/
