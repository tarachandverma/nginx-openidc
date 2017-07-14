#ifndef TOKEN_TEMPLATE_URL_H_
#define TOKEN_TEMPLATE_URL_H_
#include "apache_typedefs.h"

	char* temphand_url_encodeToken(pool* p,void* config,char* src);
	char* temphand_url_decodeToken(pool* p,void* config,char* src);

	// base64 encode decode
	char* temphand_base64_encodeToken(pool* p,void* config,char* src);
	char* temphand_base64_decodeToken(pool* p,void* config,char* src);
	
#endif /*TOKEN_TEMPLATE_ENCRYPTION_H_*/
