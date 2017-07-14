#include "template_handler_url.h"
#include "url_utils.h"

	char* temphand_url_encodeToken(pool* p,void* config,char* src){
		return url_encode2(p,src);
	}

	char* temphand_url_decodeToken(pool* p,void* config,char* src){
		return url_decode2(p,src);
	}
	
// base64 encode decode
	char* temphand_base64_encodeToken(pool* p,void* config,char* src){
		char encoded[2048];
		if(src==NULL) return "(null)";
		base64_encode(encoded, (char*)src, strlen(src));
		return apr_pstrdup(p, encoded);
	}

	char* temphand_base64_decodeToken(pool* p,void* config,char* src){
		char decoded[2048];
		if(src==NULL) return "(null)";
		base64_decode(decoded, (char*)src, strlen(src));
		return apr_pstrdup(p, decoded);
	}

	
