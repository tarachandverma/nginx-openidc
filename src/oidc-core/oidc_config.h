#ifndef __TCREWRITE_ACTION_MAPPINGS__H_
#define __TCREWRITE_ACTION_MAPPINGS__H_
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apache_typedefs.h>
#include <shm_data.h>
#include <shm_apr.h>
#include <template-core/template_engine.h>
#include <config-core/config_bindings_shm.h>
#include <json-api-core/json_parser.h>
#include "oidc_core_constants.h"
#include "cookie.h"

#define TIME_MAX 	(~ (~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1)))

	typedef struct oauth_jwskey{
		char* id;
		char* type;
		char* algorithm;
		char* use;
		char* modulus;
		char* exponent;
		char* x5c;
	}oauth_jwskey;

	typedef struct match_event{
		time_t start;
		time_t end;
	}match_event;
	
	typedef struct match_ip{
		char* ip;
		unsigned short negate;
		unsigned short isRegex;
	}match_ip;
	typedef struct match_path{
		char* path;
		unsigned short negate;
	}match_path;	
	typedef struct match_list_header{
		char* name;
		char* value;
		char* delimAnd;
		unsigned short negate;
		unsigned short isRegex;
	}match_list_header;
	
	typedef struct match_list_env{
		char* name;
		char* value;
		unsigned short negate;
		unsigned short isRegex;
	}match_list_env;
	
	typedef struct match_list_match{
		match_ip* ip;
		match_path*path;
		array_header* headerList;
		match_event*event;
		char* host;
		int cascade;
	}match_list_match;
	
	typedef struct match_list{
		char* name;
		array_header* list;
	}match_list;

	typedef struct action_header{
		char* name;
		char* value;
		char* regex;
		header_actions action;
	}action_header;
	
	typedef struct action_uri{
		char* uri;
		int weight;
	}action_uri;

	// custom response
	typedef struct action_response{
		int code;
		char* contentType;
		char* body;
	}action_response;
		
	typedef struct page_action{
		char *id, *description;		
		char* regex;
		char* handler_internal;
		template_engine* templateEngineRef;
		array_header* requestHeaders;		// array of action_header*
		array_header* responseHeaders;		// array of action_header*
		action_response* response;		
		char* uri, *oidcProvider, *relyingParty;
		int type;
		unsigned int isForward:1,isPermanent:1,isDebug:1, advancedTemplate:1,base64UrlEncodeState:1;
	}page_action;

	typedef struct pathmapping_action{
		page_action *action;
		match_list* matchList;
	}pathmapping_action;
	
	typedef struct path_mapping{
		char* pathRegex;
		int ignoreCase;
		array_header* pmactions;//array of pathmapping_action
		array_header* matchLists;
	}path_mapping;
	
	typedef struct path_mappings_rec{
		array_header* postauth;
	}path_mappings_rec;
	
	typedef struct relying_party{
		char* id;
		char* description;
		char *clientID;
		char* clientSecret;
		char* issuer;
		int	validateNonce;
		char* redirectUri;
		char* postLoginDefaultLandingPage;
	}relying_party;
	
	typedef struct oidc_providerl{
		char* id;
		char* metadataUrl;
		char* issuer;
		char* authorizationEndpoint;
		char* tokenEndpoint;
		char* jwksUri;
		shapr_hash_t* jwsKeys;
		int isDefault;
	}oidc_provider;

	typedef struct oidc_config{
		shapr_hash_t* page_actions;
		path_mappings_rec* path_mappings;
		shapr_hash_t* match_lists;
		template_engine* templateEngine;
		Cookie*	 rpSession;
		Cookie*	 oidcSession;
		Cookie*	 accessToken;
		shapr_hash_t* relyingPartyHash;
		shapr_hash_t* relyingPartyIdsHash;
		shapr_hash_t* oidcProviderHash;
		shapr_hash_t* oidcProviderIdsHash;
		oidc_provider* oidcProvider;
	}oidc_config;
	
	char* am_build(pool* p,shared_heap* sheap,int isRefresh,cbs_globals* globals,char* filepath);
	oidc_config* am_fetchFromSheap(shared_heap* sheap);
	page_action* am_getPageActionById(oidc_config* actmap,char* id);
	path_mapping* am_getPathMapping_PostAuth(pool* p,oidc_config* actmap,char* path,char* ip, apr_table_t* headers, apr_table_t* subprocess_env);
	page_action* am_getMatchingPageAction(pool* p,array_header* pactions,char* path,char* ip, apr_table_t* headers, apr_table_t* subprocess_env);
	match_list_match* am_isMatchListMatch(pool* p, match_list* matchlist, char* path, char* ip,apr_table_t *headers_in, apr_table_t* subprocess_env);
	void am_printAll(pool* p, oidc_config* oidcConfig);
	oauth_jwskey* am_getJWSKeyByKeyID(shapr_hash_t* keyHash, char* keyID);
	relying_party* am_getRelyingPartyByClientID(shapr_hash_t* relyingPartyHash, const char* clientID);
	relying_party* am_getRelyingPartyById(shapr_hash_t* relyingPartyIdsHash, const char* id);
	relying_party* am_getRelyingPartyByRedirectUri(pool*p, shapr_hash_t* relyingPartyHash, const char* currentRedirectUri);
	oidc_provider* am_getOidcProviderByIssuer(shapr_hash_t* oidcProviderHash, const char* issuer);
	oidc_provider* am_getOidcProviderById(shapr_hash_t* oidcProviderIdsHash, const char* id);

	typedef struct oauth_jwt_header {
		char* algorithm;
		char* type;
		char* keyID;
	}oauth_jwt_header;

	typedef struct oauth_jwt_claim {
		char* issuer;
		char* scope;
		char* subject;
		char* audience;
		time_t expiry;
		time_t issuedAt;
		time_t auth_time;
		apr_hash_t* options;
		array_header* roles;
	}oauth_jwt_claim;

	typedef struct oauth_jwt {
		oauth_jwt_header* header;
		oauth_jwt_claim*  claim;
		char* signature;
	}oauth_jwt;

	// JSON Web Key
	typedef struct oauth_jwk{
		char* algorithm;
		char* use;
		char* keyID;
		char* key;		// symmetric key
		char* modulus;	// rsa public key modulus
		char* exponent;	// rsa public key exponent
	}oauth_jwk;

	// JWT routines
	oauth_jwt_header* oauthutil_newJWTHeaderObj(pool* p);
	const char* oauthutil_serializeJWTHeader(pool* p, oauth_jwt_header* hdr);
	oauth_jwt_header* oauthutil_deserializeJWTHeader(pool* p, char* encodedHeader);

	oauth_jwt_claim* oauthutil_newJWTClaimObj(pool* p);
	const char* oauthutil_serializeJWTClaim(pool* p, oauth_jwt_claim* claim);
	oauth_jwt_claim* oauthutil_deserializeJWTClaim(pool* p, char* encodedClaim);
	oauth_jwt_claim* oauthutil_deserializeJWTClaimNoDecoding(pool* p, char* claimJson);

	oauth_jwt* oauthutil_newJWTObj(pool* p);
	const char* oauthutil_serializeJWT(pool*p, oauth_jwt* jwt, const char* secretKey) ;
	typedef const char* (*getClientSecretKeyByClientId_func)(pool*p, char* client_id, void* data);
	oauth_jwt* oauthutil_parseAndValidateJWT(pool* p, const char* src, getClientSecretKeyByClientId_func getClientSecretKeyByClientIdFunc, void* data);
	void oauthutil_printJWT(pool* p, oauth_jwt* jwt);

	//ID Token ( JWT format)
	oauth_jwk* oauthutil_newJWKObj(pool *p);
	const char* oauthutil_generateIDToken(pool* p, oauth_jwt_header* header, oauth_jwt_claim*  claim, const char* secretKey) ;
	typedef oauth_jwk* (*getJSONWebKey_func)(pool*p, oauth_jwt_header* header, const char* issuer, const char* audience, void* data, char** error);
	oauth_jwt* oauthutil_parseIDToken(pool* p, const char* src, char** payloadP, char** error);
	oauth_jwt* oauthutil_parseAndValidateIDToken(pool* p, const char* src, getJSONWebKey_func getJSONWebKeyFunc, void* data, char** error);
	void oauthutil_printIDToken(pool* p, oauth_jwt* IDToken);
	const char* oauthutil_serializeJWTClaimNoEncoding(pool* p, oauth_jwt_claim* claim);

	const char* am_getActionTypeStr(action_types type) ;
#endif //__TCREWRITE_ACTION_MAPPINGS__H_
