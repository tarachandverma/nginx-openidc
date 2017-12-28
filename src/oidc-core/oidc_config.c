#include <oidc-core/oidc_config.h>
#include <oidc-core/oidc_config_xml.h>
#include <oidc-core/rewrite_core.h>
#include <common_utils.h>
#include <oidc-core/match_list.h>
#include <doc_parser_utils.h>
#include <http-utils/http_client.h>

#define CONST_PATH_ACTION_DEF_ELTS	4
#define SHEAP_ITEM_ID_AUTHZ_OIDC	"NGX_OPENIDC"
#define KEYBUFFSIZE 8192

	static path_mappings_rec* am_newPathMappingObj(shared_heap* sheap){
		path_mappings_rec* ret;
		ret=(path_mappings_rec*)shdata_shpalloc(sheap,sizeof(path_mappings_rec));
		ret->postauth=shapr_array_make (sheap,CONST_PATH_ACTION_DEF_ELTS,sizeof(path_mapping*));
		return ret;	
	}
	
	static oidc_config* am_newObj(shared_heap* sheap){
		oidc_config* ret;
		
		ret=(oidc_config*)shdata_shpalloc(sheap,sizeof(oidc_config));
		ret->path_mappings=am_newPathMappingObj(sheap);
		ret->page_actions=shapr_hash_make(sheap);
		ret->match_lists=shapr_hash_make(sheap);
		ret->templateEngine=NULL;
		ret->relyingPartyHash=shapr_hash_make(sheap);
		ret->oidcProviderHash=shapr_hash_make(sheap);
		ret->oidcProvider=NULL;
		return ret;		
	}
	
	static page_action* am_newPageAction(shared_heap* sheap){
		page_action* ret=NULL;
		ret=(page_action*)shdata_shpalloc(sheap,sizeof(page_action));
		ret->id=NULL;
		ret->regex=NULL;
		ret->handler_internal=NULL;
		ret->description=NULL;
		ret->isForward=0;
		ret->isPermanent=0;
		ret->isLoginRedirect=0;
		ret->isDebug=0;
		ret->templateEngineRef=NULL;
		ret->advancedTemplate=FALSE;
		ret->requestHeaders=NULL;
		ret->responseHeaders=NULL;
		ret->response=NULL;		
		ret->uri=NULL;
		return ret;	
	}
	
	page_action* am_getPageActionById(oidc_config* actmap,char* id){
		if(actmap==NULL||actmap->page_actions==NULL||id==NULL){return NULL;}
		return shapr_hash_get(actmap->page_actions,id,APR_HASH_KEY_STRING);
	}
	match_list* am_getMatchListByName(oidc_config* actmap,char* name){
		if(actmap==NULL||actmap->match_lists==NULL||name==NULL){return NULL;}
		return shapr_hash_get(actmap->match_lists,name,APR_HASH_KEY_STRING);
	}
	pathmapping_action* am_getPathMappingAction(shared_heap* sheap,oidc_config* actmap,pathmapping_action_xml* pmaX){
		pathmapping_action*ret=NULL;
		
		if(actmap==NULL||actmap->page_actions==NULL||pmaX==NULL){return NULL;}
		
		ret=(pathmapping_action*)shdata_shpcalloc(sheap,sizeof(pathmapping_action));
		ret->action=am_getPageActionById(actmap,pmaX->id);
		ret->matchList=am_getMatchListByName(actmap,pmaX->matchList);
		return ret;
	}	
//	char* am_getFormattedUrl(pool *p, char* cur, char* namespaceid){
//		int x,queryStrState=0;
//		int curlen=strlen(cur);
//		for(x=0;x<curlen;x++){
//			if(cur[x]=='?'){
//				if(x==curlen-1){
//					queryStrState=2;
//				}else{
//					queryStrState=1;	
//				}
//			}
//		}
//		if(queryStrState==0){
//			return apr_pstrcat(p,cur,"?mg=",namespaceid,NULL);
//		}else if(queryStrState==1){
//			return apr_pstrcat(p,cur,"&mg=",namespaceid,NULL);
//		}else if(queryStrState==2){
//			return apr_pstrcat(p,cur,"mg=",namespaceid,NULL);
//		}
//	}
	
	static action_header* am_newActionHeaderObj(shared_heap* sheap, action_header_xml* hdrX,shapr_hash_t* matchLists){
		action_header* ret= 
			(action_header*)shdata_shpcalloc(sheap, sizeof(action_header));
		ret->name = 
			shdata_32BitString_copy(sheap, hdrX->name);
		ret->value = 
			shdata_32BitString_copy(sheap, hdrX->value);
		ret->regex = 
			shdata_32BitString_copy(sheap, hdrX->regex);
		ret->action = hdrX->action;
		return ret;
	}
	
	static array_header* am_copyActionHeaders(pool* p, shared_heap* sheap, array_header* actionHeadersX,shapr_hash_t* matchLists){
		array_header* ret=NULL;
		action_header_xml* hdrX=NULL;
		int i=0;
		
		if(actionHeadersX==NULL || actionHeadersX->nelts<1) return NULL;
		
		ret = shapr_array_make(sheap, actionHeadersX->nelts, sizeof(action_header*));
		for(i=0; i<actionHeadersX->nelts; i++){
			action_header_xml* hdrX = (action_header_xml*)cu_getElement(actionHeadersX, i);
			if(hdrX!=NULL&&hdrX->name!=NULL) {
				action_header** pos = (action_header**)shapr_array_push(sheap, ret);
				*pos = am_newActionHeaderObj(sheap, hdrX,matchLists);
			}
		}
		return ret;
	}
	
	static action_response* am_copyActionResponse(shared_heap* sheap, action_response_xml* responseX){
		action_response* ret = NULL;
		
		if(responseX==NULL) return NULL;
		
		ret= (action_response*)shdata_shpcalloc(sheap, sizeof(action_response));
		ret->code = responseX->code;
		ret->contentType = shdata_32BitString_copy(sheap, responseX->contentType);
		ret->body = shdata_32BitString_copy(sheap, responseX->body);
		return ret;
	}

	static char* am_build_pageActions(pool* p,shared_heap* sheap,cbs_globals* globals,oidc_config_xml* axml,shapr_hash_t* hash,template_engine* templateEngine,
			shapr_hash_t* matchLists){
		apr_hash_index_t * hi=NULL;
		void *val=NULL;
		page_action_xml* pax=NULL;
		page_action* paction=NULL;
		int i=0;
		
		for (hi = apr_hash_first(p,axml->page_actions_hash); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, &val);
			if(val!=NULL){
				pax=(page_action_xml*)val;
				paction=am_newPageAction(sheap);
				
				//set global structures
				paction->templateEngineRef=templateEngine;
				
				//transfer details
				paction->isForward=pax->isForward;
				paction->isPermanent=pax->isPermanent;
				paction->isLoginRedirect=pax->isLoginRedirect;
				paction->advancedTemplate=pax->advancedTemplate;
				paction->id=shdata_32BitString_copy(sheap,pax->id);
				paction->description=shdata_32BitString_copy(sheap,pax->description);
				paction->regex=shdata_32BitString_copy(sheap,pax->regex);
				paction->handler_internal=shdata_32BitString_copy(sheap,pax->handler);	
				paction->isDebug=pax->isDebug;
				paction->requestHeaders=am_copyActionHeaders(p,sheap,pax->requestHeaders,matchLists);
				paction->responseHeaders=am_copyActionHeaders(p,sheap,pax->responseHeaders,matchLists);
				paction->response=am_copyActionResponse(sheap,pax->response);
				paction->uri=shdata_32BitString_copy(sheap,pax->uri);
				
				shapr_hash_set(sheap,hash,pax->id,APR_HASH_KEY_STRING,paction);
			}
		}
		return NULL;
	}
	static match_ip* am_newMatchIpFromXmlMatchIpObj(shared_heap*sheap,mlx_match_ip*matchIp){
		match_ip*ret;
		
		if(matchIp==NULL)	return NULL;
		
		ret=(match_ip*)shdata_shpalloc(sheap,sizeof(match_ip));
		ret->ip=shdata_32BitString_copy(sheap,matchIp->ip);
		ret->isRegex=matchIp->isRegex;
		ret->negate=matchIp->negate;
		return ret;
	}
	static match_path* am_newMatchPathFromXmlMatchPathObj(shared_heap*sheap,mlx_match_path*matchPath){
		match_path*ret;
		
		if(matchPath==NULL)	return NULL;
		
		ret=(match_path*)shdata_shpalloc(sheap,sizeof(match_path));
		ret->path=shdata_32BitString_copy(sheap,matchPath->path);
		ret->negate=matchPath->negate;
		return ret;
	}
	
	static match_event* am_newMatchEventObj(shared_heap*sheap,mlx_match_event* e){
		match_event* ret;
		
		if(e==NULL)	return NULL;
		
		ret=(match_event*)shdata_shpalloc(sheap,sizeof(match_event));
		ret->start=e->start;
		ret->end=e->end;
		return ret;
	}	
	
	static match_list_match* am_copyMatchListMatch(shared_heap* sheap,mlx_ml_match* matchX){
		match_list_match* ret=NULL;
		//page_action_nvp_xml* nvpX=NULL;
		//match_list_match_nvp* nvp=NULL, **nvpPlace=NULL;
		mlx_match_header* hdrX=NULL;
		match_list_header*hdr=NULL, **headerPlace;
		mlx_match_env* envX=NULL;
		match_list_env*env=NULL, **envPlace;		
		int i=0;
		
		if(matchX==NULL) return NULL;
		
		ret=(match_list_match*)shdata_shpalloc(sheap,sizeof(match_list_match));
		ret->cascade=matchX->cascade;
		ret->host=shdata_32BitString_copy(sheap,matchX->host);
		ret->ip=am_newMatchIpFromXmlMatchIpObj(sheap,matchX->ip);
		ret->path=am_newMatchPathFromXmlMatchPathObj(sheap,matchX->path);
		ret->event=am_newMatchEventObj(sheap,matchX->event);
		if(matchX->headerList!=NULL&&matchX->headerList->nelts>0){
			ret->headerList=shapr_array_make(sheap,matchX->headerList->nelts,sizeof(match_list_header*));
			for(i=0;i<matchX->headerList->nelts;i++){
				hdrX=(mlx_match_header*)cu_getElement(matchX->headerList,i);
				hdr=(match_list_header*)shdata_shpalloc(sheap,sizeof(match_list_header));
				hdr->name=shdata_32BitString_copy(sheap,hdrX->name);
				hdr->value=shdata_32BitString_copy(sheap,hdrX->value);
				hdr->delimAnd=shdata_32BitString_copy(sheap,hdrX->delimAnd);
				hdr->negate=hdrX->negate;
				hdr->isRegex=hdrX->isRegex;
				headerPlace=(match_list_header**)shapr_array_push(sheap,ret->headerList);
				*headerPlace=hdr;
			}
		}else{
			ret->headerList=NULL;
		}

		return ret;		
	}
	static char* am_build_matchLists(pool* p,shared_heap* sheap,oidc_config_xml* axml,shapr_hash_t* hash){
		mlx_matchlist* mlx=NULL;
		match_list* ml=NULL;
		mlx_ml_match* matchX=NULL;
		match_list_match* match=NULL, **matchPos=NULL;
		int i=0,j=0;
		
		if(axml->match_list_arr==NULL||axml->match_list_arr->nelts==0){return NULL;}
		
		for(i=0;i<axml->match_list_arr->nelts;i++){
			mlx=(mlx_matchlist*)cu_getElement(axml->match_list_arr,i);
			ml=(match_list*)shdata_shpalloc(sheap,sizeof(match_list));
			ml->name=shdata_32BitString_copy(sheap,mlx->name);
			if(mlx->matches!=NULL&&mlx->matches->nelts>0){
				ml->list=shapr_array_make(sheap,mlx->matches->nelts,sizeof(match_list_match*));
				for(j=0;j<mlx->matches->nelts;j++){
					matchX=(mlx_ml_match*)cu_getElement(mlx->matches,j);
					match=am_copyMatchListMatch(sheap,matchX);
					matchPos=(match_list_match**)shapr_array_push(sheap,ml->list);
					*matchPos=match;
				}
			}else{
				ml->list=NULL;
			}
			shapr_hash_set(sheap,hash,ml->name,APR_HASH_KEY_STRING,ml);
		}
		
		return NULL;
	}

	
	static path_mapping* am_buildMapping(shared_heap* sheap,oidc_config* actmap, char* regex, int ignoreCase, array_header* pmactionsX, array_header* matchlists){
		path_mapping* ret=NULL;
		int i=0;
		char* match=NULL;
		match_list* mlist=NULL, **mlistPos;
		pathmapping_action_xml* pmaX;
		pathmapping_action* pma,**pos;
		
		if(pmactionsX==NULL||pmactionsX->nelts<0){
			return NULL;
		}
		ret=(path_mapping*)shdata_shpalloc(sheap,sizeof(path_mapping));
		ret->pathRegex=shdata_32BitString_copy(sheap,regex);
		ret->ignoreCase=ignoreCase;
		
		ret->pmactions=shapr_array_make(sheap,pmactionsX->nelts,sizeof(pathmapping_action*));
		for(i=0;i<pmactionsX->nelts;i++){
			pmaX=(pathmapping_action_xml*)cu_getElement(pmactionsX,i);
			pma=am_getPathMappingAction(sheap,actmap,pmaX);	
			pos=shapr_array_push(sheap,ret->pmactions);
			*pos=pma;
		}
		
		if(matchlists==NULL){
			ret->matchLists=NULL;
		}else{
			ret->matchLists=shapr_array_make(sheap,matchlists->nelts,sizeof(match_list*));
			
			//added linked match lists
			for(i=0;i<matchlists->nelts;i++){
				match=(char*)cu_getElement(matchlists,i);
				mlist=shapr_hash_get(actmap->match_lists,match,APR_HASH_KEY_STRING);
				if(mlist!=NULL){
					mlistPos=(match_list**)shapr_array_push(sheap,ret->matchLists);
					*mlistPos=mlist;
				}
			}
		}
		return ret;
	}
	static void am_addMapping(shared_heap* sheap,array_header* maparr,path_mapping* pmap){
			path_mapping** pmapholder=NULL;
			
			if(maparr!=NULL&&pmap!=NULL){
				pmapholder=(path_mapping**)shapr_array_push(sheap,maparr);
				*pmapholder=pmap;
			}
	}

	static relying_party* am_newRelyingParty(shared_heap* sheap){
		relying_party* ret=NULL;
		ret=(relying_party*)shdata_shpalloc(sheap,sizeof(relying_party));
		ret->clientID=NULL;
		ret->clientSecret=NULL;
		ret->description=NULL;
		ret->issuer=NULL;
		ret->redirectUri=NULL;
		return ret;
	}

	static char* am_copyRelyingsParties(pool* p,shared_heap* sheap, apr_hash_t* relyingPartyHash,shapr_hash_t* hash){
		apr_hash_index_t * hi=NULL;
		void *val=NULL;
		relying_party_xml* rpX=NULL;
		relying_party* rp=NULL;
		int i=0;

		for (hi = apr_hash_first(p,relyingPartyHash); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, &val);
			if(val!=NULL){
				rpX=(relying_party_xml*)val;
				rp=am_newRelyingParty(sheap);

				//transfer details
				rp->clientID=shdata_32BitString_copy(sheap,rpX->clientID);
				rp->description=shdata_32BitString_copy(sheap,rpX->description);
				rp->clientSecret=shdata_32BitString_copy(sheap,rpX->clientSecret);
				rp->issuer=shdata_32BitString_copy(sheap,rpX->issuer);
				rp->validateNonce = rpX->validateNonce;
				rp->redirectUri=shdata_32BitString_copy(sheap,rpX->redirectUri);
				shapr_hash_set(sheap,hash,rp->clientID,APR_HASH_KEY_STRING,rp);
			}
		}
		return NULL;
	}

	static char* oauthconf_downloadOIDCProviderMetadata(pool*p, shared_heap* sheap, char* homeDir, char* metadataUrl){
		oidc_provider* oidcProvider=NULL;
		char *error=NULL;
		apr_file_t* file=NULL;
		apr_status_t status;
		char key[KEYBUFFSIZE];
		apr_size_t bytes_read = KEYBUFFSIZE-1;
		pool* tp=NULL;

		if(metadataUrl==NULL) return NULL;

		//setup filepool
		if(apr_pool_create(&tp,p)!=APR_SUCCESS){
			return NULL;
		}

		char* keyPath=docp_getRemoteResourcePathEx(tp,metadataUrl,homeDir,&error);
		if(keyPath==NULL){
			keyPath=docp_getLocalResourcePath(tp,metadataUrl,homeDir);
		}

		status = apr_file_open (&file, keyPath, APR_READ,APR_OS_DEFAULT,tp);
		if(status!=APR_SUCCESS)	{
			//File open operation failed.
			apr_pool_destroy(tp);
			return NULL;
		}

		memset(key, '\0', KEYBUFFSIZE);
		if( (status = apr_file_read(file, key, &bytes_read)) != APR_SUCCESS) {
			//File read operation failed.
			apr_pool_destroy(tp);
			apr_file_close(file);
			return NULL;
		}


		apr_file_close ( file );
		apr_pool_destroy(tp);

		return apr_pstrdup(p, key);
	}

	char* am_build(pool* p,shared_heap* sheap, int isRefresh,cbs_globals* globals,char* filepath){
		apr_status_t status;
		oidc_config_xml* axml=NULL;
		oidc_config*	ret=NULL;
		char* result=NULL;
		
		//stuff to handle config
		pool* subp=NULL;
		path_mapping_xml* pathx=NULL;
		int x=0, i=0;
		
		//stuff to map path mappings
		path_mapping* pmap=NULL;
		
		//Subdoc processing
		char* homeDir=globals->homeDir;
		cbs_service_descriptor *rs=globals->resourceService;
		char* error=NULL;
		apr_hash_index_t * hi=NULL;
		
		//do on subpool
		if((status=apr_pool_create(&subp,p))!=APR_SUCCESS){
			return apr_pstrdup(p,"Could not create subpool");	
		}
		axml=amx_newObj(subp);
		result=amx_loadConfFile(subp,filepath,axml);

		if(isRefresh==0){
			amx_printAll(subp,axml);
		}
		//end
		shdata_OpenItemTag(sheap,SHEAP_ITEM_ID_AUTHZ_OIDC);
		ret=am_newObj(sheap);
		
		//initialize template engine
		ret->templateEngine=te_newEngineObj(sheap);
		result=te_initialize(p,sheap,globals,ret->templateEngine);
		
		
		//parse through matchlists in config
		am_build_matchLists(p,sheap,axml,ret->match_lists);
		
		//parse through page_actions in config
		am_build_pageActions(p,sheap,globals,axml,ret->page_actions,ret->templateEngine,ret->match_lists);
				
		//parse through path mappings in config;
		for(x=0;x<axml->path_mappings_arr->nelts;x++){
			pathx=(path_mapping_xml*)cu_getElement(axml->path_mappings_arr,x);
			if(pathx->postAuthActions!=NULL&&pathx->postAuthActions->nelts>0){
				pmap=am_buildMapping(sheap,ret,pathx->pathRegex, pathx->ignoreCase, pathx->postAuthActions,pathx->matchLists);
				if(pmap!=NULL){
					am_addMapping(sheap,ret->path_mappings->postauth,pmap);	
				}
			}
		}

		if(axml->oidcProviders==NULL||axml->oidcProviders->nelts==0) {
			return apr_pstrdup(p,"oidcProviders are missing");
		}

		// set default to NULL
		ret->oidcProvider = NULL;

		// iterate thru all the providers
		for(x=0;x<axml->oidcProviders->nelts;x++) {
			oidc_provider_xml* oidcProviderX=(oidc_provider_xml*)cu_getElement(axml->oidcProviders,x);
			if(oidcProviderX!=NULL){
				oidc_provider* oidcProvider=(oidc_provider*)shdata_shpcalloc(sheap,sizeof(oidc_provider));

				// copy one by one
				// download oidcProvider url and read it.
				oidcProvider=(oidc_provider*)shdata_shpcalloc(sheap,sizeof(oidc_provider));
				oidcProvider->isDefault = oidcProviderX->isDefault;
				char* jwksJson = NULL;
				if(oidcProviderX->metadataUrl!=NULL) {
					oidcProvider->metadataUrl=shdata_32BitString_copy(sheap,oidcProviderX->metadataUrl);
					char* metadata = oauthconf_downloadOIDCProviderMetadata(p, sheap, homeDir, oidcProviderX->metadataUrl);
					Value* json = 	JSON_Parse(p, metadata);
					if(json==NULL) return NULL;

					Value* item = JSON_GetObjectItem(json, "issuer");
					char* issuer = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;
					oidcProvider->issuer=shdata_32BitString_copy(sheap,issuer);

					item = JSON_GetObjectItem(json, "authorization_endpoint");
					char* authorizationEndpoint = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;
					oidcProvider->authorizationEndpoint=shdata_32BitString_copy(sheap,authorizationEndpoint);

					item = JSON_GetObjectItem(json, "token_endpoint");
					char* tokenEndpoint = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;
					oidcProvider->tokenEndpoint=shdata_32BitString_copy(sheap,tokenEndpoint);

					item = JSON_GetObjectItem(json, "jwks_uri");
					char* jwksUri = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;
					oidcProvider->jwksUri=shdata_32BitString_copy(sheap,jwksUri);

					// download JWT verification keys from url
					if(oidcProvider->jwksUri!=NULL) {
						http_util_result* httpResult=hc_get_verbose(p, oidcProvider->jwksUri, 10, NULL, NULL, error);
						if(!hc_is200_OK(httpResult)) {
							if(error!=NULL) { *error = apr_pstrdup(p, "jwsUri response and cache file both failed"); }
							apr_pool_destroy (subp);
							return NULL;
						}
						jwksJson = httpResult->data;
					}
				} else {
					oidcProvider->issuer=shdata_32BitString_copy(sheap, oidcProviderX->issuer);
					oidcProvider->authorizationEndpoint=shdata_32BitString_copy(sheap,oidcProviderX->authorizationEndpoint);
					oidcProvider->tokenEndpoint=shdata_32BitString_copy(sheap,oidcProviderX->tokenEndpoint);
					oidcProvider->jwksUri=shdata_32BitString_copy(sheap,oidcProviderX->jwksUri);
					// download JWT verification keys from url
					if(oidcProvider->jwksUri!=NULL) {

						http_util_result* httpResult=hc_get_verbose(p, oidcProvider->jwksUri, 10, NULL, NULL, error);
						if(!hc_is200_OK(httpResult)) {
							if(error!=NULL) { *error = apr_pstrdup(p, "jwsUri response and cache file both failed"); }
							apr_pool_destroy (subp);
							return NULL;
						}
						jwksJson = httpResult->data;
					} else {
						jwksJson = shdata_32BitString_copy(sheap,oidcProviderX->jwksJson);
					}
				}

				if(jwksJson!=NULL) {
					Value* json = 	JSON_Parse(p, jwksJson);
					if(json==NULL) {
						if(error!=NULL) { *error = apr_pstrdup(p, "jwsUri response parsing failed"); }
						apr_pool_destroy (subp);
						return NULL;
					}

					Value* array = JSON_GetObjectItem(json, "keys");
					if(array==NULL||JSON_GetItemType(array)!=JSON_Array) {
						if(error!=NULL) { *error = apr_pstrdup(p, "keys object is not array"); }
						apr_pool_destroy (subp);
						return NULL;
					}

					int	arrSz = JSON_GetArraySize(array);
					oidcProvider->jwsKeys=shapr_hash_make(sheap);

					// Retrieve item number "item" from array "array". Returns NULL if unsuccessful.
					for (i=0; i<arrSz; i++) {

						oauth_jwskey* jwsKey=(oauth_jwskey*)shdata_shpcalloc(sheap,sizeof(oauth_jwskey));

						Value* element = JSON_GetArrayItem(array, i);
						Value* keyIDObj = JSON_GetObjectItem(element, "kid");
						const char* keyID = (keyIDObj) ? JSON_GetStringFromStringItem(keyIDObj) : NULL;
						jwsKey->id = shdata_32BitString_copy(sheap,keyID);

						Value* val = JSON_GetObjectItem(element, "kty");
						char* type = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
						jwsKey->type=shdata_32BitString_copy(sheap,type);

						val = JSON_GetObjectItem(element, "alg");
						char* algorithm = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
						jwsKey->algorithm=shdata_32BitString_copy(sheap, algorithm);

						val = JSON_GetObjectItem(element, "use");
						char* use = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
						jwsKey->use=shdata_32BitString_copy(sheap, use);

						val = JSON_GetObjectItem(element, "n");
						char* modulus = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
						jwsKey->modulus=shdata_32BitString_copy(sheap, modulus);

						val = JSON_GetObjectItem(element, "e");
						char* exponent = (val) ? (char*)JSON_GetStringFromStringItem(val) : NULL;
						jwsKey->exponent=shdata_32BitString_copy(sheap, exponent);

						shapr_hash_set(sheap,oidcProvider->jwsKeys,jwsKey->id,APR_HASH_KEY_STRING,jwsKey);

					}

				}

				shapr_hash_set(sheap,ret->oidcProviderHash,oidcProvider->issuer,APR_HASH_KEY_STRING,oidcProvider);
				if(ret->oidcProvider==NULL) { // set the first valid one
					ret->oidcProvider = oidcProvider;
				}else if(oidcProvider->isDefault) { // override from default
					ret->oidcProvider = oidcProvider;
				}
			}
		}

		ret->rpSession=
			cookie_cookieShmDup(sheap,axml->rpSession);
		ret->oidcSession=
			cookie_cookieShmDup(sheap,axml->oidcSession);

		am_copyRelyingsParties(p, sheap, axml->relyingPartyHash,ret->relyingPartyHash);

		shdata_CloseItemTagWithInfo(sheap,"Action Mappings");
		apr_pool_destroy(subp);
		
		return result;
	}
	
	oidc_config* am_fetchFromSheap(shared_heap* sheap){
		return (oidc_config*)shdata_getItem(sheap,	SHEAP_ITEM_ID_AUTHZ_OIDC);
	}

	static int am_isHeaderMatched(pool*p, match_list_header* hdr, char*header){
		array_header* matchHeaderValues=NULL, *headerValues=NULL;
		int isRegex=hdr->isRegex;
		int negate=hdr->negate;
		int hasDelim=(hdr->delimAnd==NULL)?FALSE:TRUE;
		int isHeaderMatch=FALSE;
		
		if(hdr->value==NULL) return FALSE;
		
		if(header==NULL){
			if(strcasecmp(hdr->value,"nil")==0) {
				return TRUE;
			}else {
				return FALSE;
			}
		}
		isHeaderMatch=matchList_isMatched(p,hdr->value, header, isRegex);
		
		if(hasDelim){
			matchHeaderValues=cu_parseStringArrayFromCsv(p, 4, hdr->delimAnd, hdr->value);
			headerValues=cu_parseStringArrayFromCsv(p, 4, hdr->delimAnd, header);		
			if(matchHeaderValues==NULL||headerValues==NULL) return FALSE;
		}
		if(negate==FALSE){
			if(!hasDelim&&isHeaderMatch||(hasDelim&&ml_isSubsetFound(p,matchHeaderValues,headerValues,isRegex))){
				return TRUE;
			}
		}else{
			if(!hasDelim&&isHeaderMatch==FALSE||(hasDelim&&ml_isNegateSubsetFound(p,matchHeaderValues,headerValues,isRegex))){
				return TRUE;
			}
		}

		return FALSE;
	}	
	static int am_isIpMatched(pool*p, match_ip* matchIp, char*ip){
		int isIpMatch;
		
		if(matchIp==NULL||matchIp->ip==NULL||ip==NULL) return TRUE;	
		
		isIpMatch=matchList_isMatched(p,matchIp->ip, ip, matchIp->isRegex);
		if(matchIp->negate==TRUE){isIpMatch=!isIpMatch;}
		
		return isIpMatch;
	}
	static int am_isPathMatched(pool*p, match_path* matchPath, char*path){
		int isPathMatch;
		
		if(matchPath==NULL||matchPath->path==NULL||path==NULL) return TRUE;	
		
		isPathMatch=(rc_matchByStringsReturnDetails(p,matchPath->path,path)==NULL);
		if(matchPath->negate==TRUE){isPathMatch=!isPathMatch;}
		
		return isPathMatch;
	}

	static int am_isEventScheduled(pool*p, match_event* e){
		int i;
		time_t currentTime=time(NULL);
		
		//No event configured
		if(e==NULL) return TRUE;
		
		if(( e->start < currentTime ) && ( currentTime < ( (e->end>0) ? e->end : TIME_MAX) ) ) {
			return TRUE;
		}

		return FALSE;
	}
	
	match_list_match* am_isMatchListMatch(pool* p, match_list* matchlist, char* path, char* ip,apr_table_t *headers_in,apr_table_t* subprocess_env){
		int i=0,j=0;
		char* header=NULL;
		//match_list_match_nvp* nvp=NULL;
		match_list_header* matchHeader=NULL;
		match_list_match* ret=NULL;
		
		for(i=0;i<matchlist->list->nelts;i++){
			ret=(match_list_match*)cu_getElement(matchlist->list,i);
			//verify regex
			if(matchList_isHostMatched(p, ret->host, headers_in)){
				if(am_isEventScheduled(p,ret->event)){
					if(am_isPathMatched(p,ret->path,path)){
						if(am_isIpMatched(p,ret->ip,ip)){
							//now verify headers
							if(ret->headerList!=NULL&&ret->headerList->nelts>0) { //need to match headers
								if(headers_in==NULL||apr_is_empty_table(headers_in)){ //no headers to match
									return NULL;
								}else{ //match headers
									int cascade = ret->cascade;
									for(j=0;j<ret->headerList->nelts;j++){
										matchHeader=(match_list_header*)cu_getElement(ret->headerList,j);
										header=(char*)apr_table_get(headers_in,matchHeader->name);
										if(am_isHeaderMatched(p,matchHeader,header)==FALSE){
											ret = NULL;
											break;
										}
									}
									/*
									 * Bug: As soon as any match headers failed to match
									 * above for loop used to return NULL from this function
									 * For backward compatibility, this bug is kept asis
									 * And can be triggered by setting by <match cascade="false"> tag
									 * in runtime.xml
									 * Fix: Cascade would allow next match to be matched
									 * if current match is failed to match.
									 */
									if ( cascade==TRUE && ret==NULL ) { continue; }

									return ret;
								}
							}else{
								return ret;
							}
						}
					}
				}
			}
		}
		return NULL;
	}
	static match_list_match* am_isMatchListsMatch(pool* p, array_header* matchLists, char* path, char* ip,apr_table_t *headers_in,apr_table_t* subprocess_env){
		match_list* list=NULL;
		int i=0;
		
		match_list_match* ret=NULL;
		
		if(matchLists==NULL||matchLists->nelts==0){return NULL;}
		
		for(i=0;i<matchLists->nelts;i++){
			list=(match_list*)cu_getElement(matchLists,i);
			ret=am_isMatchListMatch(p,list,path,ip,headers_in,subprocess_env);
			if(ret!=NULL){return ret;}
		}
		
		return NULL;
	}
	static path_mapping* am_getPathMapping(pool* p,array_header* pgmaps,char* path,char* ip, apr_table_t* headers, apr_table_t* subprocess_env){
		path_mapping* pmap=NULL;
		int x=0;
		if(pgmaps==NULL||path==NULL){return NULL;}
		
		for(x=0;x<pgmaps->nelts;x++){
			pmap=(path_mapping*)cu_getElement(pgmaps,x);
			if(rc_matchByStrings(p, pmap->pathRegex, path)==0
				||(pmap->ignoreCase==TRUE&&(rc_matchByStringsIgnoreCase(p, pmap->pathRegex, path)==0)) ){
				if(pmap->matchLists==NULL||pmap->matchLists->nelts==0){
					return pmap;
				}else if(am_isMatchListsMatch(p,pmap->matchLists,path,ip,headers,subprocess_env)!=NULL){
					return pmap;
				}
			}
		}
		
		return NULL;
	}
	
	page_action* am_getMatchingPageAction(pool* p,array_header* pmactions,char* path,char* ip, apr_table_t* headers, apr_table_t* subprocess_env){
			pathmapping_action* pmaction=NULL;
			int x=0;
			if(pmactions==NULL||path==NULL){return NULL;}
			
			for(x=0;x<pmactions->nelts;x++){
				pmaction=(pathmapping_action*)cu_getElement(pmactions,x);
				if(pmaction->matchList==NULL){
					return pmaction->action;
				}else if(am_isMatchListMatch(p,pmaction->matchList,path,ip,headers,subprocess_env)!=NULL){
					return pmaction->action;
				}
			}
			return NULL;
		}	

	path_mapping* am_getPathMapping_PostAuth(pool* p,oidc_config* actmap,char* path,char* ip, apr_table_t* headers, apr_table_t* subprocess_env){
		if(actmap==NULL||actmap->path_mappings==NULL) return NULL;
		return am_getPathMapping(p,actmap->path_mappings->postauth,path,ip,headers,subprocess_env);
	}

#define OAUTH_TOKEN_WILDCARDNULL(str) (str!=NULL?str:"*")
#define OAUTH_TOKEN_URLENCODE_WILDCARDNULL(p, str) (str!=NULL?url_encode2(p,str):"*")

oauth_jwt_header* oauthutil_newJWTHeaderObj(pool* p) {
	return (oauth_jwt_header*)apr_pcalloc(p, sizeof(oauth_jwt_header));
}

const char* oauthutil_serializeJWTHeader(pool* p, oauth_jwt_header* hdr) {
	Value* json = JSON_CreateObject(p);
	JSON_AddStringToObject(p, json, "alg", hdr->algorithm);
	JSON_AddStringToObject(p, json, "typ", (hdr->type!=NULL) ? hdr->type : "JWT");
	if(hdr->keyID!=NULL) {
		JSON_AddStringToObject(p, json, "kid", hdr->keyID);
	}
	char* headerJson = JSON_SerializeUnformatted(p, json);

	unsigned char encodedHeader[OAUTH_BASE64_BUFSIZE];
	memset(encodedHeader, '\0', OAUTH_BASE64_BUFSIZE);
	base64Url_encode(encodedHeader, headerJson, strlen(headerJson));

	return apr_pstrdup(p, encodedHeader);
}

oauth_jwt_header* oauthutil_deserializeJWTHeader(pool* p, char* encodedHeader) {
	Value* json, *item;
	oauth_jwt_header* header;

	unsigned char headerJson[OAUTH_BASE64_BUFSIZE];
	memset(headerJson, '\0', OAUTH_BASE64_BUFSIZE);
	base64Url_decode(headerJson, encodedHeader, strlen(encodedHeader));

	json = 	JSON_Parse(p, headerJson);
	if(json==NULL) return NULL;

	item = JSON_GetObjectItem(json, "alg");

	header = oauthutil_newJWTHeaderObj(p);
    header->algorithm = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;

	item = JSON_GetObjectItem(json, "kid");
    header->keyID = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) : NULL;

	item = JSON_GetObjectItem(json, "typ");
    header->type = (item!=NULL) ? (char*)JSON_GetStringFromStringItem(item) :  NULL;

    return header;
}

 oauth_jwt_claim* oauthutil_newJWTClaimObj(pool* p) {
	return (oauth_jwt_claim*)apr_pcalloc(p, sizeof(oauth_jwt_claim));
}

const char* oauthutil_serializeJWTClaim(pool* p, oauth_jwt_claim* claim) {
	Value* json = JSON_CreateObject(p);
	if(claim->issuer!=NULL) {
		JSON_AddStringToObject(p, json, "iss", claim->issuer);
	}
	if(claim->scope!=NULL) {
		JSON_AddStringToObject(p, json, "scope", claim->scope);
	}
	if(claim->subject!=NULL) {
		JSON_AddStringToObject(p, json, "sub", claim->subject);
	}
	if(claim->audience!=NULL) {
		JSON_AddStringToObject(p, json, "aud", claim->audience);
	}
	if(claim->expiry>0) {
		JSON_AddNumberToObject(p, json, "exp", claim->expiry);
	}
	if(claim->issuedAt>0){
		JSON_AddNumberToObject(p, json, "iat", claim->issuedAt);
	}
	if(claim->auth_time>0){
		JSON_AddNumberToObject(p, json, "auth_time", claim->auth_time);
	}
	if(claim->options!=NULL) {
		apr_hash_index_t *hi;
		char* name=NULL,*value=NULL;
		for (hi = apr_hash_first(p, claim->options); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi,(const void**)&name, NULL, (void**)&value);
			JSON_AddStringToObject(p, json, name, value);
		}
	}

	if(claim->roles!=NULL){
		int i;
		Value* rolesArray = JSON_CreateArray(p);
		JSON_AddItemToObject(p, json, "roles", rolesArray);
		for(i=0;i<claim->roles->nelts;i++){
			char* roleName = (char*)cu_getElement(claim->roles, i);
			if(roleName!=NULL) {
				JSON_AddItemToArray(p, rolesArray, JSON_CreateString(p, roleName));
			}
		}
	}
	char* claimJson = JSON_SerializeUnformatted(p, json);

	unsigned char encodedClaim[OAUTH_BASE64_BUFSIZE];
	memset(encodedClaim, '\0', OAUTH_BASE64_BUFSIZE);
	base64Url_encode(encodedClaim, claimJson, strlen(claimJson));

	return apr_pstrdup(p, encodedClaim);
}

static void oauthutil_itemCallback(Value* item, void* data) {
	oauth_jwt_claim* claim = (oauth_jwt_claim*)data;

	const char* name = (item!=NULL) ? JSON_GetItemString(item) : NULL ;
	if(name==NULL) return;

	if(JSON_GetItemType(item)==JSON_Number) {
		if(strcmp(name,"exp")==0) {
			claim->expiry = JSON_GetNumberFromNumberItem(item);
		}else if(strcmp(name,"iat")==0) {
			claim->issuedAt = JSON_GetNumberFromNumberItem(item);
		}
	}else if(JSON_GetItemType(item)==JSON_String) {// string
		if(strcmp(name,"iss")==0) {
			claim->issuer = (char*)JSON_GetStringFromStringItem(item);
		}else if(strcmp(name,"scope")==0) {
			claim->scope = (char*)JSON_GetStringFromStringItem(item);
		}else if(strcmp(name,"sub")==0) {
			claim->subject = (char*)JSON_GetStringFromStringItem(item);
		}else if(strcmp(name,"aud")==0) {
			claim->audience = (char*)JSON_GetStringFromStringItem(item);
		}else{
			apr_hash_set(claim->options,name, APR_HASH_KEY_STRING, JSON_GetStringFromStringItem(item));
		}
	}else if(JSON_GetItemType(item)==JSON_Array) {// string
		int i;
		if(strcmp(name,"roles")==0) {
			char** place, *role;

			int count = JSON_GetArraySize(item);
			for (i=0; i < count; i++){
				Value* el = JSON_GetArrayItem(item, i);
				if (el!=NULL&&JSON_GetItemType(el)==JSON_String) {
					role = (char*)JSON_GetStringFromStringItem(el);
					if(role!=NULL){
						place=(char**)apr_array_push(claim->roles);
						*place=role;
					}
				}
			}
		}
	}
}

oauth_jwt_claim* oauthutil_deserializeJWTClaim(pool* p, char* encodedClaim) {
	Value* json, *item;
	oauth_jwt_claim* claim;

	unsigned char claimJson[OAUTH_BASE64_BUFSIZE];
	memset(claimJson, '\0', OAUTH_BASE64_BUFSIZE);
	base64Url_decode(claimJson, encodedClaim, strlen(encodedClaim));

	json = 	JSON_Parse(p, claimJson);
	if(json==NULL) return NULL;

	claim = oauthutil_newJWTClaimObj(p);
	claim->options = apr_hash_make(p);
	claim->expiry = -1;
	claim->issuedAt = -1;
	claim->roles = apr_array_make(p,8,sizeof(char*));

	JSON_IterateObjectItemCallback(json, claim, oauthutil_itemCallback);

    return claim;
}

oauth_jwt_claim* oauthutil_deserializeJWTClaimNoDecoding(pool* p, char* claimJson) {
	Value* json, *item;
	oauth_jwt_claim* claim;

	if(claimJson==NULL) return NULL;

	json = 	JSON_Parse(p, claimJson);
	if(json==NULL) return NULL;

	claim = oauthutil_newJWTClaimObj(p);
	claim->options = apr_hash_make(p);
	claim->expiry = -1;
	claim->issuedAt = -1;
	claim->roles = apr_array_make(p,8,sizeof(char*));

	JSON_IterateObjectItemCallback(json, claim, oauthutil_itemCallback);

    return claim;
}

static const char* oauthutil_generateJWTSignature(pool*p, const char* algorithm, unsigned char* secretKey, char* payload) {
		char* error = NULL;
		const char* signature = NULL;

	    if(strcasecmp(algorithm,"HS256")==0){
	    		signature = comu_generateHS256Signature(p, payload, secretKey, &error);
	    } else if(strcasecmp(algorithm,"RS256")==0){
    			signature = comu_rsa256Sign(p, payload, strlen(payload), secretKey, &error);
	    }

	    return signature;
	}

oauth_jwt* oauthutil_newJWTObj(pool* p) {
	return (oauth_jwt*)apr_pcalloc(p, sizeof(oauth_jwt));
}

static int oauthutil_verifyJWTSignature(pool*p, const char* algorithm, unsigned char* secretKey, char* payload, char* encodedSignature) {
		char* error = NULL;
		int verified = FALSE;

	    if(secretKey==NULL||payload==NULL) return FALSE;

	    //Generate signature
	    if(strcasecmp(algorithm,"HS256")==0){
	    		verified = comu_verifyHS256Signature(p, payload, encodedSignature, secretKey, &error);
	    }else	 if(strcasecmp(algorithm,"RS256")==0){
    			verified = comu_rsa256Verify(p, payload,strlen(payload),secretKey, encodedSignature, &error);
	    }

	    return verified;
	}

const char* oauthutil_serializeJWT(pool*p, oauth_jwt* jwt, const char* secretKey) {

	if(jwt==NULL||jwt->header==NULL||jwt->claim==NULL)	return NULL;

	const char* encodedHeader = oauthutil_serializeJWTHeader(p, jwt->header);
	const char* encodedClaim = oauthutil_serializeJWTClaim(p, jwt->claim);

	// generate JWT
	if(encodedHeader==NULL||encodedClaim==NULL) return NULL;

	char* payload = apr_pstrcat(p, encodedHeader, ".", encodedClaim, NULL);

	const char* signature = oauthutil_generateJWTSignature(p, jwt->header->algorithm, (unsigned char*)secretKey, payload);

	return apr_pstrcat(p, payload, ".", signature, NULL);
}

oauth_jwt* oauthutil_parseAndValidateJWT(pool* p, const char* src, getClientSecretKeyByClientId_func getClientSecretKeyByClientIdFunc, void* data) {
	char* srccpy = NULL;
	char* token, *last, *payload;
	char* encodedHeader = NULL;
	char* encodedClaim = NULL;
	int verified;

	oauth_jwt* jwt = oauthutil_newJWTObj(p);


	if (src == NULL)	return NULL;

	srccpy = apr_pstrdup(p, src);

	token = apr_strtok(srccpy, ".", &last);
	if (token != NULL) {
		// header
		encodedHeader = token;
		jwt->header = oauthutil_deserializeJWTHeader(p, encodedHeader);
		if(jwt->header==NULL||jwt->header->algorithm==NULL) return NULL;

		// claim
		token = apr_strtok(NULL, ".", &last);
		if (token != NULL) {
			encodedClaim = token;
			jwt->claim = oauthutil_deserializeJWTClaim(p, encodedClaim);
			if(jwt->claim==NULL||jwt->claim->issuer==NULL) return NULL;
		} else {
			return NULL;
		}

		// signature
		token = apr_strtok(NULL, ".", &last);
		if (token != NULL) {
			jwt->signature = token;
		} else {
			return NULL;
		}

		if(getClientSecretKeyByClientIdFunc==NULL) return NULL;

		const char* secretKey = (*getClientSecretKeyByClientIdFunc)(p, jwt->claim->issuer, data);

//		printf("encodedHeader=%s, encodedClaim=%s encodedSignature=%s\r\n", encodedHeader, encodedClaim, jwt->signature);

    		payload = apr_pstrcat(p, encodedHeader, ".", encodedClaim, NULL);

	    verified = oauthutil_verifyJWTSignature(p, jwt->header->algorithm, (unsigned char*)secretKey, payload, jwt->signature);

	    if(verified==FALSE) return NULL;

	}

	return jwt;
}

void oauthutil_printJWT(pool* p, oauth_jwt* jwt) {
	if(jwt==NULL||jwt->header==NULL||jwt->claim==NULL)	return;

	if(jwt->header!=NULL) {
		printf("algorithm=%s\r\n", jwt->header->algorithm);
	}

	if(jwt->claim!=NULL) {
		if(jwt->claim->issuer!=NULL) {
			printf("issuer=%s\r\n", jwt->claim->issuer);
		}
		if(jwt->claim->scope!=NULL) {
			printf("scope=%s\r\n", jwt->claim->scope);
		}
		if(jwt->claim->subject!=NULL) {
			printf("subject=%s\r\n", jwt->claim->subject);
		}
		if(jwt->claim->audience!=NULL) {
			printf("audience=%s\r\n", jwt->claim->audience);
		}
		if(jwt->claim->expiry>0) {
			printf("expiry=%ld\r\n", jwt->claim->expiry);
		}
		if(jwt->claim->issuedAt>0) {
			printf("issuedAt=%ld\r\n", jwt->claim->issuedAt);
		}

		if(jwt->claim->options!=NULL) {
			apr_hash_index_t *hi;
			char* name=NULL,*value=NULL;
			for (hi = apr_hash_first(p, jwt->claim->options); hi; hi = apr_hash_next(hi)) {
				apr_hash_this(hi,(const void**)&name, NULL, (void**)&value);
				printf("%s=%s\r\n", name,value);
			}
		}

	}

	printf("signature = %s\r\n", jwt->signature);

}

// ID token ( openid) routines
// returns JWT formatted ID Token
const char* oauthutil_generateIDToken(pool* p, oauth_jwt_header* header, oauth_jwt_claim*  claim, const char* secretKey) {

	if(header==NULL || claim==NULL||secretKey==NULL) return NULL;

	oauth_jwt* jwt = oauthutil_newJWTObj(p);
	jwt->header = header;
	jwt->claim = claim;

	return oauthutil_serializeJWT(p, jwt, secretKey);
}

oauth_jwk* oauthutil_newJWKObj(pool *p){
	oauth_jwk* jwk=(oauth_jwk*)apr_pcalloc(p, sizeof(oauth_jwk));
	return jwk;
}

// parse JWT formatted ID Token
oauth_jwt* oauthutil_parseIDToken(pool* p, const char* src, char** payloadP, char** error){

	char* srccpy = NULL;
	char* token, *last;
	char* encodedHeader = NULL;
	char* encodedClaim = NULL;

	if (src == NULL)	{
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token is null"); }
		return NULL;
	}

	srccpy = apr_pstrdup(p, src);

	token = apr_strtok(srccpy, ".", &last);
	if(token==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.header is null"); }
		return NULL;
	}

	oauth_jwt* jwt = oauthutil_newJWTObj(p);

	// header
	encodedHeader = token;
	jwt->header = oauthutil_deserializeJWTHeader(p, encodedHeader);

	// claim
	token = apr_strtok(NULL, ".", &last);
	if (token != NULL) {
		encodedClaim = token;
		jwt->claim = oauthutil_deserializeJWTClaim(p, encodedClaim);
	} else {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.claim is null"); }
		return NULL;
	}

	// signature
	token = apr_strtok(NULL, ".", &last);
	if (token != NULL) {
		jwt->signature = token;
	} else {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.signature is null"); }
		return NULL;
	}

	if(payloadP!=NULL) { *payloadP = apr_pstrcat(p, encodedHeader, ".", encodedClaim, NULL); }

//	printf("encodedHeader=%s, encodedClaim=%s encodedSignature=%s\r\n", encodedHeader, encodedClaim, jwt->signature);

	return jwt;

}

// validates JWT formatted ID Token
oauth_jwt* oauthutil_parseAndValidateIDToken(pool* p, const char* src, getJSONWebKey_func getJSONWebKeyFunc, void* data, char** error){
	char* payload = NULL;

	oauth_jwt* jwt = oauthutil_parseIDToken(p, src, &payload, error);
	if(jwt==NULL||payload==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token parsing failed"); }
		return NULL;
	}

	if(jwt->header==NULL||jwt->header->algorithm==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.header is null"); }
		return NULL;
	}

	// claim
	if(jwt->claim==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.claim is null"); }
		return NULL;
	}

	if(jwt->claim->issuer==NULL||jwt->claim->audience==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.claim audience or issuer null"); }
		return NULL;
	}

	// validate claim expiry
	if(jwt->claim->expiry>0&&jwt->claim->expiry<apr_time_sec(apr_time_now())) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.claim expired"); }
		return NULL;
	}

	// signature
	if(jwt->signature==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.signature is null"); }
		return NULL;
	}

	if(getJSONWebKeyFunc==NULL) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.webkey function is null"); }
		return NULL;
	}

	oauth_jwk* jwk = (*getJSONWebKeyFunc)(p, jwt->header, jwt->claim->issuer, jwt->claim->audience, data, error);
	if(jwk==NULL) return NULL;

	int verified=FALSE;
	if(strcasecmp(jwt->header->algorithm,"HS256")==0){
		verified = comu_verifyHS256Signature(p, payload, jwt->signature, jwk->key, error);
	}else	 if(strcasecmp(jwt->header->algorithm,"RS256")==0){
		if(jwk->modulus!=NULL&&jwk->exponent!=NULL) {
			verified = comu_rsaVerifyByModulus(p, jwt->header->algorithm, payload,strlen(payload), jwk->modulus, jwk->exponent, jwt->signature, error);
		}else if(jwk->key!=NULL) {
			verified = comu_rsa256Verify(p, payload,strlen(payload), jwk->key, jwt->signature, error);
		}
	}

	if(verified==FALSE) {
		if(error!=NULL) { *error = apr_pstrdup(p, "id_token.signature failed"); }
		return NULL;
	}

	return jwt;

}

const char* oauthutil_serializeJWTClaimNoEncoding(pool* p, oauth_jwt_claim* claim) {
	Value* json = JSON_CreateObject(p);
	if(claim->issuer!=NULL) {
		JSON_AddStringToObject(p, json, "iss", claim->issuer);
	}
	if(claim->scope!=NULL) {
		JSON_AddStringToObject(p, json, "scope", claim->scope);
	}
	if(claim->subject!=NULL) {
		JSON_AddStringToObject(p, json, "sub", claim->subject);
	}
	if(claim->audience!=NULL) {
		JSON_AddStringToObject(p, json, "aud", claim->audience);
	}
	if(claim->expiry>0) {
		JSON_AddNumberToObject(p, json, "exp", claim->expiry);
	}
	if(claim->issuedAt>0){
		JSON_AddNumberToObject(p, json, "iat", claim->issuedAt);
	}

	if(claim->options!=NULL) {
		apr_hash_index_t *hi;
		char* name=NULL,*value=NULL;
		for (hi = apr_hash_first(p, claim->options); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi,(const void**)&name, NULL, (void**)&value);
			JSON_AddStringToObject(p, json, name, value);
		}
	}
	return JSON_SerializeUnformatted(p, json);
}

// prints JWT formatted ID Token
void oauthutil_printIDToken(pool* p, oauth_jwt* IDToken){
	oauthutil_printJWT(p, IDToken);
}

static void am_printMatchList(pool* p, array_header* arr){
	int i=0, j=0;
	match_list_match* match=NULL;
	match_list_header* hdr=NULL;
	match_list_env* env=NULL;
	if(arr!=NULL&&arr->nelts>0){
		printf("\r\n\t\t -- MatchList[%d]",arr->nelts);
		for(i=0;i<arr->nelts;i++){
			match=(match_list_match*)cu_getElement(arr,i);
			printf("\r\n\t>\t");
			if(match->host!=NULL){
				printf("Host: %s ",match->host);
			}
			if(match->ip!=NULL&&match->ip->ip!=NULL){
				printf("IP: %s ",match->ip->ip);
				printf("\tisregex: %s ",BOOLTOSTR(match->ip->isRegex));
				printf("\tnegate: %s ",BOOLTOSTR(match->ip->negate));
				printf("\n");
			}
			if(match->headerList!=NULL&&match->headerList->nelts>0){
				printf("Headers [%d]",match->headerList->nelts);
				for(j=0;j<match->headerList->nelts;j++){
					hdr=(match_list_header*)cu_getElement(match->headerList,j);
					printf("\r\n\t\t\t %s = %s",hdr->name,hdr->value);
					if(hdr->delimAnd) printf("\r\n\t\t\t delimAnd = \"%s\"",hdr->delimAnd);
					printf("\tisregex: %s ",BOOLTOSTR(hdr->isRegex));
					printf("\tnegate: %s ",BOOLTOSTR(hdr->negate));
					printf("\n");
				}
			}
			printf("\r\n");
		}
	}

}

void am_printAll(pool* p, oidc_config* oidcConfig){
	int x=0, i=0;
	page_action* pa=NULL;
	shapr_hash_index_t * hi=NULL;
	void *val=NULL;
	const void *key=NULL;

	match_list* mlist=NULL;
	char* includeXml=NULL;

	printf("<OIDC Configuration>\r\n");

	printf("Page Actions (%d)\r\n",shapr_hash_count (oidcConfig->page_actions));
	for (hi = shapr_hash_first(p,oidcConfig->page_actions); hi; hi = shapr_hash_next(hi)) {
			shapr_hash_this(hi, &key, NULL, &val);
			printf("\t* %s",key);
			if(val!=NULL){
				pa=(page_action*)val;
				if(pa->uri!=NULL){
					printf(",{uri:%s",pa->uri);
				}
				if(pa->handler_internal!=NULL){
					printf(",handler:%s",pa->handler_internal);
				}
				printf(", isForward:%d,description:%s}",pa->isForward,pa->description);
				if(pa->requestHeaders!=NULL&&pa->requestHeaders->nelts>0){
					printf("\r\n\t\t>Request headers [%d]\n", pa->requestHeaders->nelts);
					for (i=0; i < pa->requestHeaders->nelts; i++){
						action_header* hdr =
							(action_header*)cu_getElement(pa->requestHeaders, i);
						printf("\t\t\tHeader{name:%s, value:%s}\r\n", hdr->name, (hdr->value)?hdr->value:"null");
					}
				}
				if(pa->responseHeaders!=NULL&&pa->responseHeaders->nelts>0){
					printf("\r\n\t\t>Response headers [%d]\n", pa->responseHeaders->nelts);
					for (i=0; i < pa->responseHeaders->nelts; i++){
						action_header* hdr =
							(action_header*)cu_getElement(pa->responseHeaders, i);
						printf("\t\t\tHeader{name:%s, value:%s}\r\n", hdr->name, (hdr->value)?hdr->value:"null");
					}
				}
			}
			printf("\r\n");
	}
	printf("Match Lists (%d):\r\n",shapr_hash_count (oidcConfig->match_lists));
	for(hi = shapr_hash_first(p,oidcConfig->match_lists); hi; hi = shapr_hash_next(hi)){
		shapr_hash_this(hi, &key, NULL, &val);
		mlist=(match_list*)val;
		printf("\t* %s",mlist->name);
		if(mlist->list->nelts>0){
			am_printMatchList(p,mlist->list);
		}
		printf("\r\n");
	}

	if(oidcConfig->oidcProvider!=NULL) {
		printf("Metadataurl: %s\r\n",oidcConfig->oidcProvider->metadataUrl);
		printf("Issuer: %s\r\n",oidcConfig->oidcProvider->authorizationEndpoint);
		printf("JWKSUri: %s\r\n",oidcConfig->oidcProvider->jwksUri);
		printf("JWKSKeys (%d):\r\n",shapr_hash_count (oidcConfig->oidcProvider->jwsKeys));
		for(hi = shapr_hash_first(p,oidcConfig->oidcProvider->jwsKeys); hi; hi = shapr_hash_next(hi)){
			shapr_hash_this(hi, &key, NULL, &val);
			oauth_jwskey* jwk=(oauth_jwskey*)val;
			printf("\t\r\nkid=%s",jwk->id);
			printf("\t\t\r\n* type=%s",jwk->type);
			printf("\t\t\r\n* algorithm=%s",jwk->algorithm);
			printf("\t\t\r\n* use=%s",jwk->use);
			printf("\t\t\r\n* modulus=%s",jwk->modulus);
			printf("\t\t\r\n* exponent=%s",jwk->exponent);
			printf("\r\n");
		}
	}

	if(oidcConfig->relyingPartyHash!=NULL) {
		printf("RelyingParties (%d):\r\n",shapr_hash_count (oidcConfig->relyingPartyHash));
		for(hi = shapr_hash_first(p,oidcConfig->relyingPartyHash); hi; hi = shapr_hash_next(hi)){
			shapr_hash_this(hi, &key, NULL, &val);
			relying_party* relyingRarty=(relying_party*)val;
			printf("\t\r\nclientID=%s",relyingRarty->clientID);
			printf("\t\t\r\n* clientSecret=%s",relyingRarty->clientSecret);
			printf("\t\t\r\n* description=%s",relyingRarty->description);
			printf("\r\n");
		}
	}

}

oauth_jwskey* am_getJWSKeyByKeyID(shapr_hash_t* keyHash, char* keyID) {
	if(keyHash==NULL || keyID==NULL) {return NULL;}

	return (oauth_jwskey*)shapr_hash_get(keyHash, keyID, APR_HASH_KEY_STRING);
}

relying_party* am_getRelyingPartyByClientID(shapr_hash_t* relyingPartyHash, const char* clientID) {

	if (relyingPartyHash==NULL || clientID==NULL) return NULL;

	return (relying_party*)shapr_hash_get(relyingPartyHash, clientID, APR_HASH_KEY_STRING);
}

relying_party* am_getRelyingPartyByRedirectUri(pool*p, shapr_hash_t* relyingPartyHash, const char* currentRedirectUri) {
	shapr_hash_index_t * hi=NULL;
	void *val=NULL;
	const void *key=NULL;

	if (relyingPartyHash==NULL || currentRedirectUri==NULL) return NULL;

	relying_party* defaultRelyingParty=NULL;
	for(hi = shapr_hash_first(p, relyingPartyHash); hi; hi = shapr_hash_next(hi)){
		shapr_hash_this(hi, &key, NULL, &val);
		relying_party* relyingParty=(relying_party*)val;
		if(defaultRelyingParty==NULL) { defaultRelyingParty = relyingParty ; } // save the first one
		if(relyingParty!=NULL&&relyingParty->redirectUri!=NULL) {
			if(strstr(currentRedirectUri, relyingParty->redirectUri)!=0) {
				return relyingParty;
			}
		}
	}

	return defaultRelyingParty;
}

oidc_provider* am_getOidcProviderByIssuer(shapr_hash_t* oidcProviderHash, const char* issuer) {

	if (oidcProviderHash==NULL || issuer==NULL) return NULL;

	return (oidc_provider*)shapr_hash_get(oidcProviderHash, issuer, APR_HASH_KEY_STRING);
}
