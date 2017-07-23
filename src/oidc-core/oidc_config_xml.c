#include <xml_core.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <common_utils.h>
#include <oidc-core/oidc_config_xml.h>
#include <oidc-core/rewrite_core.h>
#include <oidc-core/match_list.h>

#define CONST_INIT_PAGE_ACTIONS_ELTS		4
#define CONST_INIT_MATCH_LIST_ELTS			4


	typedef struct actmap_tmp{
		oidc_config_xml* conf;
		void* tmp;
		void* tmp2;
		void* tmp3;
		void* tmp4;
		void* tmp5;
		void* tmp6;
		void* tmp7;
		void* tmp8;
		void* tmp9;
		void* tmp10;
		void* tmp11;
		void* tmp12;
		void* tmp13;
		void* tmp14;
		char* str, *errorStr;
	}actmap_tmp;
	
	static int doc_uid=0;

	oidc_config_xml* amx_newObj(pool* p){
		oidc_config_xml* ret=apr_palloc(p,sizeof(oidc_config_xml));
		ret->uid=0;
		ret->page_actions_hash=apr_hash_make (p);
		ret->path_mappings_arr=apr_array_make (p,CONST_INIT_PAGE_ACTIONS_ELTS,sizeof(path_mapping_xml*));
		ret->match_list_arr=apr_array_make (p,CONST_INIT_MATCH_LIST_ELTS,sizeof(mlx_matchlist*));
		ret->rpSession=cookie_newObj(p);
		cookie_setCookieName(p, ret->rpSession, (char*)"rp_session");
		ret->oidcSession=cookie_newObj(p);
		cookie_setCookieName(p, ret->oidcSession, (char*)"oidc_session");
		ret->relyingPartyHash=apr_hash_make (p);
		ret->defaultRelyingParty=NULL;
		ret->oidcProvider=NULL;
		return ret;
	}
	static void amx_printPathMappingMatchList(pool* p, array_header* arr){
			int i=0;
			char* match=NULL;
			if(arr!=NULL&&arr->nelts>0){
				printf("\r\n\t\t -- MatchLists[%d]: ",arr->nelts);
				for(i=0;i<arr->nelts;i++){
					match=(char*)cu_getElement(arr,i);
					if(i!=0){printf(",");}
					printf("%s",match);
				}
			}
			
		}
	
	void amx_printActions(pool*p, char*type, array_header* actions){
		int i;
		if(actions!=NULL&&actions->nelts>0){
			printf("\t* %s={",type);
			for(i=0;i<actions->nelts;i++){
				pathmapping_action_xml* action=(pathmapping_action_xml*)cu_getElement(actions,i);
				if(i!=0){printf(",");}
				printf("id=%s matchList=%s",action->id,action->matchList);
			}
			printf("}\r\n");
		}
	}
	
	void amx_printAll(pool* p,oidc_config_xml* conf){
		int x=0, i=0;
		page_action_xml* pa=NULL;
		apr_hash_index_t * hi=NULL;
		void *val=NULL;
		const void *key=NULL;
		
		path_mapping_xml* pmx=NULL;
		mlx_matchlist* mlist=NULL;
		char* includeXml=NULL;
		
		printf("<OIDC Configuration XML>\r\n");
		
		printf("Page Actions (%d)\r\n",apr_hash_count (conf->page_actions_hash));
		for (hi = apr_hash_first(p,conf->page_actions_hash); hi; hi = apr_hash_next(hi)) {
				apr_hash_this(hi, &key, NULL, &val);
				printf("\t* %s",key);
				if(val!=NULL){
					pa=(page_action_xml*)val;
					printf("uri:%s",pa->uri);
					if(pa->handler!=NULL){
						printf(",handler:%s",pa->handler);
					}
					printf(", isForward:%d,description:%s}",pa->isForward,pa->description);
					if(pa->requestHeaders!=NULL&&pa->requestHeaders->nelts>0){
						printf("\r\n\t\t>Request headers [%d]\n", pa->requestHeaders->nelts);
						for (i=0; i < pa->requestHeaders->nelts; i++){
							action_header_xml* hdr = 
								(action_header_xml*)cu_getElement(pa->requestHeaders, i);
							printf("\t\t\tHeader{name:%s, value:%s}\r\n", hdr->name, (hdr->value)?hdr->value:"null");
						}
					}
					if(pa->responseHeaders!=NULL&&pa->responseHeaders->nelts>0){
						printf("\r\n\t\t>Response headers [%d]\n", pa->responseHeaders->nelts);
						for (i=0; i < pa->responseHeaders->nelts; i++){
							action_header_xml* hdr = 
								(action_header_xml*)cu_getElement(pa->responseHeaders, i);
							printf("\t\t\tHeader{name:%s, value:%s}\r\n", hdr->name, (hdr->value)?hdr->value:"null");
						}
					}
				}
				printf("\r\n");
		}
		printf("Match Lists (%d):\r\n",conf->match_list_arr->nelts);
		for(x=0;x<conf->match_list_arr->nelts;x++){
			mlist=(mlx_matchlist*)cu_getElement(conf->match_list_arr,x);
			printf("\t* %s",mlist->name);
			if(mlist->matches->nelts>0){
				ml_printMatchList(p,mlist->matches);
			}
			printf("\r\n");
		}
		
		
		printf("Path Mappings (%d):\r\n",conf->path_mappings_arr->nelts);
		for(x=0;x<conf->path_mappings_arr->nelts;x++){
			pmx=(path_mapping_xml*)cu_getElement(conf->path_mappings_arr,x);
			printf("\t* %s",pmx->pathRegex);
			if(pmx->ignoreCase==TRUE){ printf("\t* ignoreCase=true"); }
			if(pmx->postAuthActions!=NULL){
				//printf(", PostAuth:%s",pmx->postAuthAction);
				amx_printActions(p,"PostAuth", pmx->postAuthActions);
			}			
			amx_printPathMappingMatchList(p,pmx->matchLists);
			printf("\r\n");
		}

		if(conf->relyingPartyHash!=NULL) {
			printf("RelyingParties (%d):\r\n",apr_hash_count (conf->relyingPartyHash));
			for(hi = apr_hash_first(p,conf->relyingPartyHash); hi; hi = apr_hash_next(hi)){
				apr_hash_this(hi, &key, NULL, &val);
				relying_party_xml* relyingRarty=(relying_party_xml*)val;
				printf("\t\r\nclientID=%s",relyingRarty->clientID);
				printf("\t\t\r\n* clientSecret=%s",relyingRarty->clientSecret);
				printf("\t\t\r\n* description=%s",relyingRarty->description);
				printf("\t\t\r\n* domain=%s",relyingRarty->domain);
				printf("\r\n");
			}
		}

	}
	
	static page_action_xml* amx_newPageActionXml(pool* p){
		page_action_xml* ret;
		ret=apr_palloc(p,sizeof(page_action_xml));
		ret->id=NULL;
		ret->directory=NULL;
		ret->description=NULL;
		ret->isForward=1;
		ret->isPermanent=0;
		ret->isForbidden=0;
		ret->regex=NULL;
		ret->handler=NULL;
		ret->isDebug=0;
		ret->advancedTemplate=FALSE;
		ret->requestHeaders = apr_array_make(p, 1, sizeof(action_header_xml*));
		ret->responseHeaders = apr_array_make(p, 1, sizeof(action_header_xml*));
		ret->uri =NULL;
		ret->response = NULL;
		return ret;
	}
	
	static int amx_oidcConfigAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		//page_action_xml* pax=NULL;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		return 1;
	}

	static int amx_newPageAction(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		page_action_xml* pax=NULL;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		pax=(void*)amx_newPageActionXml(p);
		ctmp->tmp=pax;
		
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"id")==0){
				pax->id=apr_pstrdup(p,(char*)attributes[i + 1]);
				if(ctmp->conf->uid!=0){
					pax->id=apr_psprintf(p,"%s_%d",pax->id,ctmp->conf->uid);
				}
			}else if(strcmp(attributes[i],"debug")==0){
				pax->isDebug=STRTOBOOL((char*)attributes[i + 1]);				
			}
		}
		return 1;
	}
	static int amx_setPageActionId(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		if(pa!=NULL&&pa->id==NULL){
			pa->id=apr_pstrdup(p,body);
			if(ctmp->conf->uid!=0){
				pa->id=apr_psprintf(p,"%s_%d",pa->id,ctmp->conf->uid);
			}
		}
		return 1;
	}
	static int amx_setPageActionDescription(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->description=apr_pstrdup(p,body);
		return 1;
	}
	static int amx_setPageActionRegex(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->regex=apr_pstrdup(p,body);
		return 1;
	}
	static int amx_setPageActionHandler(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->handler=apr_pstrdup(p,body);
		return 1;
	}
	
	static int amx_setPageActionUri(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;

		if(pa!=NULL){
			pa->uri=apr_pstrdup(p,body);
		}
		
		return 1;
	}
	static int amx_setPageActionIsForward(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->isForward=strcmp(body,"true")==0?1:0;
		return 1;
	}
	static int amx_setPageActionIsPermanent(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->isPermanent=strcmp(body,"true")==0?1:0;
		return 1;
	}
	static int amx_setPageActionIsForbidden(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->isForbidden=strcmp(body,"true")==0?1:0;
		return 1;
	}	
	static int amx_setPageActionAdvancedTemplate(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		pa->advancedTemplate=STRTOBOOL(body);
		return 1;
	}
	static int amx_addPageAction(pool* p,char* xPath,int type,void* userdata){
		oidc_config_xml* amx=NULL;
			page_action_xml* pageact=NULL;
			actmap_tmp* ctmp=(actmap_tmp*)userdata;
			amx=(oidc_config_xml*)ctmp->conf;
			
			if(amx!=NULL&&ctmp->tmp!=NULL){
				pageact=(page_action_xml*)ctmp->tmp;
				apr_hash_set (amx->page_actions_hash,pageact->id,APR_HASH_KEY_STRING,ctmp->tmp);
			}
			ctmp->tmp=NULL;
			return 1;
	}
	
	//path mapping handlers
	static path_mapping_xml* amx_newPathMappingXml(pool* p){
		path_mapping_xml* ret;
		ret=apr_palloc(p,sizeof(path_mapping_xml));
		ret->pathRegex=NULL;
		ret->ignoreCase=FALSE;// Case sensitive by default
		ret->postAuthActions=apr_array_make(p,1,sizeof(pathmapping_action_xml*));
		ret->matchLists=apr_array_make(p,1,sizeof(char*));
		return ret;
	}

	static void amx_appendMatchListsToMatchListArray(pool*p,char* matchListsStr,int uniqueId,array_header*matchLists){
		array_header* arr;
		char* tmp,**pos;
		int i;
		
		if(matchListsStr==NULL)	return;
		arr=cu_parseStringArrayFromCsv(p,4,",",matchListsStr);
		if(arr==NULL||arr->nelts<1)	return;
		for(i=0;i<arr->nelts;i++){
			tmp=(char*)cu_getElement(arr,i);
			if(uniqueId!=0){tmp=apr_psprintf(p,"%s_%d",tmp,uniqueId);}
			pos=apr_array_push(matchLists);
			*pos=tmp;
		}
		return;
	}		
	static int amx_newPathMapping(pool* p,char* xPath,int type,const char ** attributes,void* userdata){\
		int i;
		path_mapping_xml* map=NULL;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		map=amx_newPathMappingXml(p);
		ctmp->tmp=(void*)map;
		char*matchListsStr;
		
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"path")==0){
				map->pathRegex=apr_pstrdup(p,(char*)attributes[i + 1]);				
			}else if(strcmp(attributes[i],"matchLists")==0){
				matchListsStr=apr_pstrdup(p,(char*)attributes[i + 1]);
				amx_appendMatchListsToMatchListArray(p,matchListsStr,ctmp->conf->uid,map->matchLists);
			}else if(strcmp(attributes[i],"ignoreCase")==0){
				map->ignoreCase=STRTOBOOL((char*)attributes[i + 1]);
			}
		}
		return 1;
	}
	static int amx_addPathMapping(pool* p,char* xPath,int type,void* userdata){
		oidc_config_xml* amx=NULL;
		path_mapping_xml* pm=NULL, **placepm=NULL;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		
		amx=(oidc_config_xml*)ctmp->conf;
		if(amx!=NULL&&ctmp->tmp!=NULL){
			pm=(path_mapping_xml*)ctmp->tmp;
			placepm=(path_mapping_xml**)apr_array_push (amx->path_mappings_arr);
			*placepm=pm;
		}
		ctmp->tmp=NULL;
		return 1;
	}
	static int amx_setPath(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		path_mapping_xml* pa=(path_mapping_xml*)ctmp->tmp;
		if(pa!=NULL){
			pa->pathRegex=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_newPathMappingAction(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		pathmapping_action_xml* action=apr_palloc(p,sizeof(pathmapping_action_xml));
		action->id=NULL;
		action->matchList=NULL;
		
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"matchList")==0){
				action->matchList=apr_pstrdup(p,(char*)attributes[i + 1]);
				if(ctmp->conf->uid!=0){
					action->matchList=apr_psprintf(p,"%s_%d",action->matchList,ctmp->conf->uid);
				}
			}
		}
		ctmp->tmp6=(void*)action;
		return 1;
	}
	static int amx_setPathMappingAction(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		pathmapping_action_xml* action=(pathmapping_action_xml*)ctmp->tmp6;
		
		if(action!=NULL){
			if(ctmp->conf->uid!=0){
				action->id=apr_psprintf(p,"%s_%d",body,ctmp->conf->uid);
			}else{
				action->id=apr_pstrdup(p,body);
			}
		}
		return 1;
	}	
	static int amx_addPathMappingAction(pool* p,void* userdata,array_header* actions){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		path_mapping_xml* pa=(path_mapping_xml*)ctmp->tmp;
		pathmapping_action_xml* action=(pathmapping_action_xml*)ctmp->tmp6, **pos=NULL;	
		if(actions!=NULL){
			pos=(pathmapping_action_xml**)apr_array_push(actions);
			*pos=action;
			printf("matchlist=%s id=%s \r\n",action->matchList, action->id);
		}
		ctmp->tmp6=NULL;
		return 1;
	}
	static int amx_addPathMappingPostAuth(pool* p,char* xPath,int type,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		path_mapping_xml* pa=(path_mapping_xml*)ctmp->tmp;
		if(pa!=NULL){
			amx_addPathMappingAction(p,userdata,pa->postAuthActions);
		}
		return 1;
	}	
	static int amx_addPathMappingMatchList(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		path_mapping_xml* pa=(path_mapping_xml*)ctmp->tmp;
		char** pos=NULL, *tmp;
		if(pa!=NULL){
			pos=apr_array_push(pa->matchLists);
			tmp=apr_pstrdup(p,body);
			if(ctmp->conf->uid!=0){
				tmp=apr_psprintf(p,"%s_%d",tmp,ctmp->conf->uid);
			}
			*pos=tmp;
		}
		return 1;
	}

	static int amx_newPathMappingMatchHeader(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;
		int i=0;
		mlx_match_header* hdr=NULL;
		
		if(match!=NULL){
			hdr=ml_newMatchHeaderObj(p);
			for(i=0;attributes[i]; i += 2) {
				if(strcmp(attributes[i],"name")==0){
					hdr->name=apr_pstrdup(p,(char*)attributes[i + 1]);
				}else if(strcmp(attributes[i],"delimAnd")==0){
					hdr->delimAnd=apr_pstrdup(p,(char*)attributes[i + 1]);
				}else if(strcmp(attributes[i],"negate")==0){
					hdr->negate=STRTOBOOL(apr_pstrdup(p,(char*)attributes[i + 1]));
				}else if(strcmp(attributes[i],"isregex")==0){
					hdr->isRegex=STRTOBOOL(apr_pstrdup(p,(char*)attributes[i + 1]));
				}
			}
			ctmp->tmp5=(void*)hdr;
		}
		return 1;
	}
	static char* amx_getGlobalPrefixedParam(pool* p, const char* key){
		if(key==NULL) return NULL;
		if(strstr(key,"global:")==key){
			return apr_pstrdup(p,key+7);
		}
		return NULL;
	}
		
	time_t amx_dateStringToSeconds(const char* dateString){
	//Functionality moved to common_utils.c
		return cu_dateStringToSeconds(dateString);
	}
	
	static int amx_newPathMappingMatchEvent(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;
		int i=0;
		mlx_match_event* e=NULL;
		
		if(match!=NULL){
			e=ml_newMatchEventObj(p);
			for(i=0;attributes[i]; i += 2) {
				if(strcmp(attributes[i],"start")==0){
					e->start=amx_dateStringToSeconds(apr_pstrdup(p,(char*)attributes[i + 1]));
				}else if(strcmp(attributes[i],"end")==0){
					e->end=amx_dateStringToSeconds(apr_pstrdup(p,(char*)attributes[i + 1]));
				}
			}
			match->event=e;
		}
		return 1;
	}

	static int amx_setPathMappingMatchHeader(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;
		mlx_match_header* hdr=(mlx_match_header*)ctmp->tmp5, **headerPlace;
		
		if(match!=NULL&&hdr!=NULL){
			hdr->value=apr_pstrdup(p,body);
			headerPlace=(mlx_match_header**)apr_array_push(match->headerList);
			*headerPlace=hdr;
			
			if(ctmp->errorStr==NULL&&!rc_isRegexValid(p,hdr->value)){
				ctmp->errorStr=apr_pstrcat(p,"Header Regex not valid: (",hdr->name,"=",hdr->value,")",NULL);
			}
			ctmp->tmp5=NULL;
		}
		return 1;
	}
	
	static action_header_xml* amx_newActionHeaderObj(pool* p){
		action_header_xml* ret=apr_palloc(p,sizeof(action_header_xml));
		ret->name=NULL;
		ret->value=NULL;
		ret->regex=NULL;
		ret->action=header_set;
		return ret;
	}
	
	static header_actions amx_getHeaderAction(const char* action) {
		header_actions header_action;
		
		if(action==NULL) return header_set;
		
		if (!strcasecmp(action, "set"))
			header_action = header_set;
	    else if (!strcasecmp(action, "add"))
	    	header_action = header_add;
	    else if (!strcasecmp(action, "append"))
	    	header_action = header_append;
	    else if (!strcasecmp(action, "merge"))
	    	header_action = header_merge;
	    else if (!strcasecmp(action, "unset"))
	    	header_action = header_unset;
	    else if (!strcasecmp(action, "echo"))
	    	header_action = header_echo;
	    else if (!strcasecmp(action, "edit"))
	    	header_action = header_edit;
	    else header_action = header_set;
		
		return header_action;
	}
	
	static int amx_newActionHeader(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		action_header_xml* hdr = amx_newActionHeaderObj(p);
		int i;
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"name")==0){
				hdr->name=apr_pstrdup(p,(char*)attributes[i + 1]);
			}
			else if(strcmp(attributes[i],"regex")==0) {
				hdr->regex = apr_pstrdup(p,(char*)attributes[i + 1]);
			}
			else if(strcmp(attributes[i],"do")==0) {
				hdr->action = amx_getHeaderAction((char*)attributes[i + 1]); 
			}			
		}
		ctmp->tmp8=(void*)hdr;
		return 1;
	}
	
	static int amx_setActionResponseHeader(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		action_header_xml* hdr=(action_header_xml*)ctmp->tmp8, **headerPlace;

		if(pa!=NULL&&pa->responseHeaders!=NULL&&hdr!=NULL){
			hdr->value=apr_pstrdup(p,body);
			headerPlace=(action_header_xml**)apr_array_push(pa->responseHeaders);
			*headerPlace=hdr;
			//printf("responseheaders=%s:%s\n", hdr->name, hdr->value);
			ctmp->tmp8=NULL;
		}
		return 1;
	}

	static int amx_setActionRequestHeader(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		page_action_xml* pa=(page_action_xml*)ctmp->tmp;
		action_header_xml* hdr=(action_header_xml*)ctmp->tmp8, **headerPlace;

		if(pa!=NULL&&pa->requestHeaders!=NULL&&hdr!=NULL){
			hdr->value=apr_pstrdup(p,body);
			headerPlace=(action_header_xml**)apr_array_push(pa->requestHeaders);
			*headerPlace=hdr;
			//printf("requestHeaders=%s:%s\n", hdr->name, hdr->value);
			ctmp->tmp8=NULL;
		}
		return 1;
	}
	
	static int amx_newMatchList(pool* p,char* xPath,int type,const char ** attributes,void* userdata){\
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_matchlist* mlist=apr_palloc(p,sizeof(mlx_matchlist));
		mlist->name=NULL;
		mlist->matches=apr_array_make(p,2,sizeof(mlx_ml_match*));
		
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"name")==0){
				mlist->name=apr_pstrdup(p,(char*)attributes[i + 1]);
				if(ctmp->conf->uid!=0){
					mlist->name=apr_psprintf(p,"%s_%d",mlist->name,ctmp->conf->uid);
				}
				ctmp->tmp=(void*)mlist;
			}
		}
		return 1;
	}
	static int amx_addMatchList(pool* p,char* xPath,int type,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		mlx_matchlist* mlist=(mlx_matchlist*)ctmp->tmp, **mlistPos=NULL;
		
		if(ctmp!=NULL&&mlist!=NULL&&mlist->name!=NULL){
			mlistPos=(mlx_matchlist**)apr_array_push(amx->match_list_arr);
			*mlistPos=mlist;
		}
		ctmp->tmp=NULL;
		return 1;
	}
	static int amx_newPathMappingMatch(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=ml_newMatchListMatchObj(p);
		int i;
		if(match!=NULL){
			for(i=0;attributes[i]; i += 2){
				if(strcmp(attributes[i],"host")==0){
					match->host=apr_pstrdup(p,(char*)attributes[i + 1]);
				}else if(strcmp(attributes[i],"cascade")==0){
					match->cascade=STRTOBOOL((char*)attributes[i + 1]);
				}
			}
		}		
		ctmp->tmp2=(void*)match;
		return 1;
	}
	
	static int amx_addPathMappingMatch(pool* p,char* xPath,int type,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_matchlist* matchlist=(mlx_matchlist*)ctmp->tmp;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2, **matchPos=NULL;
		if(match!=NULL&&matchlist!=NULL){
			matchPos=(mlx_ml_match**)apr_array_push(matchlist->matches);
			*matchPos=match;
			ctmp->tmp2=NULL;
		}
		return 1;
	}
	static int amx_setMatchHost(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;
		if(match!=NULL){
			match->host=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_newMatchListMatchIp(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_match_ip* ip=ml_newMatchIpObj(p);
		
		for(i=0;attributes[i]; i += 2){
			if(strcmp(attributes[i],"isregex")==0){
				ip->isRegex=STRTOBOOL((char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"negate")==0){
				ip->negate=STRTOBOOL((char*)attributes[i + 1]);
			}
		}
		ctmp->tmp6=(void*)ip;
		return 1;
	}
	static int amx_setPathMappingMatchIp(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;	
		mlx_match_ip* ip=(mlx_match_ip*)ctmp->tmp6;
		
		if(match!=NULL&&ip!=NULL){
			ip->ip=apr_pstrdup(p,body);
			if(ctmp->errorStr==NULL&&ip->isRegex==TRUE&&!rc_isRegexValid(p,ip->ip)){
				ctmp->errorStr=apr_pstrcat(p,"IP Regex not valid:",ip->ip,NULL);
			}
			match->ip=ip;
		}
		ctmp->tmp6=NULL;
		
		return 1;
	}
	static int amx_newMatchListMatchPath(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_match_path* path=ml_newMatchPathObj(p);
		
		for(i=0;attributes[i]; i += 2){
			if(strcmp(attributes[i],"negate")==0){
				path->negate=STRTOBOOL((char*)attributes[i + 1]);
			}
		}
		ctmp->tmp7=(void*)path;
		return 1;
	}
	static int amx_setPathMappingMatchPath(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		mlx_ml_match* match=(mlx_ml_match*)ctmp->tmp2;	
		mlx_match_path* path=(mlx_match_path*)ctmp->tmp7;
		
		if(match!=NULL&&path!=NULL){
			path->path=apr_pstrdup(p,body);
			if(ctmp->errorStr==NULL&&!rc_isRegexValid(p,path->path)){
				ctmp->errorStr=apr_pstrcat(p,"IP Regex not valid:",path->path,NULL);
			}
			match->path=path;
		}
		ctmp->tmp7=NULL;
		
		return 1;
	}	
	static int amx_newInclude(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
	
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"path")==0){
				ctmp->tmp4=apr_pstrdup(p,(char*)attributes[i + 1]);
			}
		}
		return 1;
	}

	static action_response_xml* actionmapxml_newPageActionResponseObj(pool* p){
		action_response_xml* ret=(action_response_xml*)apr_palloc(p,sizeof(action_response_xml));
		ret->code=-1;
		ret->contentType=NULL;
		ret->body=NULL;
		return ret;
	}
	
	static int amx_newPageActionResponse(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		action_response_xml* response=actionmapxml_newPageActionResponseObj(p);
		
		
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"code")==0){
				response->code=atoi(attributes[i + 1]);			
			}else if(strcmp(attributes[i],"contentType")==0){
				response->contentType=apr_pstrdup(p, attributes[i + 1]);			
			}
		}
		ctmp->tmp11=(void*)response;
		
		return 1;
	}
	
	static int amx_setPageActionResponseBody(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		action_response_xml* response=(action_response_xml*)ctmp->tmp11;
		
		if(response!=NULL){
			response->body = apr_pstrdup(p,body);
		}		
		return 1;
	}
	
	static int amx_addPageActionResponse(pool* p,char* xPath,int type,void* userdata){
			actmap_tmp* ctmp=(actmap_tmp*)userdata;
			 
			if(ctmp->tmp!=NULL&&ctmp->tmp11!=NULL){
				page_action_xml* pa=(page_action_xml*)ctmp->tmp;
				if(pa!=NULL) {
					pa->response=(action_response_xml*)ctmp->tmp11;
				}
			}
			ctmp->tmp11=NULL;
			return 1;
	}

	static int cc_setACCSessionCookieAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* stmp=(actmap_tmp*)userdata;
		oidc_config_xml* conf=(oidc_config_xml*)stmp->conf;
		for (i = 0; attributes[i]; i += 2) {
			if(strcmp(attributes[i],"name")==0){
				cookie_setCookieName(p, conf->rpSession, (char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"lifetime")==0){
				cookie_setCookieLifeTime(conf->rpSession,atoi(attributes[i + 1]));
			}else if(strcmp(attributes[i],"httpOnly")==0){
				cookie_setCookieHttpOnlyflag(conf->rpSession,
						STRTOBOOL(attributes[i + 1]));
			}else if(strcmp(attributes[i],"secureHttpOnly")==0){
				cookie_setCookieSecureHttpOnlyflag(conf->rpSession,
						STRTOBOOL(attributes[i + 1]));
			}
  		}
		return 1;
	}

	static int cc_setACCPermCookieAttributes(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* stmp=(actmap_tmp*)userdata;
		oidc_config_xml* conf=(oidc_config_xml*)stmp->conf;

		for (i = 0; attributes[i]; i += 2) {
			if(strcmp(attributes[i],"name")==0){
				cookie_setCookieName(p, conf->oidcSession,(char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"lifetime")==0){
				cookie_setCookieLifeTime(conf->oidcSession,atoi(attributes[i + 1]));
			}else if(strcmp(attributes[i],"httpOnly")==0){
				cookie_setCookieHttpOnlyflag(conf->oidcSession,STRTOBOOL(attributes[i + 1]));
			}else if(strcmp(attributes[i],"secureHttpOnly")==0){
				cookie_setCookieSecureHttpOnlyflag(conf->oidcSession,
						STRTOBOOL(attributes[i + 1]));
			}
  		}
		return 1;
	}

	static relying_party_xml* amx_newRelyingPartyXml(pool* p){
		relying_party_xml* ret;
		ret=apr_palloc(p,sizeof(relying_party_xml));
		ret->clientID=NULL;
		ret->clientSecret=NULL;
		ret->description=NULL;
		ret->domain=NULL;
		ret->validateNonce=TRUE;
		ret->redirectUri=NULL;
		return ret;
	}

	static int amx_defaultRelyingParty(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"default")==0){
				amx->defaultRelyingParty=apr_pstrdup(p,(char*)attributes[i + 1]);
			}
		}
		return 1;
	}

	static int amx_newRelyingParty(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)amx_newRelyingPartyXml(p);
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"clientID")==0){
				rpX->clientID=apr_pstrdup(p,(char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"clientSecret")==0){
				rpX->clientSecret=apr_pstrdup(p,(char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"domain")==0){
				rpX->domain=apr_pstrdup(p,(char*)attributes[i + 1]);
			}else if(strcmp(attributes[i],"validateNonce")==0){
				rpX->validateNonce=STRTOBOOL(attributes[i + 1]);
			}
		}
		ctmp->tmp14=rpX;
		return 1;
	}
	static int amx_addRelyingParty(pool* p,char* xPath,int type,void* userdata){
		oidc_config_xml* amx=NULL;
			relying_party_xml* rpX=NULL;
			actmap_tmp* ctmp=(actmap_tmp*)userdata;
			amx=(oidc_config_xml*)ctmp->conf;

			if(amx!=NULL&&ctmp->tmp14!=NULL){
				rpX=(relying_party_xml*)ctmp->tmp14;
				apr_hash_set (amx->relyingPartyHash,rpX->clientID,APR_HASH_KEY_STRING,rpX);
			}
			ctmp->tmp14=NULL;
			return 1;
	}

	static int amx_setRelyingPartyClientID(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->clientID==NULL){
			rpX->clientID=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setRelyingPartyDescription(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->description==NULL){
			rpX->description=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setRelyingPartyClientSecret(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->clientSecret==NULL){
			rpX->clientSecret=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setRelyingPartyDomain(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->domain==NULL){
			rpX->domain=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setRelyingPartyValidateNonce(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->domain==NULL){
			rpX->validateNonce=STRTOBOOL(body);
		}
		return 1;
	}
	static int amx_setRelyingPartyRedirectUri(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		relying_party_xml* rpX=(relying_party_xml*)ctmp->tmp14;
		if(rpX!=NULL&&rpX->redirectUri==NULL){
			rpX->redirectUri=apr_pstrdup(p,body);
		}
		return 1;
	}
	static oidc_provider_xml* amx_newOIDCProviderXml(pool* p){
		oidc_provider_xml* ret;
		ret=apr_palloc(p,sizeof(oidc_provider_xml));
		ret->metadataUrl=NULL;
		return ret;
	}

	static int amx_newOIDCProvider(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		amx->oidcProvider=amx_newOIDCProviderXml(p);

		return 1;
	}

	static int amx_setOIDCProviderMetadataUrl(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->metadataUrl=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setOIDCProviderIssuer(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->issuer=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setOIDCProviderAuthorizationEndpoint(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->authorizationEndpoint=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setOIDCProviderTokenEndpoint(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->tokenEndpoint=apr_pstrdup(p,body);
		}
		return 1;
	}
	static int amx_setOIDCProviderJwksUri(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->jwksUri=apr_pstrdup(p,body);
		}
		return 1;
	}

	static int amx_setOIDCProviderJwksJson(pool* p,char* xPath,int type,const char *body,void* userdata){
		actmap_tmp* ctmp=(actmap_tmp*)userdata;
		oidc_config_xml* amx=(oidc_config_xml*)ctmp->conf;
		if(amx->oidcProvider!=NULL) {
			amx->oidcProvider->jwksJson=apr_pstrdup(p,body);
		}
		return 1;
	}

	char* amx_loadConfFile(pool* p, char* file, oidc_config_xml* conf){
		XmlCore* xCore;
		actmap_tmp tmp;
		char* result=NULL;
		
		tmp.conf=conf;
		tmp.tmp=NULL;
		tmp.tmp2=NULL;
		tmp.tmp3=NULL;
		tmp.tmp4=NULL;
		tmp.tmp5=NULL;
		tmp.tmp6=NULL;
		tmp.tmp7=NULL;
		tmp.tmp8=NULL;
		tmp.tmp9=NULL;
		tmp.tmp10=NULL;
		tmp.tmp11=NULL;
		tmp.tmp12=NULL;
		tmp.tmp13=NULL;
		tmp.tmp14=NULL;
		tmp.str=NULL;
		tmp.errorStr=NULL;
		
		xCore=xc_getXmlCore(p);
		
		xc_addXPathHandler(xCore,"/oidcConfig",0,amx_oidcConfigAttributes,NULL,NULL, &tmp);
		
		//page action stuff
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action",0,amx_newPageAction,NULL,amx_addPageAction, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/id",0,NULL,amx_setPageActionId,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/description",0,NULL,amx_setPageActionDescription,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/isForward",0,NULL,amx_setPageActionIsForward,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/isPermanent",0,NULL,amx_setPageActionIsPermanent,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/isForbidden",0,NULL,amx_setPageActionIsForbidden,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/advancedTemplate",0,NULL,amx_setPageActionAdvancedTemplate,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/uri",0,NULL,amx_setPageActionUri,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/regex",0,NULL,amx_setPageActionRegex,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/handler",0,NULL,amx_setPageActionHandler,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/requestHeaders/header",0,amx_newActionHeader,amx_setActionRequestHeader,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/responseHeaders/header",0,amx_newActionHeader,amx_setActionResponseHeader,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pageActions/action/response",0,amx_newPageActionResponse,amx_setPageActionResponseBody,amx_addPageActionResponse, &tmp);
			
		//path mapping stuff
		xc_addXPathHandler(xCore,"/oidcConfig/pathMappings/mapping",0,amx_newPathMapping,NULL,amx_addPathMapping, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pathMappings/mapping/path",0,NULL,amx_setPath,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pathMappings/mapping/postAuthAction",0,amx_newPathMappingAction,amx_setPathMappingAction,amx_addPathMappingPostAuth, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/pathMappings/mapping/matchList",0,NULL,amx_addPathMappingMatchList,NULL, &tmp);
		
		//match list stuff
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList",0,amx_newMatchList,NULL,amx_addMatchList, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match",0,amx_newPathMappingMatch,NULL,amx_addPathMappingMatch, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match/host",0,NULL,amx_setMatchHost,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match/ip",0,amx_newMatchListMatchIp,amx_setPathMappingMatchIp,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match/path",0,amx_newMatchListMatchPath,amx_setPathMappingMatchPath,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match/header",0,amx_newPathMappingMatchHeader,amx_setPathMappingMatchHeader,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/matchLists/matchList/match/event",0,amx_newPathMappingMatchEvent,NULL,NULL, &tmp);
				
		xc_addXPathHandler(xCore,"/oidcConfig/rpSession",0,cc_setACCSessionCookieAttributes,NULL,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcSession",0,cc_setACCPermCookieAttributes,NULL,NULL, &tmp);

		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties",0,amx_defaultRelyingParty,NULL,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty",0,amx_newRelyingParty,NULL,amx_addRelyingParty, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/clientID",0,NULL,amx_setRelyingPartyClientID,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/description",0,NULL,amx_setRelyingPartyDescription,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/clientSecret",0,NULL,amx_setRelyingPartyClientSecret,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/domain",0,NULL,amx_setRelyingPartyDomain,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/validateNonce",0,NULL,amx_setRelyingPartyValidateNonce,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/relyingParties/relyingParty/redirectUri",0,NULL,amx_setRelyingPartyRedirectUri,NULL, &tmp);

		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider",0,amx_newOIDCProvider,NULL,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/metadataUrl",0,NULL,amx_setOIDCProviderMetadataUrl,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/issuer",0,NULL,amx_setOIDCProviderIssuer,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/authorizationEndpoint",0,NULL,amx_setOIDCProviderAuthorizationEndpoint,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/tokenEndpoint",0,NULL,amx_setOIDCProviderTokenEndpoint,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/jwksUri",0,NULL,amx_setOIDCProviderJwksUri,NULL, &tmp);
		xc_addXPathHandler(xCore,"/oidcConfig/oidcProvider/jwksJson",0,NULL,amx_setOIDCProviderJwksJson,NULL, &tmp);

		result=xc_beginParsingTextResponse(xCore,file);
		return result;
	}

