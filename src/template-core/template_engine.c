#include "template_engine.h"
#include "common_utils.h"
#include <apr_lib.h>

	static int templatecore_templateCount(){
		return sizeof(template_eng_templates)/sizeof(template_eng_template);
	}

	static template_eng_template* templatecore_findTemplate(char* id){
		int x;
		int len=templatecore_templateCount();
		for(x=0;x<len;x++){
			if(template_eng_templates[x].id!=NULL&&strcmp(template_eng_templates[x].id,id)==0){
				return (template_eng_template*)&(template_eng_templates[x]);
			}
		}
		return NULL;
	}

	template_engine* te_newEngineObj(shared_heap* sheap){
		template_engine* ret=NULL;
		ret=(template_engine*)shdata_shpcalloc(sheap,sizeof(template_engine));
		ret->templateHash=shapr_hash_make(sheap);
		return ret;
	}
	
	static template_eng_livetemplate* te_newLiveTemplate(shared_heap* sheap,template_eng_template* etemplate){
		template_eng_livetemplate* ret=NULL;
		ret=(template_eng_livetemplate*)shdata_shpcalloc(sheap,sizeof(template_eng_livetemplate));
		ret->engineTemplate=etemplate;
		return ret;
	}


	char* te_initialize(pool* p,shared_heap* sheap,cbs_globals* globals,template_engine* teng){
		char* ret=NULL;
		void* config=NULL;
		int x=0;
		template_eng_livetemplate* ltemplate=NULL;
		int len=templatecore_templateCount();
		
		for(x=0;x<len;x++){
			ltemplate=te_newLiveTemplate(sheap,(template_eng_template*)&(template_eng_templates[x]));
					
			//initialize template
			if(template_eng_templates[x].initFunc!=NULL){
				ret=(*template_eng_templates[x].initFunc)(p,sheap,globals,&config);
				if(ret!=NULL){
					return ret;
				}
				
				ltemplate->config=config;
			}
			
			//attach template to live template hash
			if(teng!=NULL){
				shapr_hash_set(sheap,teng->templateHash,template_eng_templates[x].id,APR_HASH_KEY_STRING,ltemplate);
			}
		}
		
		return ret;
	}
	char* te_getToken(pool* p, template_engine* tengine,char* tid, char* src){
		template_eng_livetemplate* ltemplate=NULL;
		char* ret=NULL;
		
		ltemplate=shapr_hash_get(tengine->templateHash,tid,APR_HASH_KEY_STRING);
		if(ltemplate!=NULL&&ltemplate->engineTemplate!=NULL&&ltemplate->engineTemplate->tokenFunc!=NULL){
			ret=(*ltemplate->engineTemplate->tokenFunc)(p,ltemplate->config,src);
		}
		
		return ret;
	}

	static int te_isToken(pool* p, char* token,template_engine* tengine){
		shapr_hash_index_t* hi;
		void* val, * key;
		
		if(tengine!=NULL&&token!=NULL){
			for(hi=shapr_hash_first(p,tengine->templateHash);hi;hi=shapr_hash_next(hi)){
				shapr_hash_this(hi,(const void**)&key,NULL,&val);
				if(strncmp(token,(char*)key,1)==0){
					return 1;
				}
			}
		}
		
		return 0;
	}
	
	
	
	typedef struct template_token{
		int num;
		char* prefix;
		char* postfix;
		char* id;
	}	template_token;
	
	static te_zeroToken(template_token* token){
		token->num=-1;
		token->prefix=NULL;
		token->postfix=NULL;
		token->id=NULL;
	}
	static char* te_append(pool* p, char* base, char* add1, char* add2){
		char* ret=NULL;
		if(base==NULL){
			ret=apr_pstrcat(p,add1,add2,NULL);	
		}else{
			ret=apr_pstrcat(p,base,add1,add2,NULL);	
		}
		return ret;
	}
	static char* te_appendToken(pool* p, array_header* matches,char* base,char* space,template_token* token,template_engine* tengine){
		char* ret=NULL;
		char* el=NULL;
		char* tmp=NULL;
		int dlen=0;
		
		if(matches!=NULL&&token!=NULL&&token->num>=0&&token->num<matches->nelts){
			el=cu_getElement(matches,token->num);
			if(token->id!=NULL){
				el=te_getToken(p,tengine,token->id,el);
			}
//			if(token->urlEncode==1){
//				dlen=(strlen(el)*3)+1;
//				tmp=apr_pcalloc(p,dlen);
//				url_encode(el,tmp,dlen);
//				el=tmp;
//			}else if (token->urlEncode==2){
//				dlen=strlen(el)+1;
//				tmp=apr_pcalloc(p,dlen);
//				url_decode(el,tmp,dlen);
//				el=tmp;
//			}
		}
		if(token!=NULL){
			ret=apr_pstrcat(p,SAFESTRBLANK(base),SAFESTRBLANK(space),SAFESTRBLANK(token->prefix),SAFESTRBLANK(el),SAFESTRBLANK(token->postfix),NULL);
		}else{
			ret=apr_pstrcat(p,SAFESTRBLANK(base),SAFESTRBLANK(space),NULL);	
		}
			
		return ret;
	}
	
	char* te_templateString(pool* p,template_engine* tengine,char* sourcestr,array_header* matches){
		char* ret=NULL;
		char* num=NULL;
		char code='\0';
		template_token token;
		char* match,*start=NULL, *str=NULL, *end=NULL,*begin=NULL,*cursor=NULL;
		
		str=apr_pstrdup(p,sourcestr);
		begin=str;
		cursor=str;
		
		match=strstr(begin,"($");
		while(match!=NULL){
			te_zeroToken(&token);
			
			//find number
			start=match+2;
			end=start;
			while(apr_isdigit(*end)){
				end++;
			}
			if(*end==')'||*end=='^'||*end=='$' || te_isToken(p,end,tengine)){   ///replace with IS TOKEN FROM TOKEN ENGINE!!!
				num=apr_pstrndup(p,start, (end-start));
				token.num=atoi(num);
			}
			if(te_isToken(p,end,tengine)){
				token.id=apr_pstrndup(p,end,1);
				end++;
			}
						
			//get pre/postfix stuff
			if(*end=='^'||*end=='$'){
				code=*end;
				start=end+1;
				end=start;
				while(*end!='\0'&&*end!=')'){
					end++;
				}
				if(*end==')'){
					if(code=='^'){
						token.prefix=apr_pstrndup(p,start, (end-start));
					}else if(code=='$'){
						token.postfix=apr_pstrndup(p,start, (end-start));
					}
				}
			}
				
			if(*end==')'){
				*match='\0';
				if(matches!=NULL&&token.num<matches->nelts){
					//do template
					ret=te_appendToken(p,matches,ret,cursor,&token,tengine);
				}else{
					ret=te_appendToken(p,NULL,ret,cursor,NULL,tengine);
				}
				cursor=end+1;
			}

			begin=end+1;
			match=strstr(begin,"($");
		}
		
		if(cursor!=NULL&&*cursor!='\0'){
			ret=te_append(p,ret,cursor,NULL);
		}
		return ret;
	}
