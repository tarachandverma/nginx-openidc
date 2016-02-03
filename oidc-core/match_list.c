#include <apache_mappings.h>
#include <xml_core.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oidc-core/match_list.h>
#include <oidc-core/rewrite_core.h>
#include <common-utils/common_utils.h>

	mlx_match_event* ml_newMatchEventObj(pool*p){
		mlx_match_event*ret=(mlx_match_event*)apr_pcalloc(p,sizeof(mlx_match_event));
		ret->start=ret->end=0;
		return ret;
	}
	mlx_match_ip*ml_newMatchIpObj(pool*p){
		mlx_match_ip* ip=apr_palloc(p,sizeof(mlx_match_ip));
		ip->isRegex=TRUE;
		ip->negate=FALSE;
		ip->ip=NULL;
		return ip;
	}
	mlx_match_path*ml_newMatchPathObj(pool*p){
		mlx_match_path* ret=apr_palloc(p,sizeof(mlx_match_path));
		ret->negate=FALSE;
		ret->path=NULL;
		return ret;
	}
	mlx_match_header* ml_newMatchHeaderObj(pool* p){
		mlx_match_header* ret=apr_palloc(p,sizeof(mlx_match_header));
		ret->name=NULL;
		ret->value=NULL;
		ret->delimAnd=NULL;
		ret->negate=FALSE;
		ret->isRegex=TRUE;
		return ret;
	}
	
	mlx_match_env* ml_newMatchEnvObj(pool* p){
		mlx_match_env* ret=(mlx_match_env*)apr_palloc(p,sizeof(mlx_match_env));
		ret->name=NULL;
		ret->value=NULL;
		ret->negate=FALSE;
		ret->isRegex=TRUE;
		return ret;
	}
	
	mlx_ml_match* ml_newMatchListMatchObj(pool* p){
		mlx_ml_match* ret=NULL;
		ret=(mlx_ml_match*)apr_palloc(p,sizeof(mlx_ml_match));
		ret->host=NULL;
		ret->cascade=TRUE;
		ret->ip=NULL;
		ret->path=NULL;
		ret->headerList=apr_array_make(p,2,sizeof(mlx_match_header*));
		ret->event=NULL;
		return ret;
	}
//	mlx_match_header* ml_newMatchHeaderObjExt(pool* p,char*name,char*value,char* delimAnd,char* isregex,char* negate){
//		mlx_match_header* ret=apr_palloc(p,sizeof(mlx_match_header));
//		ret->name=name?apr_pstrdup(p,name):NULL;
//		ret->value=value?apr_pstrdup(p,value):NULL;
//		ret->delimAnd=delimAnd?apr_pstrdup(p,delimAnd):NULL;
//		ret->isRegex=isregex?STRTOBOOL(isregex):TRUE;
//		ret->negate=negate?STRTOBOOL(negate):FALSE;
//		return ret;
//	}
	// Return TRUE if all subset elements(string type) are found in a given set.
	int ml_isSubsetFound(pool*p,array_header* subset, array_header* set,int isRegex){
		int i,j,count;
		char* e1,*e2;
		int isValueMatch=FALSE;
		
		if(subset==NULL||set==NULL||subset->nelts>set->nelts) return FALSE;
		
		for(i=0,count=0;i<subset->nelts;i++){
			e1=cu_getElement(subset,i);
			for(j=0;j<set->nelts;j++){
				e2=cu_getElement(set,j);
				isValueMatch=isRegex?(rc_matchByStringsReturnDetails(p,e1,e2)==NULL):(strcmp(e1,e2)==0);
				if(isValueMatch){
					count++;
					break;
				}
			}
		}
		
		if(count==subset->nelts) return TRUE;
		
		return FALSE;
	}
	// Return TRUE if none of subset elements(string type) are found in a given set.
	int ml_isNegateSubsetFound(pool*p,array_header* subset, array_header* set, int isRegex){
		int i,j;
		char* e1,*e2;
		int isValueMatch=FALSE;
		
		if(subset==NULL||set==NULL) return FALSE;
		
		for(i=0;i<subset->nelts;i++){
			e1=cu_getElement(subset,i);
			for(j=0;j<set->nelts;j++){
				e2=cu_getElement(set,j);
				isValueMatch=isRegex?(rc_matchByStringsReturnDetails(p,e1,e2)==NULL):(strcmp(e1,e2)==0);
				if(isValueMatch){
					return FALSE;
				}
			}
		}
		return TRUE;
	}
	
	int matchList_isMatched(pool*p,char* regex, char* value, int isRegex)
	{
		return (isRegex==TRUE
				?(rc_matchByStringsReturnDetails(p,regex,value)==NULL)
				:(strcmp(regex,value)==0));
	}

	int matchList_isHostMatched(pool*p, char* matchHost, apr_table_t *headers_in){
		if ( matchHost==NULL || headers_in==NULL ) return TRUE;
		
		char* host = (char*)apr_table_get(headers_in, "Host");

		return ( host==NULL || (rc_matchByStringsReturnDetails(p, matchHost, host)==NULL) );
	}
	
	void ml_printMatchList(pool* p, array_header* arr){
		int i=0, j=0;
		mlx_ml_match* match=NULL;
		mlx_match_header* hdr=NULL;
		mlx_match_env* env=NULL;
		if(arr!=NULL&&arr->nelts>0){
			printf("\r\n\t\t -- MatchList[%d]",arr->nelts);
			for(i=0;i<arr->nelts;i++){
				match=(mlx_ml_match*)cu_getElement(arr,i);
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
						hdr=(mlx_match_header*)cu_getElement(match->headerList,j);
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
