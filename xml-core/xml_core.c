/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#include <xml_core.h>
#include <expat.h>
#include <stdio.h>
#include <string.h>
#include <token_utils.h>
#include "apr_strings.h"

#define BUFFSIZE	8192
#ifdef XML_LARGE_SIZE
#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#define XML_FMT_INT_MOD "I64"
#else
#define XML_FMT_INT_MOD "ll"
#endif
#else
#define XML_FMT_INT_MOD "l"
#endif

#define CONST_FAILURE_FILE_OPEN	-1
#define CONST_FAILURE_CREATE	-2
#define CONST_FAILURE_READ		-4
#define CONST_FAILURE_XMLERROR	-8
#define CONST_SUCCESS			1

	DLinkedList* xc_getLinkedList(pool *p){
		DLinkedList* dlist;
		dlist=apr_palloc(p,sizeof(DLinkedList));
		dlist->head=NULL;
		dlist->tail=NULL;
		dlist->elts=0;
		return dlist;
	}
	
	int xc_AddToTail(pool* p, DLinkedList* ll, void* elt){
		llnode* node;
		node=apr_palloc(p,sizeof(llnode));
		node->data=elt;
		node->prev=NULL;
		node->next=NULL;
		if(ll->head==NULL||ll->tail==NULL){					
			ll->head=ll->tail=node;
		}else{
			ll->tail->next=node;
			node->prev=ll->tail;
			ll->tail=ll->tail->next;
		}
		ll->elts++;
	return ll->elts;
	}

	void* xc_peekTail(pool* p, DLinkedList* ll){
		if(ll->tail!=NULL){
			return ll->tail->data;
		}
		return NULL;
	}

	void* xc_RemoveFromTail(pool* p, DLinkedList* ll){
		void* elt=NULL;
		if(ll->head==ll->tail){
			elt=ll->head->data;
			ll->head=ll->tail=NULL;
		}else if(ll->head!=NULL&&ll->tail!=NULL){
			elt=ll->tail->data;
			ll->tail=ll->tail->prev;
			ll->tail->next=NULL;
		}
		return elt;
	}

	static void xc_printxrec_list(pool* p, DLinkedList* ll){
		llnode* node;
		x_rec* xrec;

		node=ll->head;
		while(node!=NULL){
			xrec=(x_rec*)(node->data);
			printf("xrec: %s\n",xrec->path);
			node=node->next;
		}
	}

	static void xc_printNodeInfo_list(pool* p, DLinkedList* ll){
		llnode* node;
		node_info *ninfo;

		node=ll->head;
		while(node!=NULL){
			ninfo=(node_info*)(node->data);
			printf("node: %s\n",ninfo->name);
			node=node->next;
		}
	}
	
	static DLinkedList* xc_parseXpathNodes(pool* p, char* str){
		node_info *ninfo;
		DLinkedList* ll;
		Tokener* tk;
		char* tok;
		
		ll=xc_getLinkedList(p);		
		tk=tu_getTokenizer(p,str,"/");

		//printf("str:%s\n",str);	
		
		while((tok=tu_next_token(tk))!=NULL){		
			ninfo=apr_palloc(p,sizeof(node_info));
			ninfo->name=tok;
			//printf("tok:%s\n",ninfo->name);	
			xc_AddToTail(p,ll,ninfo);
		}
		return ll;	
	}

	XmlCore* xc_getXmlCore(pool *p){
		XmlCore *c=apr_palloc(p,sizeof(XmlCore));
		c->p=p;
		c->xpath_nodes=xc_getLinkedList(p);
		c->xpath_handlers=xc_getLinkedList(p);
		return c;
	}
		

	int xc_addXPathHandler(XmlCore* xCore, char* path, int options, const xfunc sfunction, const bfunc bfunction, const efunc efunction, void* udata){
		int ret;
		x_rec* xrec;
		xrec=apr_palloc(xCore->p,sizeof(x_rec));
		//printf("Add Handler:%s\n",path);
		xrec->path=apr_pstrdup(xCore->p,path);
		xrec->userdata=udata;
		xrec->start_function=sfunction;
		xrec->body_function=bfunction;
		xrec->end_function=efunction;
		xrec->xpath_nodes=xc_parseXpathNodes(xCore->p,path);
		xrec->body=NULL;
		

		ret=xc_AddToTail(xCore->p,xCore->xpath_handlers,xrec);
		//xc_printxrec_list(xCore->p,xCore->xpath_handlers);
		return ret;
	}
	
	static int xc_matchNodeDLists(DLinkedList* l1, DLinkedList* l2){
		llnode *node1, *node2;
		node_info* ninfo1, *ninfo2;
		
		node1=l1->head;
		node2=l2->head;
			while(node1!=NULL&&node2!=NULL){
				ninfo1=(node_info*)node1->data;
				ninfo2=(node_info*)node2->data;
				//printf("1:%s, 2:%s\r\n",ninfo1->name,ninfo2->name);
				if(strcmp(ninfo1->name,"*")!=0&&strcmp(ninfo2->name,ninfo1->name)!=0){  //allows for wildcard all
					//printf("no match: %s,%s\n",ninfo2->name,ninfo1->name);
					return 0;
				}
				
				node1=node1->next;
				node2=node2->next;
				if((node1==NULL && node2==NULL)){
					//printf("MATC\r\n");
					return 1;
				}
			}
			//printf("no match3: %s,%s\n",ninfo2->name,ninfo1->name);
		
		return 0;
	}

	static void XMLCALL elementStart(void *data, const char *el, const char **attr){
		XmlCore* xCore=(XmlCore*)data;
		node_info* ninfo;

		//start handler data
		llnode* node;
		x_rec* xrec;

		//begin process element
		ninfo=(node_info*)apr_palloc(xCore->p,sizeof(node_info));
		ninfo->name=apr_pstrdup(xCore->p,el);
		//printf("add node:%s\n",el);
		xc_AddToTail(xCore->p,xCore->xpath_nodes,ninfo);
		//xc_printNodeInfo_list(xCore->p,xCore->xpath_nodes);

		//fire start handlers
		node=xCore->xpath_handlers->head;
		while(node!=NULL){
			xrec=(x_rec*)(node->data);
			//xc_printNodeInfo_list(xCore->p,xrec->xpath_nodes);
			if(xc_matchNodeDLists(xrec->xpath_nodes,xCore->xpath_nodes)){
				//printf("node match!\n");
				if(xrec->start_function!=NULL){
					(*xrec->start_function)(xCore->p,(char*)el,0,attr,xrec->userdata);
				}
			}
			node=node->next;
		}
		
	}
	static void XMLCALL elementEnd(void *data, const char *el){
		XmlCore* xCore=(XmlCore*)data;
		//start handler data
		llnode* node;
		x_rec* xrec;
		node_info* ninfo;
		
		//printf("END ELEMENT BEGIN\r\n");
		// fire end element handlers	
		node=xCore->xpath_handlers->head;
		while(node!=NULL){
			xrec=(x_rec*)(node->data);		
			//printf("ELEMENT END\r\n");
			if(xc_matchNodeDLists(xrec->xpath_nodes,xCore->xpath_nodes)){
				//printf("endnode match!\n");
				//fire end body handler
				if(xrec->body_function!=NULL){
					(*xrec->body_function)(xCore->p,(char*)el,0,xrec->body,xrec->userdata);
				}
				
				//fire end element handler
				if(xrec->end_function!=NULL){
					(*xrec->end_function)(xCore->p,(char*)el,0,xrec->userdata);
				}
				xrec->body=NULL;
			}
			node=node->next;
		}
		
		//clean up nodes
		ninfo=xc_RemoveFromTail(xCore->p,xCore->xpath_nodes);
		//printf("rem node:%s\n",ninfo->name);
		//xc_printNodeInfo_list(xCore->p,xCore->xpath_nodes);
	}
	static void XMLCALL cdataHandler(void *data, const XML_Char *s, int len){
		XmlCore* xCore=(XmlCore*)data;
		llnode* node;
		x_rec* xrec;
		node_info* ninfo;
		char* str=NULL;

				
		node=xCore->xpath_handlers->head;
		while(node!=NULL){
			xrec=(x_rec*)(node->data);
			
			if(xc_matchNodeDLists(xrec->xpath_nodes,xCore->xpath_nodes)){
				//printf("cdata!! match:!\n");
				if(str==NULL){
					str=apr_palloc(xCore->p,(len+1)*sizeof(char));
					memset(str,'\0',len+1);
					strncpy(str,s,len);
				}				
				
				if(xrec->body==NULL){					
					xrec->body=str;
				}else{
					xrec->body=apr_pstrcat(xCore->p,xrec->body,str,NULL);
				}
				//printf("val: [%s]\n",xrec->body);
				
			}
			node=node->next;
		}
		
		
		//printf("len: %d: %s\n",len,s);
	}
	static void XMLCALL cdataSectionHandlerStart(void *userData){
		//printf("!!!!!!!!!!!!!!!: \n");
	}
	static void XMLCALL cdataSectionHandlerEnd(void *userData){
		//printf("lenSecE\n");
	}
	
	int xc_beginParsing(XmlCore* xCore,const char* file){
		XML_Parser parser=NULL;
		FILE* xFile=NULL;		
		char xBuffer[BUFFSIZE];
		memset (xBuffer,'\0',BUFFSIZE);
		if(file!=NULL){xFile=fopen(file,"r");}
		if(xFile!=NULL){
			parser=XML_ParserCreate(NULL);
			if (! parser) {
    			fclose(xFile);
    			return CONST_FAILURE_CREATE;
 			}
			
			XML_SetUserData(parser,xCore);
			XML_SetElementHandler(parser, elementStart, elementEnd);
			XML_SetCdataSectionHandler(parser,cdataSectionHandlerStart,cdataSectionHandlerEnd);
			XML_SetCharacterDataHandler(parser,cdataHandler);

			//begin actual parsing
			for (;;) {
   				int done;
    			int len;
			
   				len = fread(xBuffer, 1, BUFFSIZE, xFile);
				if (ferror(stdin)) {
					fclose(xFile);
					XML_ParserFree(parser);
      				return CONST_FAILURE_READ;
    			}
			
    			done = feof(xFile);
			
				//printf("done: %d\n",done);
    			if (XML_Parse(parser, xBuffer, len, done) == XML_STATUS_ERROR) {
      				//fprintf(stderr, "Parse error at line %" XML_FMT_INT_MOD "u:\n%s\n",
          	    	//XML_GetCurrentLineNumber(parser),
         	     	//XML_ErrorString(XML_GetErrorCode(parser)));
					//printf("code: %d\n",XML_GetErrorCode(parser));
      				fclose(xFile);
      				XML_ParserFree(parser);
					return CONST_FAILURE_XMLERROR;
    			}
			
    			if (done){
      				break;
  				}
			}

			fclose(xFile);
			XML_ParserFree(parser);
			return 1;
		}
	return CONST_FAILURE_FILE_OPEN;
	}
	
	
	int xc_parseFromStringSource(XmlCore* xCore,const char* source){
		XML_Parser parser=NULL;
		char xBuffer[BUFFSIZE];


		if(source!=NULL){
			parser=XML_ParserCreate(NULL);
			if (! parser) {
    			return CONST_FAILURE_CREATE;
 			}
			
			XML_SetUserData(parser,xCore);
			XML_SetElementHandler(parser, elementStart, elementEnd);
			XML_SetCdataSectionHandler(parser,cdataSectionHandlerStart,cdataSectionHandlerEnd);
			XML_SetCharacterDataHandler(parser,cdataHandler);

			//begin actual parsing
			if (XML_Parse(parser, source, strlen(source), 1) == XML_STATUS_ERROR) {
				XML_ParserFree(parser);
				return CONST_FAILURE_XMLERROR;
			}
			XML_ParserFree(parser);
			return 1;
		}
	return CONST_FAILURE_READ;
	}
	
	static char* xc_parseTextResponse(apr_pool_t* p, int code, char* file){
		if(code==CONST_FAILURE_FILE_OPEN){
			return apr_pstrcat(p,"Failure to open file:",file!=NULL?file:"NULL",NULL);	
		}else if(code==CONST_FAILURE_XMLERROR){
			return apr_pstrcat(p,"Failure parsing xml:",file!=NULL?file:"NULL",NULL);
		}else if(code==CONST_FAILURE_READ){
			return apr_pstrcat(p,"Failure reading file:",file!=NULL?file:"NULL",NULL);
		}else if(code==CONST_FAILURE_CREATE){
			return apr_pstrcat(p,"Failure creating parser:",file!=NULL?file:"NULL",NULL);
		}
		return NULL;
	}
	char* xc_parseFromStringSourceTextResponse(XmlCore* xCore, char* source){
		int ret;
		ret=xc_parseFromStringSource(xCore,source);
		return xc_parseTextResponse(xCore->p,ret,source);
	}
	char* xc_beginParsingTextResponse(XmlCore* xCore, char* file){
		int ret;
		ret=xc_beginParsing(xCore,file);
		return xc_parseTextResponse(xCore->p,ret,file);
	}
