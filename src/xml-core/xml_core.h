/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __TCREWRITE_XML_CORE__H_
#define __TCREWRITE_XML_CORE__H_

#ifdef __cplusplus
extern "C" {
#endif

#include "apache_typedefs.h"
	typedef struct llnode {
    	void* data;
    	struct llnode *next;
		struct llnode *prev;
  	}llnode;

	typedef struct DLinkedList{
		llnode *head;
		llnode *tail;
		int elts;
	}DLinkedList;

	typedef struct xc_rec{
		DLinkedList* xpath_nodes;
		DLinkedList* xpath_handlers;
		pool* p;	
	}XmlCore;

	typedef int (*xfunc) (pool*,char*,int,const char **,void*);
	typedef int (*bfunc) (pool*,char*,int,const char *,void*);
	typedef int (*efunc) (pool*,char*,int,void*);

	typedef struct x_rec{ 
		char* path;
		DLinkedList* xpath_nodes;
		void* userdata;
		xfunc start_function;
		bfunc body_function;
		efunc end_function;
		char* body;
	}x_rec;
	typedef struct node_info_rec{
		char* name;
	}node_info;

	DLinkedList* xc_getLinkedList(pool *p);
	int xc_AddToTail(pool* p, DLinkedList* xCore, void* elt);
	void* xc_peekTail(pool* p, DLinkedList* ll);
	XmlCore* xc_getXmlCore(pool *p);
	int xc_addXPathHandler(XmlCore* xCore, char* path, int options, const xfunc sfunction, const bfunc bfunction, const efunc efunction, void* udata);
	int xc_beginParsing(XmlCore* xCore,const char* file);
	int xc_parseFromStringSource(XmlCore* xCore,const char* source);
	char* xc_beginParsingTextResponse(XmlCore* xCore, char* file);
	char* xc_parseFromStringSourceTextResponse(XmlCore* xCore, char* source);

#ifdef __cplusplus
}
#endif
#endif	//__TCREWRITE_XML_CORE__H_
