/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#include <memory.h>
#include <string.h>
#include "token_utils.h"


static int remove_leading_delimiters (Tokener* tok) {
	char* tmp;
	tmp=strstr(tok->text,tok->delim);
	//printf("remtok:%s\n",tok->text);
	if(tmp==tok->text){
		tok->text+=tok->delim_len;
		return remove_leading_delimiters(tok);
	}
	return 1;
}

Tokener* tu_getTokenizer (pool* p, char* text, char* delim)
{
	Tokener* tok;
	
	tok=apr_palloc(p,sizeof(Tokener));

	/*printf ("new_tokenizer: \"%s\", \"%s\"\n", text, delim);*/
	tok->text = text;
	tok->delim = delim;
	tok->delim_len = strlen (delim);
	tok->offset = 0;
	tok->p=p;

	remove_leading_delimiters(tok);
	return tok;
}





/*	
	Returns new allocated token string
*/
char *tu_next_token (Tokener* tok){
	char* sv, *ev, *ret=NULL;
	int len, lenNull;
	sv=tok->text;
	if(tok->text!=NULL){
		ev=strstr(tok->text,tok->delim);
		if(ev!=NULL){
			len=ev-sv;
			lenNull=len+1;
			ret=apr_palloc(tok->p,lenNull*sizeof(char));
			memset(ret,'\0',lenNull*sizeof(char));
			strncpy(ret,sv,len);	
			tok->text+=(len+tok->delim_len);
			//printf("len:%d,%s\n",len,ret);
			//printf("toktext:%s\n",tok->text);
		}else{
			if(*(tok->text)!='\0'){
				ret=apr_pstrdup(tok->p,tok->text);
				tok->text=NULL;
			}
		}
	}	
	/*printf ("next_token returning: \"%s\"\n", ret);*/
	return ret;
}


/*	
	 
*/
char *tu_remaining_text (Tokener* tok)
{
	char *ret;
	char *ptroffset = (tok->text)+tok->offset;
	size_t len = strlen (ptroffset)+1;
	
	ret=apr_palloc(tok->p,len+1);
	memcpy (ret, ptroffset, len);
	/*printf ("remaining_text returning: \"%s\"\n", ret);*/
	return ret;
}
