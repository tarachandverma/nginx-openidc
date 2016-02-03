#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "url_utils.h"

#define MAX_VAR_SIZE	256
#define URL_MAX_VAR_SIZE 1280

const int STAGE=0;
const int STEP=1;
const int CURSOR=2;

int c_to_hex(char c) {
  return 0xF & (('0' <= c && c <= '9')? (c - '0') : (toupper(c) - 'A' + 10));
}

int containsValidSlots(int slotsneeded, int slotlen){
  return slotsneeded<slotlen;
}

int marshallError(char* dst,int cursor){
       dst[cursor]='\0';
       return -cursor;
}

void resetUrlState(int state[]){
   state[STAGE]=0;
   state[STEP]=0;
   state[CURSOR]=0;
}
int validHex(char* ch){
    return ((int)*ch>=48&&(int)*ch<=57)||((int)*ch>=65&&(int)*ch<=70)||((int)*ch>=97&&(int)*ch<=102);
}

void url_stream_decode(const char *ch,char* dest, int state[]){
  //printf("%c,%d\n",*ch,state[CURSOR]);
   if(state[STAGE]==0){
      if(*ch=='+'){
        dest[state[CURSOR]++]=' ';
      }else if(*ch=='%'){
        state[STAGE]=1;
      }else{
        dest[state[CURSOR]++]=*ch;
      }
   }else if(state[STAGE]==1){
      state[STAGE]=2; 
   }else if (state[STAGE]==2){
//printf("Make char %c:%d, %c:%d\n",*(ch-1),(int)(*(ch-1)),*ch,(int)(*ch));
      if(validHex((char*)ch)&&validHex((char *)(ch-1))){ 
       dest[state[CURSOR]++] = (c_to_hex(*(ch-1)) << 4) + c_to_hex(*ch);
      }
      state[STAGE]=0;
   }
}


int url_get_param(const char *queryString, const char *paramName, char *dest, int dlen){
  int stage,paramLen,cursor,maxslots;
  int decodeState[3];
  if(paramName==NULL||queryString==NULL) return -1;

  paramLen=strlen(paramName);
  stage=-1;
  cursor=0;
  maxslots=dlen-1;
  resetUrlState(decodeState);


//printf("orig maxslots:%d,%d,%d,%d\n",maxslots,dlen,decodeState[STEP],decodeState[CURSOR]);

  while(*queryString){
    if(stage==-1){
     //find param
     if(!cursor){
       if(*queryString==paramName[cursor]){
        cursor++;
       }else{
         //this is not the param we are looking for..reset
         stage=-21;
       }
     }else{
      if(*queryString==paramName[cursor]){
        cursor++;
      }else{
        //this is not the param we are looking for..reset
         stage=-21;
      }
     } 
     if(paramLen==cursor){
       //printf("FOUND\n");
       stage=-2;
     }
    }else if(stage==-2){
      //find equals sign
      if(*queryString=='='){
        stage=-3;
      }else{
        //could not find equals...must reset to nearest &
        stage=-21;
      }
    }else if(stage==-21){
       if(*queryString=='?'||*queryString=='&'){
        stage=-1;
        cursor=0;
       }
    }else if(stage==-3){
       //fill buffer until end 
       if(decodeState[CURSOR]>=maxslots){
         //printf("cursor:%d, slots:%d",decodeState[CURSOR],maxslots);
         decodeState[CURSOR]=-decodeState[CURSOR];
         break;
       }else if(*queryString!='\0'&&*queryString!='&'){
        url_stream_decode(queryString,dest,decodeState);
       }else{
         stage=4;
       }
    }
    
  queryString++; 
  }
if(decodeState[CURSOR]>=0){
   dest[decodeState[CURSOR]]='\0';
}else{
   dest[-decodeState[CURSOR]]='\0';
}
return decodeState[CURSOR];
}


/* Decodes a url encoded cstring given as src
*and places result into dst
*
*@returns length of decoded string on success, -length of
*what was decoded on failure
*/
int url_decode(const char *src, char *dst, int dlen){
  int maxSlots;
  int decodeState[3];

  if (!src || !dst)
    return 0;

  maxSlots=dlen-1;
  resetUrlState(decodeState);
    while (*src) {
       if(decodeState[CURSOR]>=maxSlots){
         //printf("cursor:%d, slots:%d",decodeState[CURSOR],maxSlots);
         decodeState[CURSOR]=-decodeState[CURSOR];
         break;
       }else if(*src!='\0'){
        url_stream_decode(src,dst,decodeState);
       }
     src++; 
    }

if(decodeState[CURSOR]>=0){
   dst[decodeState[CURSOR]]='\0';
}else{
   dst[-decodeState[CURSOR]]='\0';
}

return decodeState[CURSOR];

}



/**
*Encodes a url encoded cstring given as src
*and places result into dst
*
*@returns length of Encoded string on success, -length of 
*what was Encoded on failure
*/
int url_encode(const char *src, char *dst, int dlen) {
  int  i, j, len;
  int maxslots=dlen-1;
  char c;

  static const char hc[] = "0123456789ABCDEF";

  len = strlen(src);
  j   = 0;
  //  for (i = 0; i < len, j<dlen; i++) {
  for (i = 0; i < len; i++) {
    switch (c = src[i]) {
      case ' ':
        if(containsValidSlots(j,maxslots)){
           dst[j++] = '+';
        }else{
           return marshallError(dst,j); 
        }
        break;

      case '!': case '"': case '#': case '$': case '%': case '&': case '(': case ')':
      case '+': case ',': case ':': case ';': case '<': case '=': case '>': case '?':
      case '[': case '\'': case '\\': case ']': case '^': case '`': case '{': case '|':
      case '}': case '~': case '/': case '@':
      if(containsValidSlots(j+2,maxslots)){
        dst[j++] = '%';
        dst[j++] = hc[(c >> 4) & 0xF];
        dst[j++] = hc[c & 0xF];
      }else{
        return marshallError(dst,j);
      }
        break;

      default:
        if (iscntrl(c) || !isascii(c)) {
            if(containsValidSlots(j+2,maxslots)){
              dst[j++] = '%';
              dst[j++] = hc[(c >> 4) & 0xF];
              dst[j++] = hc[c & 0xF];
            }else{
              return marshallError(dst,j);
            }

        }
        else
           if(containsValidSlots(j,maxslots)){
             dst[j++] = c;
           }else{
            return  marshallError(dst,j);
           }

    }
  }
 
  dst[j] = '\0';
  return j;
}


char b64string[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

long base64_encode (char *to, char *from, unsigned int len){
	char *fromp = from;
	char *top = to;
	unsigned char cbyte;
	unsigned char obyte;
	char end[3];

	for (; len >= 3; len -= 3) {
		cbyte = *fromp++;
		*top++ = b64string[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 4);			/* 0000 1111 */
		*top++ = b64string[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 6);			/* 0000 0011 */
		*top++ = b64string[(int)obyte];
		*top++ = b64string[(int)(cbyte & 0x3F)];/* 0011 1111 */
	}

	if (len) {
		end[0] = *fromp++;
		if (--len) end[1] = *fromp++; else end[1] = 0;
		end[2] = 0;

		cbyte = end[0];
		*top++ = b64string[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = end[1];
		obyte |= (cbyte >> 4);
		*top++ = b64string[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		if (len) *top++ = b64string[(int)obyte];
		else *top++ = '=';
		*top++ = '=';
	}
	*top = 0;
	return top - to;
}

char b64Urlstring[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
long base64Url_encode (char *to, char *from, unsigned int len){
	char *fromp = from;
	char *top = to;
	unsigned char cbyte;
	unsigned char obyte;
	char end[3];

	for (; len >= 3; len -= 3) {
		cbyte = *fromp++;
		*top++ = b64Urlstring[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 4);			/* 0000 1111 */
		*top++ = b64Urlstring[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 6);			/* 0000 0011 */
		*top++ = b64Urlstring[(int)obyte];
		*top++ = b64Urlstring[(int)(cbyte & 0x3F)];/* 0011 1111 */
	}

	if (len) {
		end[0] = *fromp++;
		if (--len) end[1] = *fromp++; else end[1] = 0;
		end[2] = 0;

		cbyte = end[0];
		*top++ = b64Urlstring[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = end[1];
		obyte |= (cbyte >> 4);
		*top++ = b64Urlstring[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		if (len) *top++ = b64Urlstring[(int)obyte];
	}
	*top = 0;

	return top - to;
}

#define badchar(c,p) (!(p = memchr(b64string, c, 64)))

long base64_decode (char *to, char *from, unsigned int len){
	char *fromp = from;
	char *top = to;
	char *p;
	unsigned char cbyte;
	unsigned char obyte;
	int padding = 0;

	for (; len >= 4; len -= 4) {
		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else {
			if (badchar(cbyte, p)) return -1;
			cbyte = (p - b64string);
		}
		obyte = cbyte << 2;		/* 1111 1100 */

		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else {
			if (badchar(cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte >> 4;		/* 0000 0011 */
		*top++ = obyte;

		obyte = cbyte << 4;		/* 1111 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else {
			padding = 0;
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte >> 2;		/* 0000 1111 */
		*top++ = obyte;

		obyte = cbyte << 6;		/* 1100 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else {
			padding = 0;
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte;			/* 0011 1111 */
		*top++ = obyte;
	}

	*top = 0;
	if (len) return -1;
	return (top - to) - padding;
}

long base64Url_decode (char *to, char *from, unsigned int len){
	char *fromp = from;
	char *top = to;
	char *p;
	unsigned char cbyte;
	unsigned char obyte;
	int padding = 0;
	char padded_src[URL_MAX_VAR_SIZE];

	// add padding
	if(len%4) {
		memcpy(padded_src,  from, len);
		memcpy(padded_src+len, "====", 4);
		fromp = padded_src;
		len+=4;
	}

	for (; len >= 4; len -= 4) {
		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else {
			if(cbyte=='-') { cbyte='+'; } else if(cbyte=='_') { cbyte='/'; }
			if (badchar(cbyte, p)) return -1;
			cbyte = (p - b64string);
		}
		obyte = cbyte << 2;		/* 1111 1100 */

		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else {
			if(cbyte=='-') { cbyte='+'; } else if(cbyte=='_') { cbyte='/'; }
			if (badchar(cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte >> 4;		/* 0000 0011 */
		*top++ = obyte;

		obyte = cbyte << 4;		/* 1111 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else {
			padding = 0;
			if(cbyte=='-') { cbyte='+'; } else if(cbyte=='_') { cbyte='/'; }
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte >> 2;		/* 0000 1111 */
		*top++ = obyte;

		obyte = cbyte << 6;		/* 1100 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else {
			padding = 0;
			if(cbyte=='-') { cbyte='+'; } else if(cbyte=='_') { cbyte='/'; }
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		obyte |= cbyte;			/* 0011 1111 */
		*top++ = obyte;
	}

	// handle the remaining bytes
	*top = 0;

	return (top - to) - padding;
}

char* url_getParam(pool* p, char* queryString,const char* name){
	char tmp[URL_MAX_VAR_SIZE];		
	if(url_get_param(queryString,name,tmp,URL_MAX_VAR_SIZE)>0){
		return apr_pstrdup(p,tmp);
	}
	return NULL;
}

char* url_addParam(pool* p, char* url, char* pName, char* pVal){
	char tmp[URL_MAX_VAR_SIZE];
	char* ret=NULL;
	
	if(pName==NULL||pVal==NULL||url==NULL){
		return url;		
	}
	
	if(url_encode(pVal,tmp,URL_MAX_VAR_SIZE)>0){
		ret=apr_pstrcat(p,url,"?",pName,"=",tmp,NULL);
	}else{
		ret=url;
	}
	
	return ret;
}
//This appends param to query string.
char* url_appendParamToQuery(pool*p, char*query, char*pName,char*pVal){
	char* tmp;
	
	if(pName==NULL||pVal==NULL)	return query;//return query as is
	
	tmp=url_encode2(p,pVal);
	if(query==NULL) {return apr_pstrcat(p,pName,"=",tmp,NULL);}
	return apr_pstrcat(p,query,"&",pName,"=",tmp,NULL);
}
char* url_encode2(pool* p, char* src){
	int dlen=0;
	int slen=0;
	char* tmp=NULL;
	if(src==NULL) return NULL;
	
	slen=strlen(src);
	if(slen==0) return NULL;
	
	dlen=(slen*3)+1;
	tmp=apr_pcalloc(p,dlen);
	url_encode(src,tmp,dlen);

	return apr_pstrdup(p,tmp);
}
char* url_decode2(pool* p, char* src){
	int dlen=0;
	int slen=0;
	char* tmp=NULL;
	if(src==NULL) return NULL;
	
	slen=strlen(src);
	if(slen==0) return NULL;
	
	dlen=slen+1;
	tmp=apr_pcalloc(p,dlen);
	url_decode(src,tmp,dlen);
	
	return apr_pstrdup(p,tmp);
}

