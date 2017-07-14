
#include <string.h>
#include <shm_dup.h>
#include <math.h>


int shdup_32BitString_size(char* str){
	int tmp, mod;
	if(str==NULL) return 0;
	
	tmp=strlen(str)+1;
	mod=tmp%4;

	if(mod>0){
		tmp=tmp-mod+4;
	}
return tmp;
}
int shdup_arrayheader_size(array_header* arr){
        int sz=0;
        sz+=sizeof(array_header);
        sz+=arr->elt_size*arr->nelts;
return sz;
}
/**
 * Copies str to icharbuf and returns the beginning of the new string. icharbuf is updated rollingly
 */
char* shdup_32BitString_copy(char** icharbuf, char* str){
	int slen;
	char* buf;
	
	if(str==NULL){
		return NULL;
	}
	
	buf=*icharbuf;

	slen=shdup_32BitString_size(str);	
        memset(buf,'\0',(int)slen);
        memcpy(buf,str, strlen(str));

	*icharbuf+=(int)slen;	
	
return buf;
}

