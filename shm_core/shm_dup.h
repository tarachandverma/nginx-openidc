#ifndef __TCREWRITE_SHM_DUP__H_
#define __TCREWRITE_SHM_DUP__H_

#include <sys/types.h>
#include "apache_typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif
	
int shdup_32BitString_size(char* str);
char* shdup_32BitString_copy(char** icharbuf, char* str);

int shdup_arrayheader_size(array_header* arr);

#ifdef __cplusplus
}
#endif
	
#endif
