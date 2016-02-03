/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __DJREWRITE_TOKEN_UTILS__H_
#define __DJREWRITE_TOKEN_UTILS__H_

#include "apache_typedefs.h"

typedef struct {
	char*	text;
	char*	delim;
	int	delim_len;
	size_t	offset;
	pool* p;
} Tokener;


Tokener* tu_getTokenizer (pool* p, char* text, char* delim);
char *tu_next_token(Tokener* tok);
char *tu_remaining_text (Tokener* tok);

#endif
