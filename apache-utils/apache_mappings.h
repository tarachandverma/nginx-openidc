/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __TCREWRITE_APACHE_MAPPINGS__H_
#define __TCREWRITE_APACHE_MAPPINGS__H_

#ifdef NGX_HTTP_OPENIDC
	#include <ngx_config.h>
	#include <ngx_core.h>
	#include <ngx_http.h>
	#include <nginx.h>
#else
	#include "httpd.h"
	#include "http_config.h"
	#include "http_log.h"
	#include "ap_compat.h"
#endif

#endif
