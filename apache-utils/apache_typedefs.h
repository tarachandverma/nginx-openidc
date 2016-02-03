/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __TCREWRITE_APACHE_TYPEDEFS__H_
#define __TCREWRITE_APACHE_TYPEDEFS__H_
 
#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <apache_macros.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_uri.h>

	typedef struct apr_pool_t pool;
	typedef struct apr_pool_t ap_pool;
	typedef struct apr_array_header_t array_header;
	typedef apr_uri_t uri_components;
	typedef struct apr_table_t table;
 
#endif
