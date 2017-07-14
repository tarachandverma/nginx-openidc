/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __TCREWRITE_APACHE2_COMPAT_H
#define __TCREWRITE_APACHE2_COMPAT_H

#include <apr_version.h>

#if (APR_MAJOR_VERSION>=1)

typedef apr_uint32_t 			apr_atomic_t;

#define apr_atomic_inc 			apr_atomic_inc32
#define apr_atomic_set 			apr_atomic_set32
#define apr_atomic_read 		apr_atomic_read32

#endif // #if APR_MAJOR_VERSION

#endif // #if __TCREWRITE_APACHE2_COMPAT_H
