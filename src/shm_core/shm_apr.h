#ifndef __TCREWRITE_SHM_APR__H_
#define __TCREWRITE_SHM_APR__H_
#include <sys/types.h>
#include <shm_data.h>

#ifdef __cplusplus
extern "C" {
#endif
	
	/**
 	* Abstract type for hash tables.
 	*/
	typedef struct shapr_hash_t shapr_hash_t;

	/**
	* Abstract type for scanning hash tables.
	*/
	typedef struct shapr_hash_index_t shapr_hash_index_t;

	array_header* shapr_array_make(shared_heap* sheap, int nelts, int elt_size);
	void * shapr_array_push(shared_heap* sheap, array_header *arr);
	array_header* shapr_parseStringArrayFromCsv(shared_heap* sheap, int arraySz, const char* delim, char* src);
	array_header* shapr_parseLongArrayFromCsv(shared_heap* sheap, int arraySz, const char* delim, char* src);
	array_header* shapr_copyStringArrayToSheap(shared_heap* sheap, array_header* sarray);
	
	shapr_hash_t* shapr_hash_make(shared_heap* sheap);
	void* shapr_hash_get(shapr_hash_t *ht,const void *key,apr_ssize_t klen);
	void shapr_hash_set(shared_heap* sheap,shapr_hash_t *ht,const void *key,apr_ssize_t klen,const void *val);
	shapr_hash_index_t * shapr_hash_first(apr_pool_t* pool, shapr_hash_t *ht);
	shapr_hash_index_t* shapr_hash_next(shapr_hash_index_t *hi);
	void shapr_hash_this(shapr_hash_index_t *hi,const void **key,apr_ssize_t *klen,void **val);
	unsigned int shapr_hash_count(shapr_hash_t *ht);
#ifdef __cplusplus
}
#endif

#endif
