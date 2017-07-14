#include "shm_apr.h"
#include "shm_data.h"
#include "common_utils.h"

	static void shapr_make_array_core(array_header *res, shared_heap* sheap,int nelts, int elt_size, int clear){			    
 	   /*
    	* Assure sanity if someone asks for
   		* array of zero elts.
    	*/
    	if (nelts < 1) {
    	    nelts = 1;
    	}

   		if (clear) {
    	    res->elts = shdata_shpcalloc(sheap, nelts * elt_size);
    	}else {
        	res->elts = shdata_shpalloc(sheap, nelts * elt_size);
    	}

    	res->pool = NULL;
    	res->elt_size = elt_size;
    	res->nelts = 0;		/* No active elements yet... */
    	res->nalloc = nelts;	/* ...but this many allocated */
	}

	array_header* shapr_array_make(shared_heap* sheap, int nelts, int elt_size){
	    array_header *res;
		
	    res = (array_header*) shdata_shpalloc(sheap,sizeof(array_header));
    	shapr_make_array_core(res, sheap, nelts, elt_size, 1);
    	return res;
	}

	void * shapr_array_push(shared_heap* sheap, array_header *arr){
		int new_size;
		char *new_data;

		if (arr->nelts == arr->nalloc) {
        	new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;       		

        	new_data = shdata_shpalloc(sheap, arr->elt_size * new_size);

        	memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
        	memset(new_data + arr->nalloc * arr->elt_size, 0, arr->elt_size * (new_size - arr->nalloc));
               
        	arr->elts = new_data;
        	arr->nalloc = new_size;
    	}

    	++arr->nelts;
    	return arr->elts + (arr->elt_size * (arr->nelts - 1));
	}

	array_header* shapr_parseLongArrayFromCsv(shared_heap* sheap, int arraySz, const char* delim, char* src){
		char *srccpy=NULL, *prodStr=NULL, *p1=NULL;
        long *prodId=NULL, prodlook=0;
        char* end=NULL;
        array_header* arr=(array_header*)shapr_array_make(sheap,arraySz,sizeof(long));
        if(src==NULL){return arr;}
        
        srccpy=shdata_32BitString_copy(sheap,src);
        
        if(arr==NULL){
                return NULL;
        }
        prodStr=apr_strtok(srccpy,delim,&p1);
        while(prodStr!=NULL){
               // prodId= (long *) shapr_array_push(sheap,arr);
               // *prodId = (long) atol(prodStr);
               prodlook = strtol(prodStr,&end,10);
                if(*end=='\0'){
                	prodId= (long *) shapr_array_push(sheap,arr);
                	*prodId=prodlook;
                }
                prodStr =strtok_r(NULL,delim,&p1);
        }
		return arr;
	}
	// Copies source array of char* to sheap array.
	array_header* shapr_copyStringArrayToSheap(shared_heap* sheap, array_header* sarray){
		int i;
		char**place;
		array_header* dstArr;
		
		if(sarray==NULL||sarray->nelts<1) return NULL;
		
		dstArr=shapr_array_make(sheap,sarray->nelts,sizeof(char*));
		for(i=0;i<sarray->nelts;i++){
			place=(char**)shapr_array_push(sheap,dstArr);
			*place=shdata_32BitString_copy(sheap,(char*)cu_getElement(sarray,i));
		}
		return dstArr;
	}	
	array_header* shapr_parseStringArrayFromCsv(shared_heap* sheap, int arraySz, const char* delim, char* src){
		char *srccpy=NULL, *prodStr=NULL, *p1=NULL;
        char **val=NULL;
        array_header* arr=(array_header*)shapr_array_make(sheap,arraySz,sizeof(char*));
        if(src==NULL){return arr;}
        
        srccpy=shdata_32BitString_copy(sheap,src);
        
        if(arr==NULL){
                return NULL;
        }
        prodStr=apr_strtok(srccpy,delim,&p1);
        while(prodStr!=NULL){
                val= (char**) shapr_array_push(sheap,arr);
                *val = prodStr;
                prodStr =strtok_r(NULL,delim,&p1);
        }
                
		return arr;
	}

	typedef struct shapr_hash_entry_t shapr_hash_entry_t;

	struct shapr_hash_entry_t {
  		shapr_hash_entry_t *next;
    	unsigned int      hash;
    	const void       *key;
    	apr_ssize_t       klen;
    	const void       *val;
	};

	/*
	 * Data structure for iterating through a hash table.
	 *
	 * We keep a pointer to the next hash entry here to allow the current
	 * hash entry to be freed or otherwise mangled between calls to
	 * apr_hash_next().
	 */
	struct shapr_hash_index_t {
 	   shapr_hash_t         *ht;
 	   shapr_hash_entry_t   *this, *next;
 	   unsigned int        index;
	};

	/*
	 * The size of the array is always a power of two. We use the maximum
	 * index rather than the size so that we can use bitwise-AND for
 	 * modular arithmetic.
	 * The count of hash entries may be greater depending on the chosen
	 * collision rate.
	 */
	struct shapr_hash_t {
	    shapr_hash_entry_t   **array;
	    shapr_hash_index_t     iterator;  /* For apr_hash_first(NULL, ...) */
	    unsigned int         count, max;
	    shapr_hash_entry_t    *free;  /* List of recycled entries */
	};

	#define INITIAL_MAX 127 /* tunable == 2^n - 1 */


	static shapr_hash_entry_t **shapr_alloc_array(shared_heap* sheap, shapr_hash_t *ht, unsigned int max){
  		return (shapr_hash_entry_t **)shdata_shpcalloc(sheap, sizeof(*ht->array) * (max + 1));
	}

	shapr_hash_t* shapr_hash_make(shared_heap* sheap){
    	shapr_hash_t *ht;
    	ht = (shapr_hash_t*)shdata_shpalloc(sheap, sizeof(shapr_hash_t));
    	ht->free = NULL;
    	ht->count = 0;
    	ht->max = INITIAL_MAX;
    	ht->array = shapr_alloc_array(sheap,ht, ht->max);
    	return ht;
	}


	void shapr_hash_this(shapr_hash_index_t *hi,
                                const void **key,
                                apr_ssize_t *klen,
                                void **val){
	    if (key)  *key  = hi->this->key;
	    if (klen) *klen = hi->this->klen;
	    if (val)  *val  = (void *)hi->this->val;
	}

	/*
	 * This is where we keep the details of the hash function and control
	 * the maximum collision rate.
	 *
	 * If val is non-NULL it creates and initializes a new hash entry if
	 * there isn't already one there; it returns an updatable pointer so
	 * that hash entries can be removed.
	 */

	static shapr_hash_entry_t **shapr_find_entry(shared_heap* sheap,shapr_hash_t *ht,const void *key,apr_ssize_t klen,const void *val){
                       
    	shapr_hash_entry_t **hep, *he;
    	const unsigned char *p;
    	unsigned int hash;
    	apr_ssize_t i;

    /*
     * This is the popular `times 33' hash algorithm which is used by
     * perl and also appears in Berkeley DB. This is one of the best
     * known hash functions for strings because it is both computed
     * very fast and distributes very well.
     *
     * The originator may be Dan Bernstein but the code in Berkeley DB
     * cites Chris Torek as the source. The best citation I have found
     * is "Chris Torek, Hash function for text in C, Usenet message
     * <27038@mimsy.umd.edu> in comp.lang.c , October, 1990." in Rich
     * Salz's USENIX 1992 paper about INN which can be found at
     * <http://citeseer.nj.nec.com/salz92internetnews.html>.
     *
     * The magic of number 33, i.e. why it works better than many other
     * constants, prime or not, has never been adequately explained by
     * anyone. So I try an explanation: if one experimentally tests all
     * multipliers between 1 and 256 (as I did while writing a low-level
     * data structure library some time ago) one detects that even
     * numbers are not useable at all. The remaining 128 odd numbers
     * (except for the number 1) work more or less all equally well.
     * They all distribute in an acceptable way and this way fill a hash
     * table with an average percent of approx. 86%.
     *
     * If one compares the chi^2 values of the variants (see
     * Bob Jenkins ``Hashing Frequently Asked Questions'' at
     * http://burtleburtle.net/bob/hash/hashfaq.html for a description
     * of chi^2), the number 33 not even has the best value. But the
     * number 33 and a few other equally good numbers like 17, 31, 63,
     * 127 and 129 have nevertheless a great advantage to the remaining
     * numbers in the large set of possible multipliers: their multiply
     * operation can be replaced by a faster operation based on just one
     * shift plus either a single addition or subtraction operation. And
     * because a hash function has to both distribute good _and_ has to
     * be very fast to compute, those few numbers should be preferred.
     *
     *                  -- Ralf S. Engelschall <rse@engelschall.com>
     */
    	hash = 0;
    	if (klen == APR_HASH_KEY_STRING) {
        	for (p = key; *p; p++) {
            	hash = hash * 33 + *p;
        	}
        	klen = p - (const unsigned char *)key;
    	}else {
        	for (p = key, i = klen; i; i--, p++) {
            	hash = hash * 33 + *p;
        	}
    	}

    	/* scan linked list */
    	for (hep = &ht->array[hash & ht->max], he = *hep;
         	he; hep = &he->next, he = *hep) {
        	if (he->hash == hash
            	&& he->klen == klen
            	&& memcmp(he->key, key, klen) == 0)
            	break;
    	}
    	if (he || !val)
        	return hep;

    	/* add a new entry for non-NULL values */
    	if ((he = ht->free) != NULL)
        	ht->free = he->next;
    	else
        	he = (shapr_hash_entry_t*)shdata_shpalloc(sheap, sizeof(*he));
    	he->next = NULL;
    	he->hash = hash;
    	
    	/*allocate shared memory for key
    	 * this used to be he->key=key;
    	 **/
    	he->key  = shdata_32BitString_copy(sheap,(char*)key);
    	he->klen = klen;
    	he->val  = val;
    	*hep = he;
    	ht->count++;
    	return hep;
	}
	
	shapr_hash_index_t * shapr_hash_next(shapr_hash_index_t *hi){
    	hi->this = hi->next;
    	while (!hi->this) {
        	if (hi->index > hi->ht->max)
            	return NULL;

        	hi->this = hi->ht->array[hi->index++];
    	}
    	hi->next = hi->this->next;
    	return hi;
	}

	shapr_hash_index_t * shapr_hash_first(apr_pool_t* pool, shapr_hash_t *ht){
    	shapr_hash_index_t *hi;
    	if (pool)
        	hi = (shapr_hash_index_t*)apr_palloc(pool, sizeof(*hi));
    	else
        	hi = &ht->iterator;

    	hi->ht = ht;
    	hi->index = 0;
    	hi->this = NULL;
    	hi->next = NULL;
    	return shapr_hash_next(hi);
	}


	/*
	 * Expanding a hash table
	 */
	static void shapr_expand_array(shared_heap* sheap,shapr_hash_t *ht){
	    shapr_hash_index_t *hi;
	    shapr_hash_entry_t **new_array;
	    unsigned int new_max;

	    new_max = ht->max * 2 + 1;
	    new_array = shapr_alloc_array(sheap,ht, new_max);
	    for (hi = shapr_hash_first(NULL, ht); hi; hi = shapr_hash_next(hi)) {
	        unsigned int i = hi->this->hash & new_max;
	        hi->this->next = new_array[i];
	        new_array[i] = hi->this;
	    }
	    ht->array = new_array;
	    ht->max = new_max;
	}

	void shapr_hash_set(shared_heap* sheap,shapr_hash_t *ht,const void *key,apr_ssize_t klen,const void *val){
  		shapr_hash_entry_t **hep;
  		
  		if(key==NULL) return;
  		
  		hep = shapr_find_entry(sheap,ht, key, klen, val);
	    if (*hep) {
        	if (!val) {
            	/* delete entry */
            	shapr_hash_entry_t *old = *hep;
            	*hep = (*hep)->next;
            	old->next = ht->free;
            	ht->free = old;
            	--ht->count;
        	}else {        	
            	/* replace entry */
            	(*hep)->val = val;
            	/* check that the collision rate isn't too high */
            	if (ht->count > ht->max) {
                	shapr_expand_array(sheap,ht);
            	}
        	}
    	}
    	/* else key not present and val==NULL */
	}


	void* shapr_hash_get(shapr_hash_t *ht,const void *key,apr_ssize_t klen){
	    shapr_hash_entry_t *he, **he_p;
		he_p=shapr_find_entry(NULL,ht, key, klen, NULL);
    	he = *he_p;
    	if (he)
    	    return (void *)he->val;
    	else
    	    return NULL;
	}
	unsigned int shapr_hash_count(shapr_hash_t *ht){
		return ht->count;
	}

