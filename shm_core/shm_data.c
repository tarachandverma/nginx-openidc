#include <shm_data.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <shm_dup.h>
#include "apache_macros.h"
#include <common_utils.h>
#include <log-utils/logging.h>
#include <oidc_globals.h>

	static smutex_refresh_mutex* shdata_getMutex(pool *p){
		smutex_refresh_mutex* mutex;
		apr_status_t status;
		
		mutex=apr_palloc(p,sizeof(smutex_refresh_mutex));
		mutex->isRefreshing=0;
		status = apr_thread_mutex_create(&(mutex->thread_mutex),APR_THREAD_MUTEX_DEFAULT, p);
		if (status != APR_SUCCESS) {
			return NULL;
		}
		return mutex;
	}
	
	static int shdata_getMutexLock(smutex_refresh_mutex* mutex){	
		apr_status_t status;	
		status=apr_thread_mutex_lock(mutex->thread_mutex);
		if(status==APR_SUCCESS){
			if(!(mutex->isRefreshing)){
				mutex->isRefreshing=1;
				apr_thread_mutex_unlock(mutex->thread_mutex);
				return 1;
			}
			apr_thread_mutex_unlock(mutex->thread_mutex);
		}
		return 0;
	}
	
	static int shdata_isRefreshing(smutex_refresh_mutex* mutex){
		return mutex->isRefreshing;
	}
	
	static void shdata_unLockMutex(smutex_refresh_mutex* mutex){
		 mutex->isRefreshing=0;
	}


	int shdata_syncself(pool* p, shared_heap* sheap, rfunc function, void* userdata){
		APACHE_LOG_DEBUG("SHMCLIENT CHECK SYNC");
		if(sheap!=NULL&&sheap->page!=NULL){
			APACHE_LOG_DEBUG("SHMCLIENT CHECK SYNC1");
			if(sheap->timestamp!=sheap->page->timestamp){
				APACHE_LOG_DEBUG("CLIENT REFRESH");
				if(!shdata_isRefreshing(sheap->refresh_mutex)){
					if(shdata_getMutexLock(sheap->refresh_mutex)){				
						sheap->local_segment=sheap->page->frontsegment;
						sheap->timestamp=sheap->page->timestamp;
						sheap->flipcount++;

						//do attach logic
						APACHE_LOG_DEBUG("Attaching to new update");
						if(function!=NULL){
							(*function)(p,sheap,userdata);
						}
						shdata_unLockMutex(sheap->refresh_mutex);
						return 2;
					}
				}
				return 1;		
			}
			APACHE_LOG_DEBUG("SHMCLIENT CHECK SYNC2");
		}else{
			return -1;
		}
	return 0;
	}

char* shdata_32BitString_copy(shared_heap* sheap, char* str){
	int slen;
	char* nstr;
	
	if(str==NULL){
		return NULL;
	}
	slen=shdup_32BitString_size(str);	
	nstr=shdata_shpalloc(sheap,slen);
	memset(nstr,'\0',slen);
	memcpy(nstr,str,strlen(str));
	//APACHE_LOG_DEBUG("reach1");
return nstr;
}

// Copies source array of native data types to sheap array.
array_header* array_headerToSheap(shared_heap* sheap, array_header* sarray){
        array_header* dst;

        dst=(array_header*)shdata_shpalloc(sheap, sizeof(array_header));
        memcpy(dst,sarray,sizeof(array_header));

        if(sarray->elts!=NULL){
                dst->elts=shdata_shpalloc(sheap,(sarray->nelts*sarray->elt_size));
                memcpy(dst->elts,(void*)(sarray->elts), (sarray->nelts*sarray->elt_size));
        }else{
                dst->elts=NULL;
        }
	dst->pool=NULL;
return dst;
}

	shared_page* shdata_getNewSharedPage(pool* p, apr_shm_t** shm_t, int segmentsize, char* path){
		int overheadsize,usersize, x;
		shared_page* page;
		apr_status_t rv;
		overheadsize=sizeof(shared_page);
		usersize=segmentsize*2;
		char buf[200];

		rv=apr_shm_create(shm_t,overheadsize+usersize,path,p);
		lc_printLog("\n shdata_getNewSharedPage - apr_shm_create status : ec:%d desc:%s size %ld path %s \n",
									 rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))), (overheadsize+usersize), SAFESTR(path) );
		
#ifdef WIN32
		if(rv==APR_EEXIST) { // try to attach it; seems windows specific behaviour
			rv = apr_shm_attach(shm_t,path,p);
		}
#endif
		if(rv!=APR_SUCCESS){
			//if failure then try to remove shm segment and try again
			rv = apr_shm_attach(shm_t,path,p);
			lc_printLog("\n shdata_getNewSharedPage - apr_shm_attach status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
			if(rv==APR_SUCCESS){
				rv = apr_shm_destroy(*shm_t);
				lc_printLog("\n shdata_getNewSharedPage - apr_shm_destroy status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
				rv=apr_shm_create(shm_t,overheadsize+usersize,path,p);
				lc_printLog("\n shdata_getNewSharedPage - apr_shm_create status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
				//if again failure..possible bad shm file...remove and retry
				if(rv!=APR_SUCCESS){
					rv=apr_file_remove(path,p);
					lc_printLog("\n shdata_getNewSharedPage - apr_file_remove status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
					if(rv==APR_SUCCESS){
						rv=apr_shm_create(shm_t,overheadsize+usersize,path,p);
						lc_printLog("\n shdata_getNewSharedPage - apr_shm_create status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
					}
				}
			}else{ //if cannot attach blow file away and try again
				rv=apr_file_remove(path,p);
				lc_printLog("\n shdata_getNewSharedPage - apr_file_remove status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
				if(rv==APR_SUCCESS){
					rv=apr_shm_create(shm_t,overheadsize+usersize,path,p);
					lc_printLog("\n shdata_getNewSharedPage - apr_shm_create status : ec:%d desc:%s \n", rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))) );
				}
			}
		}
		
		if(rv==APR_SUCCESS){
			APACHE_LOG_DEBUG1("SHARED PAGES CREATED: Path=%s",path);
			page=apr_shm_baseaddr_get(*shm_t);
			page->itemmax=MAX_PAGE_ITEMS;
			page->segmentsize=segmentsize;
			page->timestamp=SHM_TIMESTAMP_INIT;
			page->flipcount=0;
			page->frontsegment=1;
			page->backsegment=0;
			page->data=(char*)(page+1);
			page->cursor=page->data;
			for(x=0;x<SEGMENTS_PER_PAGE;x++){
				page->segments[x].itemcount=0;
			}			
			return page;
		}
		APACHE_LOG_DEBUG("SHARED PAGE BAD");
	return NULL;
	}

	static shared_page* shdata_attachToSharedPage(pool* p, apr_shm_t** shm_t, int segmentsize, char* path){
		int overheadsize,usersize, x;
		shared_page* page;
		apr_status_t rv;
		overheadsize=sizeof(shared_page);
		usersize=segmentsize*2;
			
		rv = apr_shm_attach(shm_t,path,p); 
		if(rv!=APR_SUCCESS){
			APACHE_LOG_DEBUG("UNABLE TO ATTACH TO SHARED PAGE BAD");
		}
		
		if(rv==APR_SUCCESS){
			APACHE_LOG_DEBUG1("SHARED PAGES CREATED: Path=%s",path);
			page=apr_shm_baseaddr_get(*shm_t);
			page->itemmax=MAX_PAGE_ITEMS;
			page->segmentsize=segmentsize;
			page->timestamp=SHM_TIMESTAMP_INIT;
			page->flipcount=0;
			page->frontsegment=1;
			page->backsegment=0;
			page->data=(char*)(page+1);
			page->cursor=page->data;
			for(x=0;x<SEGMENTS_PER_PAGE;x++){
				page->segments[x].itemcount=0;
			}			
			return page;
		}
		APACHE_LOG_DEBUG("SHARED PAGE BAD");
	return NULL;
	}	

	shared_page* shdata_getNewUnNamedSharedPage(pool* p, apr_shm_t** shm_t, int segmentsize, char* path){
		int overheadsize,usersize, x;
		shared_page* page;
		apr_status_t rv;
		overheadsize=sizeof(shared_page);
		usersize=segmentsize*2;
		char buf[200];

		rv=apr_shm_create(shm_t,overheadsize+usersize,NULL,p);
		lc_printLog("\n shdata_getNewUnNamedSharedPage - apr_shm_create with unnamed shm status : ec:%d desc:%s size %ld  \n",
									rv, SAFESTR(apr_strerror(rv, buf, sizeof(buf))), (overheadsize+usersize));
		if(rv != APR_SUCCESS) {
			if(rv == APR_ENOTIMPL && path != NULL) {
				return shdata_getNewSharedPage(p, shm_t, segmentsize, path);
			}
		}
		else {
			APACHE_LOG_DEBUG("UNNAMED SHARED PAGES CREATED");
			page=apr_shm_baseaddr_get(*shm_t);
			page->itemmax=MAX_PAGE_ITEMS;
			page->segmentsize=segmentsize;
			page->timestamp=SHM_TIMESTAMP_INIT;
			page->flipcount=0;
			page->frontsegment=1;
			page->backsegment=0;
			page->data=(char*)(page+1);
			page->cursor=page->data;
			for(x=0;x<SEGMENTS_PER_PAGE;x++){
				page->segments[x].itemcount=0;
			}
			return page;
		}
		APACHE_LOG_DEBUG("UNNAMED SHARED PAGE BAD");
		return NULL;
	}

	shared_heap* shdata_sheap_make(pool* p, int segmentSize, char* path){
		int x;
		shared_heap* sheap;
		apr_shm_t* shm_t;
		//struct shmid_ds ds;
		
		sheap=(shared_heap*)apr_palloc(p,sizeof(shared_heap));

#ifdef WIN32
		sheap->page=shdata_getNewSharedPage(p,&shm_t,segmentSize,path);
#else
		if(djrglobals_isUnnamedSHMEnabled() == FALSE && path != NULL) {
			sheap->page=shdata_getNewSharedPage(p,&shm_t,segmentSize,path);
		}
		else {
			sheap->page=shdata_getNewUnNamedSharedPage(p,&shm_t,segmentSize,path);
		}
#endif
		
		sheap->timestamp=-1;
		sheap->flipcount=0;
		sheap->local_segment=-1;		
		sheap->shm_main=shm_t;
		sheap->refresh_mutex=shdata_getMutex(p);
		if(sheap->page==NULL){return NULL;}
	return sheap;
	}

	shared_heap* shdata_sheap_attach(pool* p, int segmentSize, char* path){
		int x;
		shared_heap* sheap;
		apr_shm_t* shm_t;
		//struct shmid_ds ds;
		
		sheap=(shared_heap*)apr_palloc(p,sizeof(shared_heap));
		sheap->page=shdata_attachToSharedPage(p,&shm_t,segmentSize,path);
		
		sheap->timestamp=-1;
		sheap->flipcount=0;
		sheap->local_segment=-1;		
		sheap->shm_main=shm_t;
		sheap->refresh_mutex=shdata_getMutex(p);
		if(sheap->page==NULL){return NULL;}
	return sheap;
	}

	char* shdata_getItem(shared_heap* sheap,const char* ID){
		int x;
		char* buf=NULL;
		segment_header* sh;

		sh=&(sheap->page->segments[sheap->local_segment]);	
		for(x=0;x<sh->itemcount;x++){
			if(strcmp(sh->items[x].ITEMID,ID)==0){
				buf=((char*)(sheap->page->data))+(sh->items[x].offset);	
				//printf("D:%ld, b: %ld, o:%d\n",sheap->page->data,buf, sh->items[x].offset);
				return buf;
			}
		}
	return buf;
	}
	int shdata_getFlipCount(shared_heap* sheap){
		return sheap->page->flipcount;
	}
	time_t* shdata_getLastFlipTime(shared_heap* sheap){
		return &(sheap->page->timestamp);
	}

	void shdata_PublishBackSeg(shared_heap* sheap){
		int tmp;
		tmp=sheap->page->backsegment;
		sheap->page->backsegment=sheap->page->frontsegment;
		sheap->page->frontsegment=tmp;
		sheap->page->flipcount++;
		APACHE_LOG_DEBUG1("PUBLISH PAGE: %d",sheap->page->flipcount);
		sheap->page->timestamp=time(NULL);
	}
	void shdata_rollback(shared_heap* sheap){
		int x,y;
		page_item* item;
		shared_page* p;
		segment_header* sh;

		APACHE_LOG_DEBUG("ROLLBACK BACKBUFFER SHEAP");

		p=sheap->page;
		sh=&(sheap->page->segments[sheap->page->backsegment]);

		if(sh->itemcount>=MAX_PAGE_ITEMS){
			y=MAX_PAGE_ITEMS-1;
		}else{
			y=sh->itemcount;
		}
		for(x=0;x<=y;x++){			
			item=&(sh->items[x]);
			memset(item->ITEMID,'\0',PAGE_ITEM_CHARS);	
			memset(item->INFO,'\0',PAGE_ITEM_CHARS);
		}
		p->cursor=p->data+(p->backsegment*p->segmentsize);
		sh->itemcount=0;
	}
	void shdata_BeginTagging(shared_heap* sheap){
		shared_page* p=sheap->page;		
		p->cursor=p->data+(p->backsegment*p->segmentsize);
		APACHE_LOG_DEBUG1("BEGIN TAGGING @ %d",p->cursor);
		p->segments[p->backsegment].itemcount=0;
	}
	void shdata_OpenItemTag(shared_heap* sheap,const char* ID){
		segment_header* sh=&(sheap->page->segments[sheap->page->backsegment]);
		page_item* item;
		item=&(sh->items[sh->itemcount]);
		memset(item->ITEMID,'\0',PAGE_ITEM_CHARS);
		memset(item->INFO,'\0',PAGE_ITEM_CHARS);
		strcpy(item->ITEMID,ID);	
		item->offset=sheap->page->cursor-sheap->page->data;
	}
	void shdata_AppendInfo(shared_heap* sheap,char* info){
		segment_header* sh=&(sheap->page->segments[sheap->page->backsegment]);
		page_item* item=&(sh->items[sh->itemcount]);
		strcat(item->INFO,info);
	}
	void shdata_CloseItemTag(shared_heap* sheap){
		segment_header* sh=&(sheap->page->segments[sheap->page->backsegment]);
		page_item* item;
		item=&(sh->items[sh->itemcount]);
		item->size=sheap->page->cursor-sheap->page->data-item->offset;		
		sh->itemcount++;
	}
	void shdata_CloseItemTagWithInfo(shared_heap* sheap, char* info){
		segment_header* sh=&(sheap->page->segments[sheap->page->backsegment]);
		page_item* item;	
		item=&(sh->items[sh->itemcount]);
		strncpy(item->INFO,info,PAGE_ITEM_CHARS-1);
		shdata_CloseItemTag(sheap);
	}
	int shdata_cursor(shared_heap* sheap){
			if(sheap==NULL||sheap->page==NULL){
				return -1;	
			}
			return sheap->page->cursor-sheap->page->data;
	}
	char* shdata_shpalloc(shared_heap* sheap, int size){
                shared_page* page;
                char* retchar;
                int spaceleft;

                page=sheap->page;
		spaceleft=page->segmentsize-(page->cursor-page->data)+(page->segmentsize*page->backsegment);
                if(spaceleft<size){
					APACHE_LOG_DEBUG("OUT OF SHEAP SPACE");
                    return NULL;
                }
				
                retchar=page->cursor;
                page->cursor+=size;
        return retchar;
    }

	char* shdata_shpcalloc(shared_heap* sheap, int size){
		char* tmp;
		tmp=shdata_shpalloc(sheap,size);
		memset(tmp,0,size);
		return tmp;
	}
	void* shdata_memcpy(shared_heap* sheap, void* src, int size){
		void* ret=NULL;
		
		if(src!=NULL&&size>0){
			ret=shdata_shpcalloc(sheap,size);
			memcpy(ret,src,size);
		}
		return ret;
	}
	
	static apr_sockaddr_t* shdata_copyAddr1(shared_heap* sheap,apr_sockaddr_t* addr){
		apr_sockaddr_t* ret=NULL;
		ret=(apr_sockaddr_t*)shdata_memcpy(sheap,addr,sizeof(apr_sockaddr_t));
		ret->hostname=shdata_32BitString_copy(sheap,addr->hostname);
		ret->hostname=shdata_32BitString_copy(sheap,addr->servname);
		ret->ipaddr_ptr=shdata_memcpy(sheap,addr->ipaddr_ptr,addr->ipaddr_len);
		ret->next=NULL;
		return ret;
	}
	apr_sockaddr_t* shdata_sockAddrCpy(shared_heap* sheap, apr_sockaddr_t* addr){
		apr_sockaddr_t* ret=NULL, *cur=NULL,*curShm=NULL;
		
		if(addr!=NULL){
			cur=addr;
			ret=curShm=shdata_copyAddr1(sheap,addr);
			while(cur->next!=NULL){
				cur=cur->next;
				curShm->next=shdata_copyAddr1(sheap,cur);
				curShm=curShm->next;
			}
		}
		
		return ret;
	}
