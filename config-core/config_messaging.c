#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <common_utils.h>
#include <config-core/config_messaging.h>
#include <config-core/config_core.h>
#include <config-core/config_messaging_parsing.h>
#include <log-utils/logging.h>
#include <http-utils/http_client.h>
#include "xml_core.h"

#ifdef NGX_HTTP_DJREWRITE
#else // APACHE
	#include <ap_mpm.h>
#endif

	cfgm_connection* cfgm_newConnectionObj(pool* p){
			cfgm_connection* ret=(cfgm_connection*)apr_palloc(p,sizeof(cfgm_connection));
			ret->wireHeader=cfgm_newWireHeader(p);
			return ret;
	}

	static char* cfgm_getMessageType(cfgm_wire_message* msg){
		if(msg!=NULL){
			return msg->type;
		}
		return NULL;
	}
	
	static char* cfgm_getMessageNodeName(cfgm_wire_message* msg){
		if(msg!=NULL&&msg->header!=NULL){
			return msg->header->nodeName;
		}
		return NULL;
	}
	int cfgm_isRefreshMessage(cfgm_wire_message* msg){
		return (msg!=NULL&&(strcmp(msg->type,"AUTO-REFRESH")==0));
	}
	
	static cfgm_wire_message* cfgm_generateAutoRefreshMessage(pool* p){
		cfgm_wire_header* wireHeader=cfgm_newWireHeader(p);
		cfgm_wire_message* msg=cfgm_newWireMessageType(p,"AUTO-REFRESH",wireHeader);
		return msg;
	}
	
	typedef struct next_refresh_info{
		time_t nextRefreshTimestamp;
	}next_refresh_info;

	static int cfgm_setRefreshTimestampAttribute(pool* p,char* xPath,int type,const char ** attributes,void* userdata){
		int i;
		next_refresh_info* refreshInfo=(next_refresh_info*)userdata;
		for(i=0;attributes[i]; i += 2) {
			if(strcmp(attributes[i],"nextRefreshTime")==0){
				refreshInfo->nextRefreshTimestamp=cu_dateStringToSeconds((char*)attributes[i + 1]);
			}
		}
		return 1;
	}

	static int cfgm_canAutoRefreshNow(pool* p, cfg_service_descriptor* resourceService, char*oidcConfigFile, const time_t lastRefreshTimestamp, mm_logger* logger){
		http_util_result* httpResult=NULL;
		char* reqQuery=NULL;
		char* error = NULL;
		time_t currentTimestamp;
		XmlCore* xCore=NULL;
		char* result=NULL;
		
		if(resourceService==NULL) return FALSE;
		
		currentTimestamp = time(NULL);
		
		reqQuery=apr_pstrcat(p,resourceService->uri,"/",oidcConfigFile, NULL);
		httpResult=hc_get_verbose2(p,reqQuery,resourceService->timeoutSeconds,5,resourceService->userColonPass,NULL,&error);
		
		if(httpResult==NULL||httpResult->data==NULL||!hc_is200_OK(httpResult)) {
			logging_log(logger,"Refresh httpResult Error: %s", (error!=NULL) ? error : "unknown");
			return FALSE;
		}
		
		next_refresh_info refreshInfo;
		refreshInfo.nextRefreshTimestamp = -1;

		xCore=xc_getXmlCore(p);
		xc_addXPathHandler(xCore,"/oidcConfig",0,cfgm_setRefreshTimestampAttribute,NULL,NULL, &refreshInfo);
		result=xc_parseFromStringSourceTextResponse(xCore, httpResult->data);
		if(result!=NULL) {
			logging_log(logger,"Refresh error : %s", result);
			return FALSE;
		}

		if(refreshInfo.nextRefreshTimestamp<0) {
			logging_log(logger,"Refresh nextRefresh not configued");
			return TRUE;
		}
		
		logging_log(logger,"Refresh lastRefreshTimestamp:%d, refreshTimestamp : %d, currentTimestamp:%d",lastRefreshTimestamp,refreshInfo.nextRefreshTimestamp, currentTimestamp);
		
		if( (lastRefreshTimestamp<refreshInfo.nextRefreshTimestamp) && (refreshInfo.nextRefreshTimestamp<=currentTimestamp)) return TRUE;

		logging_log(logger,"Refresh refreshTimestamp : %d is tool old or already processed", refreshInfo.nextRefreshTimestamp);
		return FALSE;
	}

	static void cfgm_internalMessagingLoop(pool* p, char* logsDir, void* localConfig, void* userdata,cfgm_message_recieved_func msgRecFunc){
		#define BUFSIZE 256 
		cfgm_connection* cmConn=cfgm_newConnectionObj(p);
		cfgm_wire_message* msg=NULL;
		char* error=NULL;
		apr_status_t rc;
		apr_time_t 	lastHello=0;
		char errorbuf[512];	
		int errorCode = 0,maxLogFileSizeMB=2;
		time_t lastAutoRefreshTimestamp = time(NULL); // startup time
		
		sprintf(errorbuf,"%s/monitor.log",logsDir);
		mm_logger* logger=logging_getLogger(p,errorbuf,maxLogFileSizeMB);

		cfg_service_descriptor* resourceService=((config_core*)userdata)->globals->resourceService;
		int refreshWaitSeconds = ((config_core*)userdata)->refreshWaitSeconds;
		char* oidcConfigFile=((config_core*)userdata)->oidcConfigFile;
		
		//start wait for message loop
		while(1){
			logging_log(logger,"AutoRefreshing...");
			if(cfgm_canAutoRefreshNow(p, resourceService, oidcConfigFile, lastAutoRefreshTimestamp, logger)){
				msg=cfgm_generateAutoRefreshMessage(p);
				if(msg!=NULL){
					logging_log(logger,"AutoRefresh processing message: %s (%s)",cfgm_getMessageType(msg),cfgm_getMessageNodeName(msg));
					//internal hello handling
					if(msgRecFunc!=NULL){
						(*msgRecFunc)(p,NULL,msg,localConfig,userdata);
					}
					logging_log(logger,"AutoRefresh complete");
					lastAutoRefreshTimestamp = time(NULL); // update with current timestamp;
				}
			}
			usleep(refreshWaitSeconds*1000*1000);
		}
	}
	
	typedef struct djrewrite_messaging_proc_rec{
		char* logDir;
		void* userdata;
		cfgm_init_messaging_func initFunc;
		cfgm_message_recieved_func msgRecFunc;
		apr_proc_t* proc;
	}djrewrite_messaging_proc_rec;
	
	static djrewrite_messaging_proc_rec*cfgm_newMessagingProcRecObj(pool* p, char* logDir,
		void* userdata,
		cfgm_init_messaging_func initFunc, cfgm_message_recieved_func msgRecFunc){
		djrewrite_messaging_proc_rec* mpr=(djrewrite_messaging_proc_rec*)apr_palloc(p,sizeof(djrewrite_messaging_proc_rec));
		mpr->logDir = logDir;
		mpr->userdata = userdata;
		mpr->initFunc = initFunc;
		mpr->msgRecFunc = msgRecFunc;
		mpr->proc = (apr_proc_t*)apr_palloc(p,sizeof(apr_proc_t));
		return mpr;
	}
	
	pool* root_mpr_pool = NULL;	// root process pool created by root process
	void cfgm_startMessagingProcess(djrewrite_messaging_proc_rec*msg,int disableProcessRecovery);

#if 0/*APR_HAS_OTHER_CHILD && !NGX_HTTP_DJREWRITE*/
	static void cfgm_messageProcessRestartCallback(int reason, void *data, apr_wait_t status) {
		djrewrite_messaging_proc_rec* mpr = (djrewrite_messaging_proc_rec*)data;
		int mpm_state;
		int stopping;

		switch (reason) {
			case APR_OC_REASON_DEATH:
				apr_proc_other_child_unregister(data);
				/* If apache is not terminating or restarting,
				 * restart the message processer
				 */
				stopping = 1; 	/* if MPM doesn't support query,
	                           	 * assume we shouldn't restart message process
	                             */
				if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS &&
					mpm_state != AP_MPMQ_STOPPING) {
					stopping = 0;
				}
				if (!stopping) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "djrewrite refresh recieved APR_OC_REASON_DEATH, restarting");
					if(mpr!=NULL){
						cfgm_startMessagingProcess(mpr,FALSE);
					}
				}
				break;
              
			case APR_OC_REASON_RESTART:
				/* don't do anything; server is stopping or restarting */
				apr_proc_other_child_unregister(data);
				break;
               
			case APR_OC_REASON_LOST:
				/* Restart the child messaging processor as we lost it */
				apr_proc_other_child_unregister(data);
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "djrewrite refresh recieved APR_OC_REASON_LOST");
				cfgm_startMessagingProcess(mpr, FALSE);
              	break;
              
			case APR_OC_REASON_UNREGISTER:
				/* we get here when child message processor is cleaned up; it gets cleaned
				 * up when pconf gets cleaned up
				 */
				if(mpr!=NULL&&mpr->proc!=NULL){
					kill(mpr->proc->pid, SIGHUP); /* send signal to message processor to die */
				}
				break;
       }
   }
#endif

	void cfgm_startMessagingProcess(djrewrite_messaging_proc_rec*mpr, int disableProcessRecovery){
		apr_status_t rv;
		void* localConfig=NULL;
		if((rv=apr_proc_fork(mpr->proc,root_mpr_pool))==APR_INCHILD){
			if(mpr->initFunc!=NULL){
				localConfig=(*mpr->initFunc)(root_mpr_pool,mpr->userdata);
			}
			cfgm_internalMessagingLoop(root_mpr_pool,mpr->logDir, localConfig, mpr->userdata,mpr->msgRecFunc);
			exit(1);
		}else{
			apr_pool_note_subprocess (root_mpr_pool,mpr->proc,APR_KILL_AFTER_TIMEOUT);
			if ( !disableProcessRecovery ) {
			#if 0/*APR_HAS_OTHER_CHILD && !NGX_HTTP_DJREWRITE*/
				apr_proc_other_child_register(mpr->proc, cfgm_messageProcessRestartCallback, mpr, NULL, root_mpr_pool);
			#endif
			}
		}
	}
	
	apr_proc_t* cfgm_initializeMessagingLoop(pool* p, char* logDir, void* messageBroker, void* userdata,
			cfgm_init_messaging_func initFunc, cfgm_message_recieved_func msgRecFunc,
			int disableProcessRecovery){
		root_mpr_pool = p;
		djrewrite_messaging_proc_rec* mpr = cfgm_newMessagingProcRecObj(root_mpr_pool, logDir, userdata, initFunc, msgRecFunc);
		cfgm_startMessagingProcess(mpr, disableProcessRecovery);
		return mpr->proc;	
	}
	
