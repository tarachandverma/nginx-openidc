/*
 *  Created by Tarachand verma on 01/04/14.
 *
 */
#ifndef __TCREWRITE_APACHE_MACROS__H_
#define __TCREWRITE_APACHE_MACROS__H_

#define SAFESTR(str) (str!=NULL?str:"NULL")
#define SAFESTRBLANK(str) (str!=NULL?str:"") 
#define SAFESTRELSE(str,elstr) (str!=NULL?str:elstr) 
#define SAFESTRLEN(str) (str!=NULL?strlen(str):0)
#define BOOLTOSTR(bol) (bol!=1?"FALSE":"TRUE")
#define STRTOBOOL(str) ((str!=NULL&&(strcmp(str,"true")==0||strcmp(str,"TRUE")==0||strcmp(str,"on")==0))?1:0)
#define SAFEDUP(p,str) (str==NULL?NULL:apr_pstrdup(p,str))

#define str(s) #s
#define PIDWRAP(msg) "INFO: ID>%d< " msg "" , getpid ()
#define PIDWRAPC(msg) "CRITICAL: ID>%d< " msg "" , getpid ()

#define APACHE_LOG_DEBUG(msg)
#define APACHE_LOG_DEBUG1(msg, arg1)
#define APACHE_FREE_CHAR_ARRAY(arr)
#define AP_LOG_CRITICAL1(req,msg,arg){ap_log_error(APLOG_MARK, APLOG_CRIT,APR_SUCCESS, req->server, PIDWRAPC(msg),arg);}
#define AP_LOG_ERROR(req,msg){ap_log_error(APLOG_MARK, APLOG_INFO,APR_SUCCESS,req->server, PIDWRAP(msg));}
#define AP_LOG_ERROR1(req,msg,arg){ap_log_error(APLOG_MARK, APLOG_INFO,APR_SUCCESS,req->server, PIDWRAP(msg),arg);}
#define AP_LOG_ERROR2(req,msg,arg,arg1){ap_log_error(APLOG_MARK, APLOG_INFO,APR_SUCCESS,req->server,PIDWRAP(msg),arg,arg1);}
#define AP_LOG_ERROR3(req,msg,arg,arg1,arg2){ap_log_error(APLOG_MARK, APLOG_INFO,APR_SUCCESS,req->server,PIDWRAP(msg),arg,arg1,arg2);}

#define AP_RPRINTF(req,arg1){ap_rprintf(req,arg1);}
#define AP_RPRINTF1(req,tem,arg1){ap_rprintf(req,tem,arg1);}
#define AP_RPRINTF2(req,tem,arg1,arg2){ap_rprintf(req,tem,arg1,arg2);}
#define AP_RPRINTF3(req,tem,arg1,arg2,arg3){ap_rprintf(req,tem,arg1,arg2,arg3);}
#define AP_RPRINTF4(req,tem,arg1,arg2,arg3,arg4){ap_rprintf(req,tem,arg1,arg2,arg3,arg4);}
#define AP_RPRINTF5(req,tem,arg1,arg2,arg3,arg4,arg5){ap_rprintf(req,tem,arg1,arg2,arg3,arg4,arg5);}
 
#endif
