#include <unistd.h>
#include <apr_time.h>
#include <sys/stat.h>
#include "logging.h"
#include "common_utils.h"

	#define BUFFERSIZE 2048

	mm_logger* logging_getLogger(pool* p,char* path,long maxLogFileSizeMB){
		apr_status_t rc;
		if(path==NULL) return NULL;
		
		mm_logger* ret=(mm_logger*)apr_pcalloc(p,sizeof(mm_logger));
		ret->filepath=apr_pstrdup(p,path);
		ret->maxLogFileSizeMB=maxLogFileSizeMB;

		if((rc=apr_file_open(&(ret->file),path,APR_READ|APR_WRITE|APR_CREATE|APR_APPEND,APR_OS_DEFAULT,p))!=APR_SUCCESS){
			return NULL;
		}
		
		ret->p=p;
		return ret;
	}
	
	
	void logging_log(mm_logger* log,const char* a_format, ...){
		va_list va;
		//int i=0;
		apr_time_t tnow;
		char tbuf[64];
		char buffer[BUFFERSIZE];
		memset(buffer, '\0', BUFFERSIZE);
		
		if(log->maxLogFileSizeMB>0) logging_rotateLogFile(log);

		va_start(va, a_format);
		vsnprintf(buffer, BUFFERSIZE-1, a_format, va);
		
		tnow=apr_time_now();
		memset(tbuf,'\0',64);
		apr_ctime(tbuf,tnow);
		apr_file_printf(log->file,"%s mm.monitor.refresh [%d] %s\r\n",tbuf,getpid(),buffer);
		va_end(va);
	}

	int logging_rotateLogFile(mm_logger* log){
		mm_logger* ltmp;
		apr_finfo_t finfo;
		apr_time_t tnow;
		apr_time_exp_t texp;
		apr_status_t st;
		apr_size_t tbuflen,tbufmax=64;
		char tbuf[64],*newPath;

		st=apr_stat(&finfo,log->filepath,APR_FINFO_SIZE,log->p);

		if(finfo.size > log->maxLogFileSizeMB*1024*1024){
			apr_file_printf(log->file,"Monitor File Size [%dB], Max Value [%dB].\r\n",finfo.size,log->maxLogFileSizeMB*1024*1024);
			logging_closeLogger(log);
			log->file=NULL;

			tnow=apr_time_now();
			memset(tbuf,'\0',64);
			apr_time_exp_lt(&texp,tnow);
			apr_strftime(tbuf,&tbuflen,tbufmax,"%F-%H_%M_%S",&texp);
			newPath=apr_psprintf(log->p,"%s.%s.%d",log->filepath,tbuf,texp.tm_usec);
			apr_file_rename(log->filepath,newPath,log->p);
			ltmp=logging_getLogger(log->p,log->filepath,log->maxLogFileSizeMB);
			log->file=ltmp->file;

			return TRUE;
		}
		return FALSE;
	}

	void logging_printf(mm_logger* log,const char* a_format, ...){
		va_list va;
		//int i=0;
		//apr_time_t tnow;
		//char tbuf[64];
		char buffer[BUFFERSIZE];
		memset(buffer, '\0', BUFFERSIZE);
		
		va_start(va, a_format);
		vsnprintf(buffer, BUFFERSIZE-1, a_format, va);
		apr_file_printf(log->file,"%s\r\n",buffer);
		va_end(va);
	}		
	//Returns True if file successully closed.
	int logging_closeLogger(mm_logger* log){
		apr_status_t rc;
		if(log==NULL) return FALSE;
		if((rc=apr_file_close(log->file))!=APR_SUCCESS){
			return FALSE;
		}
		return TRUE;
	}
	void logging_setMaxFileSize(mm_logger* log,int maxLogFileSizeMB){
		log->maxLogFileSizeMB=maxLogFileSizeMB;
	}
	
// startup logs
	
	// startup log
	#define MAX_LOGFILE_SIZE 51200
	
	typedef struct process_logger {
		mm_logger logger;
		apr_status_t status;
		int pid;
	}process_logger;
		
	static process_logger refreshLogger;
	
	int lc_openLogFile(apr_pool_t* p,char* filepath){
		
		if(filepath==NULL){
			//printf("\nLogfile name not specified \n");
			return FALSE;
		}
		refreshLogger.status=apr_file_open(&refreshLogger.logger.file,filepath,APR_APPEND | APR_WRITE | APR_CREATE,APR_OS_DEFAULT,p);
		if(refreshLogger.status!=APR_SUCCESS){
		//printf("\nFailed to open logfile - %s\n", filepath);
		}
		refreshLogger.logger.p=p;
		refreshLogger.logger.filepath=apr_pstrdup(p,filepath);
		refreshLogger.logger.maxLogFileSizeMB=2;
		refreshLogger.pid=getpid();
		
		return refreshLogger.status;
	}
		
	int lc_closeLogFile(void){
		int cur_pid=getpid();
		if(refreshLogger.status!=APR_SUCCESS||cur_pid!=refreshLogger.pid){
			//printf("\nFailed to close logfile - %s\n", filepath);
			return FALSE;
		}
		apr_file_close(refreshLogger.logger.file);
		refreshLogger.status=-1;
		return APR_SUCCESS;
	}
		
	int lc_rotateLogFile(){
		apr_status_t status=0;
		int cur_pid;
		cur_pid=getpid();
		if(refreshLogger.status!=APR_SUCCESS||cur_pid!=refreshLogger.pid){
			//printf("\nLogfile has not been opened.\n");
			return FALSE;
		}

		lc_closeLogFile();

		apr_time_t tnow;
		apr_time_exp_t texp;
		apr_size_t tbuflen,tbufmax=64;
		char tbuf[64],*renamedPath;

		tnow=apr_time_now();
		memset(tbuf,'\0',64);
		apr_time_exp_lt(&texp,tnow);
		apr_strftime(tbuf,&tbuflen,tbufmax,"%F-%H_%M_%S",&texp);
		renamedPath=apr_psprintf(refreshLogger.logger.p,"%s.%s.%d",refreshLogger.logger.filepath,tbuf,texp.tm_usec);
		status = apr_file_rename(refreshLogger.logger.filepath,renamedPath,refreshLogger.logger.p);
		// open a new file
		status = lc_openLogFile(refreshLogger.logger.p, refreshLogger.logger.filepath);
		return status;
	}

	int lc_truncateLogFile(void){
		apr_status_t status=0;
		int cur_pid=getpid();
		if(refreshLogger.status!=APR_SUCCESS||cur_pid!=refreshLogger.pid){
			//printf("\nLogfile has not been opened.\n");
			return FALSE;
		}
		status=apr_file_trunc(refreshLogger.logger.file,0);
		//if(status!=APR_SUCCESS)
			//printf("\nFailed to truncate logfile - %s\n", refreshLogger.filepath);
		
		return status;
	}
		
	int lc_trimLogFile(void){
		//To ensure that logfile size never grows to a crazy size
		struct stat file_stat;
		
		int rc = stat(refreshLogger.logger.filepath,&file_stat);
		if(rc == 0 && file_stat.st_size > MAX_LOGFILE_SIZE){
			lc_rotateLogFile();
			return TRUE;
		}
		return FALSE;
	}
		
	int lc_printLog(const char* format,...){
		
		va_list ap;
		apr_size_t out_bytes;
		char logs[1024];
		apr_status_t status=0;
		int cur_pid;
		
		//Print to stdout to keep current behaviour
		va_start(ap,format);
		vfprintf(stdout,format,ap);
		va_end(ap);
		
		va_start(ap,format);
		vsprintf(logs,format,ap);
		va_end(ap);
		
		lc_trimLogFile();
		cur_pid=getpid();
		
		if(refreshLogger.status!=APR_SUCCESS||cur_pid!=refreshLogger.pid){
			//printf("\nLogfile has not been opened by this pool.\n");
			return FALSE;
		}
		status=apr_file_write_full(refreshLogger.logger.file,logs,strlen(logs),&out_bytes);
		//if(status!=APR_SUCCESS)
			//printf("\nFailed to write logfile - %s\n", refreshLogger.filepath);
		
		return status;
	}		
