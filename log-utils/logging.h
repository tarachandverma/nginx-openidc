#ifndef __DJREWRITE_LOGGING__H_
#define __DJREWRITE_LOGGING__H_

#include <apr_file_io.h>
#include "apache_typedefs.h"

	typedef struct mm_logger{
		pool* p;
		char* filepath;
		apr_file_t* file;
		long maxLogFileSizeMB;
	}mm_logger;

	mm_logger* logging_getLogger(pool* p,char* path,long maxLogFileSizeMB);
	
	void logging_log(mm_logger* log,const char* a_format, ...);
	void logging_printf(mm_logger* log,const char* a_format, ...);
	void logging_setMaxFileSize(mm_logger* log,int maxLogFileSizeMB);
	int logging_rotateLogFile(mm_logger* log);
	int logging_closeLogger(mm_logger* log);
	
	// static refresh log
	int lc_openLogFile(apr_pool_t* p,char* filepath);
	int lc_closeLogFile(void);
	int lc_rotateLogFile();
	int lc_truncateLogFile(void);
	int lc_trimLogFile(void);
	int lc_printLog(const char* format,...);
	
#endif

