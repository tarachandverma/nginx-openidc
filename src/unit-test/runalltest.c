#include <stdlib.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <stdio.h>
#include <assert.h>
#include <CuTest.h>
#include <logging.h>

// Declare xxx_GetSuite() from xxx module here
// i.e. CuSuite* prodDefinitions_GetSuite();
static int die(int exitCode, const char *message, apr_status_t reason) {
    char msgbuf[80];
	apr_strerror(reason, msgbuf, sizeof(msgbuf));
	fprintf(stderr, "%s: %s (%d)\n", message, msgbuf, reason);
	exit(exitCode);
	return reason;
}

static void terminate()
{
   apr_terminate();
}
static apr_pool_t* initializePool()
{
	apr_status_t rc;
	apr_pool_t *pool;
	rc = apr_initialize();
	rc==APR_SUCCESS || die(-2, "Could not initialize !", rc);
	//atexit(terminate);	
	
	rc = apr_pool_create(&pool, NULL);
	rc==APR_SUCCESS || die(-2, "Could not allocate pool", rc);
	return pool;
}
static void destroyPool(apr_pool_t*p){
	apr_pool_destroy(p);
}

CuSuite* oidccore_GetSuite();

void RunAllTests(void) {
	CuString *output = CuStringNew();
	CuSuite* suite = CuSuiteNew();
	apr_pool_t*pool=NULL;
	mm_logger* logger=NULL;
	char* logsDir="./unit-test"; //Write the log in current directory.
	char logBuff[512];
	apr_status_t status;
	int size=2;
	
	setbuf(stdout, NULL);
	printf("Initializing pool...");
	pool=initializePool();
	if(pool==NULL){
		printf("FAILURE\r\n");
		printf("Could not initialize pool\r\n");
	}else{
		printf("OK\r\n");
	}
	
	sprintf(logBuff,"%s/results.txt",logsDir);
	//Remove any existing log file.
	apr_file_remove(logBuff,pool);
	
	printf("Initializing logger...");
	logger=logging_getLogger(pool,logBuff,size);
	if(logger==NULL){
		printf("FAILURE\r\n");
		printf("Could not initialize logger\r\n");
	}else{
		printf("OK\r\n");
	}
	
	printf("Check the results for unit test result in unit-test/results.txt \r\n");
	/* Add a new suite from xxx module here
	** i.e.  CuSuiteAddSuite(suite, xxx_GetSuite());
	*/
	CuSuiteAddSuite(suite, oidccore_GetSuite());
	
	//Run and print the summary
	CuSuiteRun(logger,suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	logging_printf(logger,"%s\n", output->buffer);
	printf("%s\n", output->buffer);
	
	   // write the results to html	
	mm_logger* html=NULL;
	sprintf(logBuff, "%s/summary.html", logsDir);

	apr_file_remove(logBuff, pool);

	printf("Writing to html...");
	html=logging_getLogger(pool,logBuff,size);
	if(html!=NULL){
		CuSuiteResultsToHtml(suite, html);
	}else{
		printf("FAILURE:Could not initialize html document\r\n\r\n");
	}
	
	destroyPool(logger->p);
	
	//Close the log file.
	logging_closeLogger(logger);
}

int main(int argc, char**argv) {
   RunAllTests();
   return 0;
}

