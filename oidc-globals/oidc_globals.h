#ifndef __DJREWRITE_GLOBALS__H_
#define __DJREWRITE_GLOBALS__H_

	//Exposed functions for the Enable unnamed shared memory flag.
	void djrglobals_setEnableUnnamedSHM(const char * arg);
	int djrglobals_isUnnamedSHMEnabled();

	//Exposed functions to set/get config check phase delay seconds.
	void djrglobals_setConfigCheckPhaseDelaySec(const char * arg);
	int djrglobals_getConfigCheckPhaseDelaySec();

#endif
