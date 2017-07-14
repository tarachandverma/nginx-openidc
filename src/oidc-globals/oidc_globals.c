/*
 *  Created by Anoop Bindal on 04/27/15.
 *
 */
#include <oidc_globals.h>
#include <common_utils.h>

static int DJRE_EnableUnnamedSHM = FALSE;
static int DJRE_ConfigCheckPhaseDelaySec = 0;

void djrglobals_setEnableUnnamedSHM(const char * arg) {
	DJRE_EnableUnnamedSHM = STRTOBOOL(arg);
}

int djrglobals_isUnnamedSHMEnabled() {
	return DJRE_EnableUnnamedSHM;
}

void djrglobals_setConfigCheckPhaseDelaySec(const char * arg) {
	if(arg != NULL) {
		DJRE_ConfigCheckPhaseDelaySec = atoi(arg);
	}
}
int djrglobals_getConfigCheckPhaseDelaySec() {
	return DJRE_ConfigCheckPhaseDelaySec;
}
