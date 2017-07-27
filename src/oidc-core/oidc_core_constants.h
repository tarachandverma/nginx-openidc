#ifndef ACTION_MAPPINGS_CONSTANTS_H_
#define ACTION_MAPPINGS_CONSTANTS_H_

typedef enum {
    header_add = 'a',              /* add header (could mean multiple hdrs) */
    header_set = 's',              /* set (replace old value) */
    header_append = 'm',           /* append (merge into any old value) */
    header_merge = 'g',            /* merge (merge, but avoid duplicates) */
    header_unset = 'u',            /* unset header */
    header_echo = 'e',             /* echo headers from request to response */
    header_edit = 'r'              /* change value by regexp */
} header_actions;

// token encryption/decryption buffer size
#define OAUTH_CRYPTO_BUFSIZE				1024
#define OAUTH_BASE64_BUFSIZE				4096

// delimiters and wildcard
#define OAUTH_TOKEN_DELIM      			":"
#define OAUTH_TOKEN_WILDCARD			"*"

// versions
#define OAUTH_AUTHORIZED_CODE_VERSION1 	"V1"
#define OAUTH_ACCESS_TOKEN_VERSION1   	"V1"
#define OAUTH_REFRESH_TOKEN_VERSION1   	"V1"
#define OAUTH_USER_TOKEN_VERSION1   	"V1"
#define OAUTH_PAGE_TOKEN_VERSION1   	"V1"

// response types
#define OAUTH_TYPE_UNKNOWN					0
#define OAUTH_TYPE_AUTHORIZE_CODE			1
#define OAUTH_TYPE_ACCESS_TOKEN				2
#define OAUTH_TYPE_AUTHENTICATE_CODE		3
#define OAUTH_TYPE_ID_TOKEN					4
#define OAUTH_TYPE_CODE_AND_ID_TOKEN		5

// subject types
#define OAUTH_SUBJECT_TYPE_UNKNOWN			0
#define OAUTH_SUBJECT_TYPE_UUID				1
#define OAUTH_SUBJECT_TYPE_APP				2

// response types
#define OAUTH_GRANT_TYPE_UNKNOWN				0
#define OAUTH_GRANT_TYPE_AUTHORIZE_CODE			1
#define OAUTH_GRANT_TYPE_PASSWORD				2
#define OAUTH_GRANT_TYPE_JWT					3
#define OAUTH_GRANT_TYPE_REFRESH_TOKEN			4
#define OAUTH_GRANT_TYPE_CLIENT_CREDENTIALS		5
#define OAUTH_GRANT_TYPE_PWD_WITH_CLIENT_CREDENTIALS		6
#define OAUTH_GRANT_TYPE_UUID_WITH_CLIENT_CREDENTIALS		7

// versions
#define OAUTH_TCS_RESPONSE_SUCCESS			 	0
#define OAUTH_TCS_RESPONSE_FAILURE   			1

#define OAUTH_LIS_RESPONSE_SUCCESS			 	0
#define OAUTH_LIS_RESPONSE_FAILURE   			1
#define OAUTH_LIS_RESPONSE_UNAVILABLE   		2

#define OAUTH_AUTHID_SUCCESS					0
#define OAUTH_AUTHID_FAILURE   					1

// OIDC headers
#define OIDC_STATUS_HEADER				"VALIDATE-STATUS"
#define OIDC_DESC_HEADER				"VALIDATE-DESCRIPTION"
#define OIDC_ISSUER_HEADER				"ISSUER"
#define OIDC_AUDIENCE_HEADER			"AUDIENCE"
#define OIDC_SUBJECT_HEADER			"SUBJECT"
#define OIDC_ROLES_HEADER				"ROLES"

#define OIDC_RP_SESSIONID					"X-RP-SESSION"

#endif /*ACTION_MAPPINGS_CONSTANTS_H_*/
