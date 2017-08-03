# nginx-openidc
Nginx module for openid connect relying party.
=============================================

**nginx-openidc is Nginx module allows openid-connect(JWT) validation and access control based on standard claim as headers. 

This document details the technical architecture and reasoning behind the
nginx-openidc system.

The request flow - Relying Party ( RP )
---------------------------------------
1. The user makes a request for a protected resource on RP `ngx-oidc-demo.com` for resource http://ngx-oidc-demo.com/protected.
2. In "Access" phase of nginx, **nginx-openidc** performs a check RP session exists containing the logged-in userinfo.
3. **nginx-openidc** decrypts cookie, verifies payload.
4. On success, The **nginx-openidc** sets request headers X-OIDC-* i.e. X-OIDC-SUBJECT, X-OIDC-ISSUER and many more depending on scopes requested from JWT claim.
5. In post "Access" phase, **nginx-openidc** oidc-config.xml rules are executed.
	This is most important phase where you can define unlimited authorization rules based on X-OIDC-* header
6. Upon successfully running rules in post authorization phase, nginx forwards them to the
   backend **service** application.
7. The **service** application can use the X-OIDC-* headers as-is.

The request flow - API authorization
------------------------------------
1. ClientApp gets a JWT from authorized OP or generates a JWT using "client-credentials" flow
2. The clientApp makes a request for a protected API on `ngx-oidc-demo.com` for resource with access_token as "Authorization: Bearer <id_token>" header. 
Examples
	http://ngx-oidc-demo.com/api/user.email
	Authorization: Bearer <id_token received from step(1)>
3. In "Access" phase of nginx, **nginx-openidc** performs JWT validation.
4. On success, The **nginx-openidc** sets request headers X-OIDC-* i.e. X-OIDC-SUBJECT, X-OIDC-ISSUER and many more depending on scopes requested from JWT claim.
5. In post "Access" phase, **nginx-openidc** oidc-config.xml rules are executed.
6. Upon successfully running rules in post authorization phase, nginx forwards them to the
   backend **service** application.
7. The **service** application can use the X-OIDC-* headers as-is.
   
Here are the some of the features supported.

Features
------------
- Supports all OAuth2.0/OpenID-Connect flows
- Supports HS256 and RS256
- Supports rotated RS256 public key.
- Implements Access phase which validates id_token(JWT) and passes claims as custom headers
- Implements Post Authorization phase custom response based on custom headers.
- Allows multiple relying party based on domain
- Supports "nonce" generation and validation
- Supports relying party session
- Removes custom headers from incoming request to ensure these headers are not spoofed.
- Unlimited capabilities from Authorization to rewrites
- Capabilites to add/remove/update request/response headers
- Capability to generate custom error response
- Support fo auto refresh entire oidc-config.xml periodically with no server restart

Supported platforms
--------------------------------------
- All the flavors of *nix platforms, freebsd.

# Installation
``````````
git clone https://github.com/tarachandverma/nginx-openidc.git
cd nginx-openidc
wget 'http://nginx.org/download/nginx-1.8.0.tar.gz'
tar -xzvf nginx-1.8.0.tar.gz
cd nginx-1.8.0/

 # Here we assume you would install you nginx under /opt/nginx/.
 ./configure --add-module=../src --with-http_ssl_module
 make
 make install
``````````
     
# Test ( using docker )
# build docker image
	docker build -t nginx-oidc .

#run docker image	
	docker run -p 80:80 -p 443:443 -i -t nginx-oidc

# add /etc/hosts entry
NEW-DOCKER-IP ngx-oidc-demo.com

#access docker container via protected path
http://ngx-oidc-demo.com/protected

# Example : headers available on successful JWT validation ( all header is prefixed with HTTP_ when it reaches to backend app )
````````````````````
X-OIDC-VALIDATE-STATUS = 	success
X-OIDC-ISSUER = 	https://accounts.google.com
X-OIDC-SUBJECT = 	113146716035256978692
X-OIDC-AUDIENCE = 	282412598309-545pvmsh9r23f4k1o7267744s59sod6v.apps.googleusercontent.com
X-OIDC-NONCE = 	a44df6ae-27f2-4c92-85e1-a22eb6381f53
X-OIDC-EMAIL = 	xxxx@gmail.com
````````````````````

# Main Configuration
````````````````````
OPENIDC_HomeDir                        /usr/local/nginx/conf;
OPENIDC_LogFile                        oidc-refresh.log;
OPENIDC_SharedMemory  file=/config.shm size=61000;
OPENIDC_RemotePath uri=https://raw.githubusercontent.com/tarachandverma/nginx-openidc/master/example-conf/;
OPENIDC_PassPhrase                     abc123;
OPENIDC_HeaderPrefix                   X-OIDC-;
OPENIDC_RefreshWaitSeconds             20;
OPENIDC_ConfigFile                     oidc-config.xml;

````````````````````

- **OPENIDC_HomeDir** Home directory to hold openid configuration and logs files.

Specify description string.

- **OPENIDC_LogFile**

Log file is generated upon startup and refresh and records information whats loaded in shared memory.

- **OPENIDC_SharedMemory**

Specifies shared memory file name and size

- **OPENIDC_RemotePath**

Optional: Specifies remote directory to download oidc-config.xml during startup.

- **OPENIDC_PassPhrase**

Specifies passPhrase to encrypt/decrypt relying party session

- **OPENIDC_HeaderPrefix**

Specifies custom headers prefix for the claims, default:X-OIDC-

- **OPENIDC_RefreshWaitSeconds (mendatory if OP signing keys are rotating )**

This will refresh entire oidc-config.xml remote repository defined by OPENIDC_RemotePath along with OP publicKeys 
defined by <jwksUri> in oidc-config.xml
default:no refresh

- **OPENIDC_ConfigFile**

Specify relying party configuration and custom post Authorization response and rules


How to enable ngx openid-connect : nginx.conf
---------------------------------------------
`````````````````````

http {

	...
	OPENIDC_HomeDir                        /opt/nginx-1.8.0/conf/oidc;
	OPENIDC_LogFile                        oidc-refresh.log;
	OPENIDC_SharedMemory  file=/config.shm size=61000;
	OPENIDC_RemotePath uri=https://raw.githubusercontent.com/tarachandverma/nginx-openidc/master/example-conf/;
	OPENIDC_PassPhrase                     abc123;
	OPENIDC_HeaderPrefix                   X-REMOTE-;
	#OPENIDC_RefreshWaitSeconds				20;
	OPENIDC_ConfigFile                     oidc-config.xml;
	
	server {
			...
			# authorization code flow - exchanging authorization code to id_token(JWT)
		    location /internal/oauth2/token {
		    	internal;
		        proxy_pass https://www.googleapis.com/oauth2/v4/token;
		    }
	}
...
}


`````````````````````

openid-connect configuration : oidc-conf.xml
-------------------------------------------

```XML
<?xml version="1.0"?>
<oidcConfig>
	<!-- OpenID-Connect Provider metadata url -->	 
	 <oidcProvider>
	 	<metadataUrl>$$OP metadata url$$</metadataUrl>
		<!--you can set individua params as well if metadata is not available -->
	 	<issuer>$$OP issuer$$</issuer>
	 	<authorizationEndpoint>$$OP authorization_end_point$$</authorizationEndpoint>
	 	<tokenEndpoint>$$OP token_end_point same as defined in nginx.conf's proxy_pass for token endpoint$$</tokenEndpoint>
	 	<jwksUri>$$OP json web keys end poing$$</jwksUri><!-- json web keys url exposed by OP, useful if keys are rotated by OP -->
	 	<!-- json web keys in JSON format, useful if keys are not rotated by OP -->
	 	<jwksJson><![CDATA[{
 "keys": [
  $$key1 json$$,
  $$key2 json$$,
  $$key3 json$$,
  ...
  $$keyn json$$
 ]
}]]></jwksJson>
	<!-- example -->	 	
	 	<!--jwksJson><![CDATA[{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "2758a0d689ad62a453a671429a41d192d6bb7291",
   "n": "wjiigb39qOCj_WwYKqspYpk7SbuirXARcOo8bLzI95V3OIisz-40eOyo_SaeNeDb4KOcWZ9Qr0YmRnw0G8JhfVB973KwTURsUHQw3Q1fZSBw5T0vCMS5UHbMLxjHptCZ6kVRbBnRVuCMvY3ws0LCK9h9e4l7rCfXMQF3IlBUCisrGpYiVTO1-Mj3J6h_TJ7QDRQnqkX5jzcv-8XCRg_BefA40sC2fXjpZezdf8i27d3tuPRsjD46wFydDZk_KFBqSr8RE2EzJ6yaSNWnKByJejA6tNLK72UIrt0GE83TS1d369kGN2hk57gonlNMo-v5GTFweFNnQGU1xOng30bdvQ",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "8a60d44a4ece38c0c9d16be136b2a1427b1d6ee0",
   "n": "l9Cn5qmr7VFKIed9RQIZPdenYp-V1BDM1wMg7Rpkl8mNQ7qsnJWuK8JKQoIljbwr9L1kKikKOR37z1prV0ZTQQao73YsB34OLbi25g0Xcr32j5giQDMxmFxmrYN1LG-T4qEOI4hE52Bafr5jBuZwL56HeuEU5G-QunGrNieGcfdVFXVW8-f9UBkJmoF_Dw_H38wNKif79tGKD2XXdG-VjT-Pg2nbpzQ6fIXunzaaW9aUyoNZWpQQ9_QBqgEApHAP5qWGQsUQLwzkiUr1Du51ERLC7nm3B-pLFqIlRmqiWVtUAdF0wkKaCQXyvFS2KabG9D4aX0T_MKESsV7T6wwvsQ",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "eb29843dd7334cf989e1db6a2b0c6e07a10a9cd3",
   "n": "jTBFxlzE8GwPWvSRsiUIiZGp8QxhZNv9QMhoEIHaoyaTlHBGS3cmsqhEroFjW5dwiVee_WJFBd7IcoaBZgVmHgLVMCr7dDokcO2LWIgbPikS1gfCuD2twZyoGdVWRpLy1KGSFlINcn1bbvPpod6Bt3sEEIv-rSSR5sgRFJbPpKwIZDrZnZMRPVM6a29WJ129uo04hIpig3p7ULpFTJrAkkQAtfEtP_uFJXCF8DrG1HoM6xlVOR2ksqjkpQYAa7p5yPZGEn_oZDxeVSzjuKG5KRt7-UL7hSg3q4jdEeX60j6DAZEcxX8apIpmYG2gmACBWKWnguHRZXdqfofyBcKizQ",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "0ec3739dba77e22d632f3484b687391a8956f96b",
   "n": "jA4LmJfj1zuYFYCEWJD62Di-LbuamWbTqdhSaNWCRovztCIY0UlbnoGluNpzePOHJSuocOgucQNybwpdCVJ9S0rCPccytDw1hAxcFqmHOeqGIdfnpCojF0m9pggleHgWI9biwWt1jbkAqNx7VK1gNUkhWoVp_iQGfE37DnWptdDMmh9wVMc2SY8wqxtkcZebYpRNE52t1HSnXJ6z_HtMYvoRpi35Ltv6tuB16vFgb70k3AiGfrK8llpo8VZBHax5MCAZM612zA24G3tYDPSPGksrnoUFL5Iwyv-Mf9y4y6kFlV5hIpC27VPJxXzc9jD1kMBmQxIArHpAVsea_C8eQQ",
   "e": "AQAB"
  }
 ]
}]]></jwksJson-->	 	
	 </oidcProvider>

	<!-- relying parties configuration, you can configure multiple relying parties, default must be configured and usually same as first one in case there is only one -->
	 <relyingParties default="$$YOUR CLIENT ID for APP1 $$"><!-- default is mendatory and is same as first one  -->
	 	<relyingParty clientID="$$YOUR CLIENT ID for app1$$" clientSecret="$$YOUR CLIENT SECRET for app1$$" domain=""$$YOUR APPLICATION DOMAIN$$"" validateNonce="true/false depending on if you want to validate JWT nonce">
	 		<description>nginx oidc demo</description>
	 		<redirectUri>$$CALLBACK URL WHERE ID_TOKEN OR CODE WILL BE RECIEVED$$</redirectUri>
	 	</relyingParty>
	 	<relyingParty clientID="$$YOUR CLIENT ID for app2 $$" clientSecret="$$YOUR CLIENT SECRET for app2$$" domain=""$$YOUR APPLICATION DOMAIN$$"" validateNonce="true/false depending on if you want to validate JWT nonce">
	 		<description>nginx oidc demo</description>
	 		<redirectUri>$$CALLBACK URL WHERE ID_TOKEN OR CODE WILL BE RECIEVED$$</redirectUri>
	 	</relyingParty>
	 	...
	 	<relyingParty clientID="$$YOUR CLIENT ID for appn $$" clientSecret="$$YOUR CLIENT SECRET for appn$$" domain=""$$YOUR APPLICATION DOMAIN$$"" validateNonce="true/false depending on if you want to validate JWT nonce">
	 		<description>nginx oidc demo</description>
	 		<redirectUri>$$CALLBACK URL WHERE ID_TOKEN OR CODE WILL BE RECIEVED$$</redirectUri>
	 	</relyingParty>	 		 	
	 </relyingParties>
	 <!-- end of relying parties configuration -->
	 
 	 <!-- specify collection of actions inside the pageActions -->
     <pageActions>	<!-- start of page-actions -->
 
		<!-- nginx authz handlers -->
	    <action id="oidc_version"><handler>oidc_version</handler></action>
	    <action id="oidc_config_core_status"><handler>oidc_config_core_status</handler></action>
	    <action id="oidc_rewrite_pageactions"><handler>oidc_rewrite_pageactions</handler></action>
	    <action id="oidc_rewrite_actionmappings"><handler>oidc_rewrite_actionmappings</handler></action>
	    <action id="oidc_rewrite_match"><handler>oidc_rewrite_match</handler></action>
	    <action id="oidc_headers"><handler>oidc_headers</handler></action>	    
	    <action id="oidc_index"><handler>oidc_index</handler></action>

        <action id="$$unique-action-name1$$" debug=$$true/false$$><!-- echo hostname of front-end box and/or echoes backend proxied box if its proxy request-->
    	    <description>describe what action does in few words</description> <!-- string -->
            <isForward>true/false</isForward> <!-- boolean set it to true if its internal redirect, false for 302 redirect, default value true -->
            <isPermanent>true/false</isPermanent> <!-- boolean, set it to true if permanent redirect 301 -->
            <regex>$$regex-to-generate-tokens-to-build-below-url$$</regex> <!-- string -->
            <advancedTemplate>true/false</advancedTemplate> <!-- string, set to true of below url is dynamically generated using advanced tokens -->
            <methods-allowed>$$command separated list of methods allow to proxy$$</methods-allowed> <!-- string -->
            <uri>$$target-path1</uri> <!-- string, specify relative url if internal redirect or full path if external redirect 302 -->
    		<requestHeaders> <!-- array of header -->
        		<header name="$$header-name$$" do="add|set|append|merge|unset" matchList="$$match-list-name$$">$$header-value$$</header>
    		</requestHeaders>
    		<responseheaders> <!-- array of header -->
        		<header name="$$header-name$$" do="add|set|append|merge|unset" matchList="$$match-list-name$$">$$header-value$$</header>
    		</responseheaders>                                 
        </action>                                                     
    </pageActions><!-- end of page-actions -->

    <!-- matchLists are collection of individual matchList -->
    <!-- matchList is collection of individual matches evaluates as match1 OR match2 OR match3 ...  -->
    <!-- match is collection of individual conditions evaluates as host AND ip AND event AND header1 AND heder2 AND env1 ... -->
    <matchLists>  <!-- start of match-lists -->
       <!-- matchList returns true upon first match ie.evaluates condition as match1 OR match2 OR ... -->
       <matchList name="$$matchlist-name1$$">
       	    <!-- match return true if all elements matches ie.evaluates condition as host AND ip AND header1 AND header2 ... -->
       	    <!-- Any unspecified tag in match is considered matched ie if unspecified host matches all host  -->
            <match host=”$$host-name-regex$$”>
                <host>$$host-name-regex$$</host> <!-- string -->
            	<ip isregex="true/false" negate="true/false">$$client-ip-address-regex-or-string$$</ip> <!-- string -->
            	<path negate="true/false">$$path-regex-or-string$$</path> <!-- string -->
            	<event start="$$start-time$$" end="$$end-time$$" /> <!-- date time string ddd mmm MM HH:MM:SS YYYY format -->
                <header name="$$header-name1$$" isregex="$$true/false$$" negate=$$true/false$$ delimAnd="$$delimitor$$" >$$header-value1$$</header> 
                <header name="$$header-name2$$" isregex="$$true/false$$" negate=$$true/false$$ delimAnd="$$delimitor$$" >$$header-value2$$</header>
                .	.	. 
            </match>
            <match> <!-- match2 -->
            </match>
            <match> <!-- match3 -->
            </match>
        </matchList>
       <matchList name="$$matchlist-name1$$">
            <match host=”$$host-name$$”> 
                <header name="$$header-name1$$">$$header-value1$$</header> 
                <header name="$$header-name2$$">$$header-value2$$</header>
                .	.	. 
            </match> 
        </matchList>
        .	.	.
    </matchLists>
	
    <!-- pathMappings are collection of individual mappings -->
    <!-- mappings is associated to source path and list of actions to choose  -->
    <pathMappings> <!-- array -->
		<!-- nginx authz handlers to verify oidc information, mainly for debug purpose -->
	    <mapping path="^/oidc/version"><postAuthAction>oidc_version</postAuthAction></mapping>
	    <mapping path="^/oidc/config-status"><postAuthAction>oidc_config_core_status</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-pageactions"><postAuthAction>oidc_rewrite_pageactions</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-actionmappings"><postAuthAction>oidc_rewrite_actionmappings</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-match"><postAuthAction>oidc_rewrite_match</postAuthAction></mapping>
	    <mapping path="^/oidc/headers"><postAuthAction>oidc_headers</postAuthAction></mapping>	    
	    <mapping path="^/oidc"><postAuthAction>oidc_index</postAuthAction></mapping>
	    <!-- end of nginx authz-->
        
        <mapping path="$$source-path-regex$$" matchLists="$$comma separated list of matchList$$" ignoreCase="true/false">
                <postAuthAction matchList=$$matchlist to select this action$$>one of the action in above actions-list-1</postAuthAction>
                <postAuthAction matchList=$$matchlist to select this action$$>one of the action in above actions-list-2</postAuthAction>
                .	.	.
                <postAuthAction>last action, its default action if above action don't match</postAuthAction>
        </mapping>
		.	.	.                                                                 
    </pathMappings> <!-- end of pathMappings -->
</oidcConfig>

```

**mapping** source url 
- **path**  specifies uri patterns match on source uri

- **postAuthAction** specifies action taken in authorization where it can use all the x-oidc-* headers avaiable in the request

- **matchLists** specifies the condition

**action** target action on source url
- **description** specifies what action is all about in couple of words

- **isForward**  specifies internal forwared/redirect if set to true

- **uri** specifies the target url which can be generated from source url
- **advancedTemplate** specifies advanced usage to generate target url using various kind of format.
  Target url : <uri>http://hostname:port/myurl/%{format}<format-tag></uri>

Following format-tags are supported.

               'r', requestVariables, 
               's', serverVariables,
               'c', requestCookie, 
               'u', urlDecodeToken, 
               'U', urlEncodeToken, 
               'q', requestQuery

Development
------------

- Source hosted at [GitHub](https://github.com/tarachandverma/nginx-openidc)
- Report issues, questions, feature requests on [GitHub Issues](https://github.com/tarachandverma/nginx-openidc/issues)

Diagnostics
---------------------

- Log file path
-  	Startup log - <homeDir>/oidc-refresh.log


Authors
-------

[Tara chand Verma]

* * *
