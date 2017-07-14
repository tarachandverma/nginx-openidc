# nginx-openidc
Nginx module for openid connect relying party.
=============================================

**nginx-openidc is Nginx module allows openid-connect(JWT) validation and access control based on standard claim as headers. 

Here are the some of the features supported.

Features
------------
- Supports all OAuth2.0/OpenID-Connect flows
- Supports HS256 and RS256
- Caching of RS256 public key to avoid downloading RS256 public key every request.
- Implements Access phase which validates id_token(JWT) and passes claims as custom headers
- Implements Post Authorization phase custom response based on custom headers.
- Allows multiple relying party based on domain
- Supports "nonce" generation and validation
- Supports relying party session
- Removes custom headers from incoming request to ensure these headers are not spoofed.

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


# Main Configuration
````````````````````
OPENIDC_HomeDir                        /usr/local/nginx/conf;
OPENIDC_LogFile                        oidc-refresh.log;
OPENIDC_SharedMemory  file=/config.shm size=61000;
OPENIDC_RemotePath uri=https://raw.githubusercontent.com/tarachandverma/nginx-openidc/master/example-conf/;
OPENIDC_PassPhrase                     abc123;
OPENIDC_HeaderPrefix                   X-REMOTE-;
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
	 	<metadataUrl>https://accounts.google.com/.well-known/openid-configuration</metadataUrl>
		<!--you can set individua params as well if metadata is not available -->
	 	<issuer>https://accounts.google.com</issuer>
	 	<authorizationEndpoint>https://accounts.google.com/o/oauth2/v2/auth</authorizationEndpoint>
	 	<tokenEndpoint>https://www.googleapis.com/oauth2/v4/token</tokenEndpoint>
	 	<jwksJson><![CDATA[{
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
}]]></jwksJson>	 	
	 </oidcProvider>

	<!-- relying parties configuration -->
	 <relyingParties default="282412598309-545pvmsh9r23f4k1o7267744s59sod6v.apps.googleusercontent.com">
	 	<relyingParty clientID="282412598309-545pvmsh9r23f4k1o7267744s59sod6v.apps.googleusercontent.com" clientSecret="xxxxxxxxxxx" domain=".com" validateNonce="true">
	 		<description>nginx oidc demo</description>
	 		<redirectUri>http://ngx-oidc-demo.com/oauth2/callback</redirectUri>
	 	</relyingParty>
	 </relyingParties>
	 <!-- end of relying parties configuration -->
	 
     <pageActions>
 
		<!-- nginx authz handlers -->
	    <action id="oidc_version"><handler>oidc_version</handler></action>
	    <action id="oidc_config_core_status"><handler>oidc_config_core_status</handler></action>
	    <action id="oidc_rewrite_pageactions"><handler>oidc_rewrite_pageactions</handler></action>
	    <action id="oidc_rewrite_actionmappings"><handler>oidc_rewrite_actionmappings</handler></action>
	    <action id="oidc_rewrite_match"><handler>oidc_rewrite_match</handler></action>
	    <action id="oidc_headers"><handler>oidc_headers</handler></action>	    
	    <action id="oidc_index"><handler>oidc_index</handler></action>
	    
	    <!-- post auth phase id_token validation actions -->
		<action id="oidc-login">
		    <description>oidc login</description>
		    <isForward>false</isForward>
		    <regex>(.*)</regex>
			<advancedTemplate>true</advancedTemplate>
		    <uri><![CDATA[https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope=email+openid&client_id=282412598309-545pvmsh9r23f4k1o7267744s59sod6v.apps.googleusercontent.com&redirect_uri=http://ngx-oidc-demo.com/oauth2/callback&nonce=%{HTTP_X-RP-SESSION}r]]></uri>
		</action>
		<action id="oidc-login2"><!-- strip id_token from outgoig request -->
		    <description>oidc login</description>
		    <isForward>false</isForward>
		    <regex><![CDATA[(.*)(\?|&)id_token(.*)]]></regex> <!-- to avoid passing expired id_token -->
		    <advancedTemplate>true</advancedTemplate>
		    <uri><![CDATA[https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope=email+openid&client_id=282412598309-545pvmsh9r23f4k1o7267744s59sod6v.apps.googleusercontent.com&redirect_uri=http://ngx-oidc-demo.com/oauth2/callback&nonce=%{X-RP-SESSION}r]]></uri>
		</action>
		<action id="oidc_show_error">
		    <description>error returned from idp</description>
		    <isForward>false</isForward>
		    <response code="412" contentType="application/json"><![CDATA[{"responsecode":412, "description":"Error occured, see query param for description"}]]></response>
		</action>
	    
	    
    </pageActions>

	<matchLists>
	    <matchList name="invalid_id_token">
	        <match>
	          	<path>id_token=</path>
				<header name="X-OIDC-VALIDATE-STATUS">failure</header>
	        </match>
	    </matchList>
	    <matchList name="oidc_session_missing">
	        <match>
				<header name="X-OIDC-VALIDATE-STATUS" isregex="true">nil</header>
	        </match>
	    </matchList>
	    <matchList name="oidc_session_invalid">
	        <match>
              <header name="X-OIDC-VALIDATE-STATUS">failure</header>
	        </match>
	    </matchList>
	    <matchList name="oidc_idp_error">
	        <match>
				<path>error=</path>
	        </match>
	    </matchList>
	</matchLists>
	
	<pathMappings>
		<!-- nginx authz handlers to verify oidc information, mainly for debug purpose -->
	    <mapping path="^/oidc/version"><postAuthAction>oidc_version</postAuthAction></mapping>
	    <mapping path="^/oidc/config-status"><postAuthAction>oidc_config_core_status</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-pageactions"><postAuthAction>oidc_rewrite_pageactions</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-actionmappings"><postAuthAction>oidc_rewrite_actionmappings</postAuthAction></mapping>
	    <mapping path="^/oidc/rewrite-match"><postAuthAction>oidc_rewrite_match</postAuthAction></mapping>
	    <mapping path="^/oidc/headers"><postAuthAction>oidc_headers</postAuthAction></mapping>	    
	    <mapping path="^/oidc"><postAuthAction>oidc_index</postAuthAction></mapping>
	    <!-- end of nginx authz-->
        
        <!-- id_token authorization rules -->
	    <mapping path="^/protected" >
			<postAuthAction matchList="oidc_idp_error">oidc_show_error</postAuthAction>
			<postAuthAction matchList="invalid_id_token">oidc-login2</postAuthAction>
			<postAuthAction matchList="oidc_session_missing">oidc-login</postAuthAction>
			<postAuthAction matchList="oidc_session_invalid">oidc-login</postAuthAction>
	    </mapping>
        <!-- end of id_token authorization rules -->
        	            
	</pathMappings>
</oidcConfig>

```

More documentation to be followed:

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
