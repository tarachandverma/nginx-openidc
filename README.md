# ngx-openidc
Nginx module for openid connect relying party.
=============================================

**ngx-openidc is Nginx module allows openid-connect(JWT) validation and access control based on standard claim as headers. 

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
git clone https://github.com/tarachandverma/ngx-openidc.git
wget 'http://nginx.org/download/nginx-1.8.0.tar.gz'
tar -xzvf nginx-1.8.0.tar.gz
cd nginx-1.8.0/

 # Here we assume you would install you nginx under /opt/nginx/.
 ./configure --prefix=/opt/nginx \
     --add-module=../ngx-openidc
``````````
     
# Test
TODO

NodeJS API :


```ruby

#
# Main Configuration
#

```````
OPENIDC_HomeDir                        /opt/nginx-1.8.0/conf/oidc;
OPENIDC_LogFile                        oidc-refresh.log;
OPENIDC_SharedMemory  file=/config.shm size=61000;
OPENIDC_RemotePath uri=https://raw.githubusercontent.com/tarachandverma/ngx-openidc/master/example-conf/;
OPENIDC_PassPhrase                     abc123;
OPENIDC_HeaderPrefix                   X-REMOTE-;
OPENIDC_ConfigFile                     oidc-config.xml;

```

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


openid-connect configuration : oidc-conf.xml
-------------------------------------------

```XML
<?xml version="1.0"?>
<oidcConfig>
	<!-- OpenID-Connect Provider metadata url -->	 
	 <oidcProvider>
	 	<metadataUrl>https://accounts.google.com/.well-known/openid-configuration</metadataUrl>
	 </oidcProvider>

	<!-- relying parties configuration -->
	 <relyingParties>
	 	<relyingParty clientID="client123" clientSecret="secret123" domain=".example1.com" validateNonce="true">
	 		<description>client 123</description>
	 	</relyingParty>
	 	<relyingParty clientID="client234" clientSecret="secret234" domain=".example2.com" validateNonce="false">
	 		<description>client 123</description>
	 	</relyingParty>	 	
	 </relyingParties>
	 <!-- end of relying parties configuration -->
	 
     <pageActions>
 
		<!-- nginx-oidc verification handlers -->
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
		    <uri><![CDATA[https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&scope=email%2Copenid&client_id=4bf497da4fe0402eb67af22e2fed1877&redirect_uri=http://dev.marketwatch.com/xxxxx&nonce=%{HTTP_X-RP-SESSION}r]]></uri>
		</action>
		<action id="oidc-login2"><!-- strip id_token from outgoig request -->
		    <description>oidc login</description>
		    <isForward>false</isForward>
		    <regex><![CDATA[(.*)(\?|&)id_token(.*)]]></regex> <!-- to avoid passing expired id_token -->
		    <advancedTemplate>true</advancedTemplate>
		    <uri><![CDATA[https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&scope=email%2Copenid&client_id=bX4v0n2RYsa5a6PIOsK0TipeKvpfyt2B&redirect_uri=($1U)&nonce=%{X-RP-SESSION}r]]></uri>
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

- Source hosted at [GitHub](https://github.com/tarachandverma/ngx-openidc)
- Report issues, questions, feature requests on [GitHub Issues](https://github.com/tarachandverma/ngx-openidc/issues)

Diagnostics
---------------------

- Log file path
-  	Startup log - <homeDir>/config-refresh.log


Authors
-------

[Tara chand Verma]

* * *