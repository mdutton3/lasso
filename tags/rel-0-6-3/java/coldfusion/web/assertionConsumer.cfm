<html>
  <head>
    <title>Lasso Assertion Consumer</title>
  </head>
  <body>
    <h1>Lasso Assertion Consumer</h1>
<!--
    <cfdump var="#QUERY_STRING#">
    <cfobject type="java" name="sys" class="java.lang.System" action="create">
    <cfset properties=sys.getProperties()>
    <cfdump var="#properties#">
-->
    <cfobject action="create" type="Java" class="CFLassoSingleSignOn" name="lasso">
    <cfset lasso.init()>
    <cfset lasso.configure("/opt/coldfusionmx/wwwroot/lasso/data/metadata.xml", "/opt/coldfusionmx/wwwroot/lasso/data/public-key-la.pem", "/opt/coldfusionmx/wwwroot/lasso/data/private-key-raw-la.pem", "https://idp2/metadata", "/opt/coldfusionmx/wwwroot/lasso/data/metadata-idp.xml", "/opt/coldfusionmx/wwwroot/lasso/data/idp2-la/public-key.pem")>
    <cfset lasso.initRequest(#QUERY_STRING#)>
    <cfset lasso.buildRequestMsg()>
    <cfset soapUrl=lasso.getMsgUrl()>
    <cfset soapBody=lasso.getMsgBody()>
    <cfset relayState=lasso.getMsgRelayState()>
<!--
    <cfdump var="#soapUrl#">
    <cfdump var="#soapBody#">
-->
    <cfhttp method="POST" url="#soapUrl#">
     <cfhttpparam type="XML" name="body" value="#soapBody#">
    </cfhttp>
<!--
    <cfdump var="#cfhttp.statuscode#">
    <cfdump var="#cfhttp.header#">
    <cfdump var="#cfhttp.fileContent#">
-->
    <cfset lasso.processResponseMsg(#cfhttp.fileContent#)>
    <cfset nameIdentifier=lasso.getNameIdentifier()>
    <!-- TODO: Retrieve identity dump and session dump in your users and sessions databases,
         using nameIdentifier to retrieve user and session. --> 
    <!-- cfset lasso.setIdentityFromDump(#identityDump#) -->
    <!-- cfset lasso.setSessionFromDump(#sessionDump#) -->
    <cfset lasso.acceptSso()>
    <cfset identityDump=lasso.getIdentityDump()>
    <cfset sessionDump=lasso.getSessionDump()>
    <!-- TODO: Store identity dump and session dump into your users and sessions databases. -->
    <cfoutput>
      <p>User is now logged. RelayState = #relayState#</p>
    </cfoutput>
  </body>
</html>

