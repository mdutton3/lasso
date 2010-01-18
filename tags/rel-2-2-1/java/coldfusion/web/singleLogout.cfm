<html>
  <head>
    <title>Lasso Single Logout</title>
  </head>
  <body>
    <h1>Lasso Single Logout</h1>
    <cfobject action="create" type="Java" class="CFLassoSingleLogout" name="lasso">
    <cfset lasso.init()>
    <cfset lasso.configure("/opt/coldfusionmx/wwwroot/lasso/data/metadata.xml", "/opt/coldfusionmx/wwwroot/lasso/data/public-key-la.pem", "/opt/coldfusionmx/wwwroot/lasso/data/private-key-raw-la.pem", "https://idp2/metadata", "/opt/coldfusionmx/wwwroot/lasso/data/metadata-idp.xml", "/opt/coldfusionmx/wwwroot/lasso/data/idp2-la/public-key.pem")>
    <!-- TODO: Retrieve identity dump and session dump in your users and sessions databases. --> 
    <!-- cfset lasso.setIdentityFromDump(#identityDump#) -->
    <!-- cfset lasso.setSessionFromDump(#sessionDump#) -->
    <cfset lasso.initRequest()>
    <cfset lasso.buildRequestMsg()>
    <cfset soapUrl=lasso.getMsgUrl()>
    <cfset soapBody=lasso.getMsgBody()>
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
    <cfset identityDump=lasso.getIdentityDump()>
    <cfset sessionDump=lasso.getSessionDump()>
    <!-- TODO: Store identity dump in your users database and remove session dump from sessions
         database. -->
    <cfoutput>
      <p>User is now unlogged.</p>
    </cfoutput>
  </body>
</html>

