<html>
  <head>
    <title>Lasso Single Sign-On</title>
  </head>
  <body>
    <h1>Lasso Single Sign-On</h1>
<!--
    <cfobject type="java" name="sys" class="java.lang.System" action="create">
    <cfset properties=sys.getProperties()>
    <cfdump var="#properties#">
-->
    <cfobject action="create" type="Java" class="CFLassoSingleSignOn" name="lasso">
    <cfset lasso.init()>
    <cfset lasso.configure("/opt/coldfusionmx/wwwroot/lasso/data/metadata.xml", "/opt/coldfusionmx/wwwroot/lasso/data/public-key-la.pem", "/opt/coldfusionmx/wwwroot/lasso/data/private-key-raw-la.pem", "https://idp2/metadata", "/opt/coldfusionmx/wwwroot/lasso/data/metadata-idp.xml", "/opt/coldfusionmx/wwwroot/lasso/data/idp2-la/public-key.pem")>
    <cfset lasso.initAuthnRequest("important-string")>
    <cfset lasso.buildAuthnRequestMsg()>
    <cfset ssoUrl=lasso.getMsgUrl()>
    <cfoutput><p>Identity provider single sing-on URL to redirect to = #ssoUrl#</p></cfoutput>
    <cflocation url=#ssoUrl#>
  </body>
</html>
