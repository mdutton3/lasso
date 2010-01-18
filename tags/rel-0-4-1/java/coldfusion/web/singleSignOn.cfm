<html>
  <head>
    <title>Lasso</title>
  </head>
  <body>
    <h1>Lasso</h1>
<!--
    <cfobject type="java" name="sys" class="java.lang.System" action="create">
    <cfset properties=sys.getProperties()>
    <cfdump var="#properties#">
-->
    <cfobject action="create" type="Java" class="CFLasso" name="lasso">
    <cfset lasso.init()>
    <cfset lasso.configure("/opt/coldfusionmx/wwwroot/lasso/data/metadata.xml", "/opt/coldfusionmx/wwwroot/lasso/data/public-key-la.pem", "/opt/coldfusionmx/wwwroot/lasso/data/private-key-raw-la.pem", "https://idp2/metadata", "/opt/coldfusionmx/wwwroot/lasso/data/metadata-idp.xml", "/opt/coldfusionmx/wwwroot/lasso/data/idp2-la/public-key.pem")>
    <cfset ssoUrl=lasso.login("important")>
    <cfoutput>Identity provider single sing-on URL to redirect to = #ssoUrl#</cfoutput>
    <cflocation url=#ssoUrl#>
  </body>
</html>
