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
    <cfset ssoUrl=lasso.configure("/opt/coldfusionmx/wwwroot/data/metadata.xml", "/opt/coldfusionmx/wwwroot/data/public-key-la.pem", "/opt/coldfusionmx/wwwroot/data/private-key-raw-la.pem", "https://idp2/metadata", "/opt/coldfusionmx/wwwroot/data/idp2-la/metadata.xml", "/opt/coldfusionmx/wwwroot/data/idp2-la/public-key.pem")>
    <cfset ssoUrl=lasso.login("important string")>
    <cfoutput>Identity provider single sing-on URL to redirect to = #ssoUrl#</cfoutput>
    <cflocation url=#ssoUrl#>
  </body>
</html>
