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
    <cfset ssoUrl=lasso.login("important string")>
    <cfoutput>Identity provider single sing-on URL to redirect to = #ssoUrl#</cfoutput>
    <cflocation url=#ssoUrl#>
  </body>
</html>
