import lasso

lasso.init()

## Logout initiated by service provider: Send a logout request to identity provider.
##
## Called when the user press logout button on service provider.

server_dump = [...] # Load string server_dump from file or database or...
server = lasso.Server.new_from_dump(server_dump)
user_dump = [...] # Retrieve string user_dump from logged user account.
user = lasso.User.new_from_dump(user_dump)
logout = lasso.Logout.new(server, user)
if logout.init_request():
    raise Exception('Logout error')
if logout.build_request_msg():
    raise Exception('Logout error')
if not logout.msg_body:
    [...] # Reply a HTTP redirect to logout.msg_url.
else:
    # Send a logout SOAP message to identity provider.
    [...] # Logout user from service provider, but do not erase user_dump.
    soap_response = [...] # Send SOAP message logout.msg_body to URL logout.msg_url.
    if logout.handle_response(soap_response, lasso.httpMethods['soap']):
        raise Exception('Logout error')
    # Save the updated user_dump into account.
    user_dump = logout.user.dump()
    [...] # Store string user_dump into account (replace the previous one).
    # User is now logged out => delete session, cookie...
    [...]

lasso.shutdown()
