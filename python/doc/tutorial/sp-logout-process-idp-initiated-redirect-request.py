import lasso

lasso.init()

## Redirect Logout initiated by identity provider.

query = [...] # Get current URL query.
server_dump = [...] # Load string server_dump from file or database or...
server = lasso.Server.new_from_dump(server_dump)
logout = lasso.Logout.new(server)
if logout.handle_request(query, lasso.httpMethods['redirect']):
    raise Exception('Logout error')
name_identifier = logout.response.name_identifier
account = [...] # Retrieve user account having this name_identifier.
if not account:
    # Unknown account.
    logout.response_status = lasso.libStatusCodes['unknownPrincipal']
else:
    user_dump = [...] # Retrieve string user_dump from account.
    if not user_dump:
        logout.response_status = lasso.libStatusCodes['unknownPrincipal']		
    else:
        user = lasso.User.new_from_dump(user_dump)
        del user.authn_assertion
        user_dump = user.dump()
        [...] # Store string user_dump into account (replace the previous one).
        # User is now logged out => delete session, cookie...
        [...]
if logout.build_response_msg():
    raise Exception('Logout error')
[...] # Reply a HTTP redirect to logout.msg_url.

lasso.shutdown()
