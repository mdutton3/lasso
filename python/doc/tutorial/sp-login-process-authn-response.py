import lasso

lasso.init()

## Process the authentication response returned by identity provider and send received artifact to identity
## provider.
##
## Called after a HTTP redirect from identity provider.

query = [...] # Get current URL query.
server_dump = [...] # Load server_dump from file or database or...
server = lasso.Server.new_from_dump(server_dump)
login = lasso.Login.new(server)
if login.init_request(query, lasso.httpMethodRedirect):
    raise Exception('Login error')
if login.build_request_msg():
    raise Exception('Login error')
soap_response = [...] # Send SOAP message login.msg_body to URL login.msg_url.
if login.process_response(soap_response):
    raise Exception('Login error')
name_identifier = login.response.name_identifier
account = [...] # Retrieve user account having this name_identifier.
if account:
    user_dump = [...] # Retrieve string user_dump from account.
else:
    account = [...] # Create new account.
    user_dump = None
login.set_user_from_dump(user_dump)
# Save the new or updated user_dump into account.
user_dump = login.user.dump()
[...] # Store string user_dump into account.
# User is now authenticated => create session, cookie...
[...]

lasso.shutdown()
