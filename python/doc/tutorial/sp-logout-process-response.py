import lasso

lasso.init()

## Logout initiated by service provider (continued): Process the HTTP redirect logout response returned by
## identity provider.

query = [...] # Get current URL query.
server_dump = [...] # Load string server_dump from file or database or...
server = lasso.Server.new_from_dump(server_dump)
user_dump = [...] # Retrieve string user_dump from logged user account.
user = lasso.User.new_from_dump(user_dump)
logout = lasso.Logout.new(server, user)
if logout.handle_response(query, lasso.httpMethods['redirect']):
    raise Exception('Logout error')
# Save the updated user_dump into account.
user_dump = logout.user.dump()
[...] # Store string user_dump into account (replace the previous one).
# User is now logged out => delete session, cookie...
[...]

lasso.shutdown()
