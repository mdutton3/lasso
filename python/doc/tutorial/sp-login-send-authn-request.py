import lasso

lasso.init()

## Send an authentication request to identity provider.
##
## Called when the user press login button on service provider.

server_dump = [...] # Load server_dump from file or database or...
server = lasso.Server.new_from_dump(server_dump)
login = lasso.Login.new(server)
if login.init_authn_request('http://identification.entrouvert.org'):
    raise Exception('Login error')

# Identity provider will ask user to authenticate himself.
login.request.set_isPassive(False)

# Identity provider will not ask user to authenticate himself if he has already done it recently.
# login.request.set_forceAuthn(False)

# Identity provider will create a federation with this service provider and this user, if this was
# not already done.
login.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)

if login.build_authn_request_msg():
    raise Exception('Login error')
[...] # Reply a HTTP redirect to login.msg_url.

lasso.shutdown()
