import lasso


## Initialize service provider context.
##
## This initialization can be done at service provider configuration or launch.
## Once inited, this service provider context is never changed.

# Initialize with service provider informations.
[...] # Read metadata, public_key, private_key & certificate from file or database or...
server = lasso.Server.new(metadata, public_key, private_key, certificate, lasso.signatureMethods["dsaSha1"])

# Add identity provider informations.
[...] # Read idp_metadata, idp_public_key & idp_certificate from file or database or...
server.add_provider(idp_metadata, idp_public_key, idp_certificate)

# Dump server context to a string and store it in a file.
server_dump = server.dump()
[...] # Save server_dump in a file or database or...
