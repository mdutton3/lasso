import lasso

lasso.init()

## Initialize service provider context.
##
## This initialization can be done at service provider configuration or launch.
## Once inited, this service provider context is never changed.

# Initialize with service provider informations.
[...] # Get metadata_file_path, public_key_file_path, private_key_file_path &
      # certificate_file_path.
# The last argument lassoSignatureMethod... must be the method used to crypt the private key.
server = lasso.Server.new(metadata_file_path, public_key_file_path, private_key_file_path,
                          certificate_file_path, lasso.signatureMethodRsaSha1)

# Add identity provider informations.
[...] # Get idp_metadata_file_path, idp_public_key_file_path & idp_ca_certificate_file_path.
server.add_provider(idp_metadata_file_path, idp_public_key_file_path, idp_ca_certificate_file_path)

# Dump server context to a string and store it in a file.
server_dump = server.dump()
[...] # Save server_dump in a file or database or...

lasso.shutdown()
