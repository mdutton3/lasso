import twill

def test_config_authentic():
    '''Setting up Authentic metadata'''
    twill.execute_string('''
go http://localhost:10001/admin/settings/idp
formfile 1 privatekey private-key.pem
formfile 1 publickey public-key.pem
submit''')

def test_create_users():
    '''Creating Authentic user'''
    twill.execute_string('''
go http://localhost:10001/admin/identities/new
fv 1 name Fred
fv 1 roles$element0 Administrator
fv 1 username fred
fv 1 password fred
submit submit''')

def test_config_lcs():
    '''Setting up LCS metadata'''
    twill.execute_string('''
go http://localhost:10002/admin/settings/identification/
fv 1 methods$elementidp true
submit
go http://localhost:10002/admin/settings/identification/idp/sp
formfile 1 privatekey private-key.pem
formfile 1 publickey public-key.pem
submit''')

def test_config_authentic_providers():
    '''Adding LCS as service provider in Authentic'''
    twill.execute_string('''
go http://localhost:10001/login
fv 1 username fred
fv 1 password fred
submit

go http://localhost:10001/admin/settings/liberty_providers/new_remote
showforms
fv 1 metadata_url http://localhost:10002/saml/metadata
submit
''')

def test_config_lcs_providers():
    '''Adding Authentic as identity provider in LCS'''
    twill.execute_string('''
go http://localhost:10002/admin/settings/identification/idp/idp/new_remote
showforms
fv 1 metadata_url http://localhost:10001/saml/metadata
submit
''')

