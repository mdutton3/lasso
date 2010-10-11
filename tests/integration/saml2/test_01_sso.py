import twill

def test_sso_default():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
find 'Logged in'
''')

def test_sso_post():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
fv 1 binding POST
submit
fv 1 username fred
fv 1 password fred
submit
find 'You should be automaticaly'
submit
url http://localhost:10002
find 'Logged in'
''')

def test_sso_idp_initiated():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10001
fv 1 username fred
fv 1 password fred
submit
fv 1 sp http-localhost-10002-saml-metadata
submit sso
url http://localhost:10002
find 'Logged in'
''')

def test_sso_ispassive():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
fv 1 is_passive true
submit
url http://localhost:10002
find 'Authentication failure'
''')


