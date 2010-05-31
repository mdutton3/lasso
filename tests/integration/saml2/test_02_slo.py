import twill

def test_sso_slo_initiated_by_sp_redirect():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
submit slo-redirect
url http://localhost:10002
find 'Log on'
go http://localhost:10001
find password
''')

def test_sso_slo_initiated_by_sp_soap():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
submit slo-soap
url http://localhost:10002
find 'Log on'
go http://localhost:10001
find password
''')



def test_sso_slo_initiated_by_idp_redirect():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
go http://localhost:10001
fv 2 slo 'Single Logout'
submit 'Single Logout'
follow 'singleLogout'
go http://localhost:10001/saml/singleLogoutFinish
url http://localhost:10001
find password
go http://localhost:10002
find 'Log on'
''')

def test_sso_slo_initiated_by_idp_soap():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
go http://localhost:10001
fv 2 binding SOAP
fv 2 slo 'Single Logout'
submit 'Single Logout'
url http://localhost:10001
find password
go http://localhost:10002
find 'Log on'
''')


def test_sso_idp_initiated_then_slo_sp_soap():
    ### http://bugs.entrouvert.org/rapport-de-bug-pour-la-conformance-saml-2-0/8/
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
submit slo-soap
url http://localhost:10002
find 'Log on'
go http://localhost:10001
find password
''')

