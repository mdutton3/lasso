import twill

def test_sso_defederate_initiated_by_sp_redirect():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
notfind 'Log on'
find 'Single Logout'
find 'Federation Termination'
submit fedterm-redirect
url http://localhost:10002
notfind 'Log on'
find 'Single Logout'
notfind 'Federation Termination'
go http://localhost:10001
find 'Local Logout'
find 'Single Logout'
notfind 'Federation Termination'
''')

def test_sso_defederate_initiated_by_sp_soap():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
notfind 'Log on'
find 'Single Logout'
find 'Federation Termination'
submit fedterm-soap
url http://localhost:10002
notfind 'Log on'
find 'Single Logout'
notfind 'Federation Termination'
go http://localhost:10001
find 'Local Logout'
find 'Single Logout'
notfind 'Federation Termination'
''')


def test_sso_defederate_then_slo():
    twill.commands.reset_browser()
    twill.execute_string('''
go http://localhost:10002
submit
fv 1 username fred
fv 1 password fred
submit
url http://localhost:10002
submit fedterm-soap
url http://localhost:10002
notfind 'Log on'
find 'Single Logout'
notfind 'Federation Termination'
go http://localhost:10001
find 'Local Logout'
find 'Single Logout'
notfind 'Federation Termination'
fv 2 binding SOAP
fv 2 slo 'Single Logout'
submit 'Single Logout'
url http://localhost:10001
find 'Log in'
notfind 'Single Logout'
notfind 'Federation termination'
go http://localhost:10002
find 'Log on'
notfind 'Single Logout'
notfind 'Federation termination'
''')



