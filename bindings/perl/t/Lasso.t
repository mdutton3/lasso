# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lasso.pm.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 11;
use Lasso;
use Data::Dumper;
use Error qw(:try);

#########################
my $SRCDIR = $ENV{'TOP_SRCDIR'};

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

# Test arrays
$request = new Lasso::SamlpRequest();
ok (! defined($request->RespondWith));
Lasso::SamlpRequestAbstract::RespondWith($request, "x", "y", "z");
@l = $request->RespondWith;
ok(@l == 3);
ok($l[0] eq 'x');
ok($l[1] eq 'y');
ok($l[2] eq 'z');

$server = new Lasso::Server($SRCDIR . "/tests/data/sp5-saml2/metadata.xml", $SRCDIR . "/tests/data/sp5-saml2/private-key.pem");
ok($server);
$server->add_provider(Lasso::Constants::PROVIDER_ROLE_SP, $SRCDIR . "/tests/data/sp5-saml2/metadata.xml");
$login = new Lasso::Login $server;

# Test error reporting
eval { $login->init_authn_request; };
ok($@->{code} == -408); # Missing Remote Provider ID (IDP was added with SP role)

$server = new Lasso::Server($SRCDIR . "/tests/data/sp5-saml2/metadata.xml", $SRCDIR . "/tests/data/sp5-saml2/private-key.pem");
ok($server);
$server->add_provider(Lasso::Constants::PROVIDER_ROLE_IDP, $SRCDIR . "/tests/data/idp5-saml2/metadata.xml");
ok(Lasso::check_version(2,2,90, Lasso::Constants::CHECK_VERSION_NUMERIC) == 1);
ok(Lasso::check_version(2,2,90, Lasso::Constants::CHECK_VERSION_EXACT) == 0);

$@ = undef;

eval { Lasso::Server::dump(undef); };
ok($@->{code} == Lasso::Constants::PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
