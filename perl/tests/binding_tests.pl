#! /usr/bin/env perl
#
# $Id$
#
# Perl unit tests for Lasso library
#
# Copyright (C) 2004, 2005 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


# To use this program, first install Lasso Perl binding, by executing the
# command:
#     su -c "cd ..; make install-perl"


use lasso;

sub test01 {
    print "Create and delete nodes.";

    my $authnRequest = new lasso::LibAuthnRequest;
    undef $authnRequest;

    print "..OK\n";
}

sub test02 {
    print "Get & set simple attributes of nodes.";

    my $authnRequest = new lasso::LibAuthnRequest;

    # Test a string attribute.
    $authnRequest->{consent} eq undef or die "Assertion failed\n";
    $authnRequest->{consent} = $lasso::LIB_CONSENT_OBTAINED;
    $authnRequest->{consent} eq $lasso::LIB_CONSENT_OBTAINED or die "Assertion failed\n";
    $authnRequest->{consent} = undef;
    $authnRequest->{consent} eq undef or die "Assertion failed\n";

    # Test a renamed string attribute.
    $authnRequest->{relayState} eq undef or die "Assertion failed\n";
    $authnRequest->{relayState} = 'Hello World!';
    $authnRequest->{relayState} eq 'Hello World!' or die "Assertion failed\n";
    $authnRequest->{relayState} = undef;
    $authnRequest->{relayState} eq undef or die "Assertion failed\n";

    # Test an integer attribute.
    $authnRequest->{majorVersion} eq 0 or die "Assertion failed\n";
    $authnRequest->{majorVersion} = 314;
    $authnRequest->{majorVersion} eq 314 or die "Assertion failed\n";

    undef $authnRequest;

    print "..OK\n";
}

sub test03 {
    print "Get & set attributes of nodes of type string list.";

    my $authnRequest = new lasso::LibAuthnRequest;

    $authnRequest->{respondWith} eq undef or die "Assertion failed\n";

    my $respondWith = new lasso::StringList;
    $respondWith->length eq 0 or die "Assertion failed\n";
    $respondWith->append('first string');
    $respondWith->length eq 1 or die "Assertion failed\n";
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->append('second string');
    $respondWith->length eq 2 or die "Assertion failed\n";
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->getItem(1) eq 'second string' or die "Assertion failed\n";
    $respondWith->append('third string');
    $respondWith->length eq 3 or die "Assertion failed\n";
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->getItem(1) eq 'second string' or die "Assertion failed\n";
    $respondWith->getItem(2) eq 'third string' or die "Assertion failed\n";
    $authnRequest->{respondWith} = $respondWith;
    $authnRequest->{respondWith}->getItem(0) eq 'first string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(1) eq 'second string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(2) eq 'third string' or die "Assertion failed\n";
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->getItem(1) eq 'second string' or die "Assertion failed\n";
    $respondWith->getItem(2) eq 'third string' or die "Assertion failed\n";
    undef $respondWith;
    $authnRequest->{respondWith}->getItem(0) eq 'first string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(1) eq 'second string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(2) eq 'third string' or die "Assertion failed\n";
    $respondWith = $authnRequest->{respondWith};
    $respondWith->getItem(0) eq 'first string' or die "Assertion failed\n";
    $respondWith->getItem(1) eq 'second string' or die "Assertion failed\n";
    $respondWith->getItem(2) eq 'third string' or die "Assertion failed\n";
    undef $respondWith;
    $authnRequest->{respondWith}->getItem(0) eq 'first string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(1) eq 'second string' or die "Assertion failed\n";
    $authnRequest->{respondWith}->getItem(2) eq 'third string' or die "Assertion failed\n";
    $authnRequest->{respondWith} = undef;
    $authnRequest->{respondWith} eq undef or die "Assertion failed\n";

    undef $authnRequest;

    print "..OK\n";
}

sub test04 {
    print "Get & set attributes of nodes of type node list.";

    my $response = new lasso::SamlpResponse;

    $response->{assertion} eq undef or die "Assertion failed\n";

    my $assertions = new lasso::NodeList;
    $assertions->length eq 0 or die "Assertion failed\n";
    my $assertion1 = new lasso::SamlAssertion;
    $assertion1->{assertionId} = 'assertion 1';
    $assertions->append($assertion1);
    $assertions->length eq 1 or die "Assertion failed\n";
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    my $assertion2 = new lasso::SamlAssertion;
    $assertion2->{assertionId} = 'assertion 2';
    $assertions->append($assertion2);
    $assertions->length eq 2 or die "Assertion failed\n";
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $assertions->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    my $assertion3 = new lasso::SamlAssertion;
    $assertion3->{assertionId} = 'assertion 3';
    $assertions->append($assertion3);
    $assertions->length eq 3 or die "Assertion failed\n";
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $assertions->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $assertions->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    $response->{assertion} = $assertions;
    $response->{assertion}->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $response->{assertion}->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $response->{assertion}->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $assertions->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $assertions->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    undef $assertions;
    $response->{assertion}->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $response->{assertion}->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $response->{assertion}->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    $assertions = $response->{assertion};
    $assertions->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $assertions->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $assertions->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    undef $assertions;
    $response->{assertion}->getItem(0)->{assertionId} eq 'assertion 1' or die "Assertion failed\n";
    $response->{assertion}->getItem(1)->{assertionId} eq 'assertion 2' or die "Assertion failed\n";
    $response->{assertion}->getItem(2)->{assertionId} eq 'assertion 3' or die "Assertion failed\n";
    $response->{assertion} = undef;
    $response->{assertion} eq undef or die "Assertion failed\n";

    undef $response;

    print "..OK\n";
}

sub test05 {
    print "Get & set attributes of nodes of type XML list.";

    my $authnRequest = new lasso::LibAuthnRequest;

    $authnRequest->{extension} eq undef or die "Assertion failed\n";

    my $actionString1 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 1</action>
</lib:Extension>';
    my $actionString2 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 2</action>
</lib:Extension>';
    my $actionString3 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 3</action>
</lib:Extension>';
    my $extension = new lasso::StringList;
    $extension->length eq 0 or die "Assertion failed\n";
    $extension->append($actionString1);
    $extension->length eq 1 or die "Assertion failed\n";
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->append($actionString2);
    $extension->length eq 2 or die "Assertion failed\n";
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $extension->append($actionString3);
    $extension->length eq 3 or die "Assertion failed\n";
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $extension->getItem(2) eq $actionString3 or die "Assertion failed\n";
    $authnRequest->{extension} = $extension;
    $authnRequest->{extension}->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(2) eq $actionString3 or die "Assertion failed\n";
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $extension->getItem(2) eq $actionString3 or die "Assertion failed\n";
    undef $extension;
    $authnRequest->{extension}->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(2) eq $actionString3 or die "Assertion failed\n";
    $extension = $authnRequest->{extension};
    $extension->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $extension->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $extension->getItem(2) eq $actionString3 or die "Assertion failed\n";
    undef $extension;
    $authnRequest->{extension}->getItem(0) eq $actionString1 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(1) eq $actionString2 or die "Assertion failed\n";
    $authnRequest->{extension}->getItem(2) eq $actionString3 or die "Assertion failed\n";
    $authnRequest->{extension} = undef;
    $authnRequest->{extension} eq undef or die "Assertion failed\n";

    undef $authnRequest;

    print "..OK\n";
}

sub test06 {
    print "Get & set attributes of nodes of type node.";

    my $login = new lasso::Login(new lasso::Server);

    $login->{request} eq undef or die "Assertion failed\n";
    $login->{request} = new lasso::LibAuthnRequest;
    $login->{request}->{consent} = lasso::LIB_CONSENT_OBTAINED;
    $login->{request}->{consent} eq lasso::LIB_CONSENT_OBTAINED or die "Assertion failed\n";
    undef $login->{request};
    $login->{request} eq undef or die "Assertion failed\n";

    undef $login;

    print "..OK\n";
}

lasso::init;
test01;
test02;
test03;
test04;
test05;
test06;
lasso::shutdown();
