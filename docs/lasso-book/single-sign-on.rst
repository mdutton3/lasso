=============================
Single Sign-On and Federation
=============================

Profile Overview
================

The service provider has four things to do:

- creating an authentication request
- sending it to the identity provider
- receiving an authentication response or an artifact
- (eventually) checking it against the identity provider

The first two steps are handled with an HTTP redirection; typically the user
would click on a button, the service provider would then create the
authentication request and send an HTTP Redirect to the browser.  No URL is
defined in the specifications for this first step.

The last two steps are handled in the *AssertionConsumerServiceURL*; the user
will arrive there through an HTTP Redirect or an HTTP POST carrying a piece of
information from the identity provider.  In case of a redirect, this
information won't be large and will be exchanged with the identity provider for
a *AuthnResponse*.  An HTTP POST will be able to carry much more information
and will therefore directly provider the same *AuthnResponse*.

An appropriate metadata snippet would be::

  <?xml version="1.0"?>
  <EntityDescriptor providerID="service-provider" xmlns="urn:liberty:metadata:2003-08">
   <SPDescriptor>
    <AssertionConsumerServiceURL id="AssertionConsumerServiceURL1" isDefault="true">
     https://service-provider.example.com/liberty-alliance/assertionConsumer
    </AssertionConsumerServiceURL>
   </SPDescriptor>
  </EntityDescriptor>


The identity provider has more things to do:

- receiving an authentication request
- authenticating the user if necessary
- sending a response to the service provider
- (eventually) answering a SOAP request with an other response

All but the last one is handled in the *SingleSignOnServiceURL*; the user has
been redirected there from the service provider with an authentication request
as URL parameter.  This authentication request is used to decide several things
(allowed authentication methods for example) and the authentication is done.
This step is not part of the Liberty protocols, this can be as simple as
straight HTTP authentication with a username and a password or as complex as a
Java applet checking a certificate on the client.

Anyway, once the user has been authenticated, an answer must be sent to the
service provider.  It is actually not a direct communication, the answer
bounces on the user agent with an HTTP Redirect or by an HTML form pointing to
the service provider.

The first case is preferred, an *artifact* is generated and incorporated in a
URL (based on the service provider *AssertionConsumerURL*); the user is then
simply redirected to this URL.  The service provider will then make a SOAP
request to the *SoapEndpoint* asking for the authentication response matching
the artifact.

The second case consists in the identity provider answering with an HTML page
with an HTML form embedding the authentication response.  The user will then
submit this form to the service provider *AssertionConsumerURL*.

Metadata would be::

  <?xml version="1.0"?>
  <EntityDescriptor providerID="identity-provider" xmlns="urn:liberty:metadata:2003-08">
   <IDPDescriptor>
    <SoapEndpoint>
     https://identity-provider.example.com/soapEndpoint
    </SoapEndpoint>
    <SingleSignOnServiceURL>
     https://identity-provider.example.com/singleSignOn
    </SingleSignOnServiceURL>
   </IDPDescriptor>
  </EntityDescriptor> 


Implementing the service provider parts
=======================================

Sending the user to the identity provider
-----------------------------------------

XXX


Receiving an answer from the identity provider
----------------------------------------------

XXX



Implementing the identity provider parts
========================================

XXX


