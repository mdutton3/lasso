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

The first two steps are handled with an HTTP redirection or an HTML form;
typically the user would click on a button, the service provider would then
create the authentication request and send an HTTP Redirect to the browser.  No
URL is defined in the specifications for this first step.

The last two steps are handled in the *AssertionConsumerServiceURL*; the user
will arrive there through an HTTP Redirect or an HTTP POST carrying a piece of
information from the identity provider.  In case of a redirect, this
information, called *artifact*, won't be large and will be exchanged with the
identity provider for a *AuthnResponse*.  An HTTP POST will be able to carry
much more information and will therefore be able to provide either the
*artifact* or directly the *AuthnResponse*.

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

The answer may be an *artifact* (available in the query string in case of a
redirect or in a ``LAREQ`` form field in case of a POST); the user is then
simply redirected to this URL.  The service provider will then make a SOAP
request to the *SoapEndpoint* asking for the authentication response matching
the artifact.

The answer may also be an *authentication response*; since it will be a large
piece of data it must be passed in an HTML page; an HTML form embedding the
authentication response.  The user will then submit this form to the service
provider *AssertionConsumerURL*.

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

.. warning:: The source code presented in the "implementing" section has for
             sole purpose to explain the different steps necessary to implement
             the profiles; they notably lack proper error checking.  See
             XXX for details on error checking.


Sending the user to the identity provider
-----------------------------------------

``server`` is a *LassoServer* object as seen earlier (`LassoServer`_) and
``idpProviderId`` is a string with the identity provider Id (the string must
match a providerID defined in the metadata file).

::

  LassoLogin *login;
  
  /* create login object */
  login = lasso_login_new(server);


Select profile to use, HTTP Redirect::

  lasso_login_init_authn_request(login, idpProviderId, LASSO_HTTP_METHOD_REDIRECT);

or HTTP POST::

  lasso_login_init_authn_request(login, idpProviderId, LASSO_HTTP_METHOD_POST);
  

Parametrize request::

  /* will force authentication on the identity provider */
  LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->ForceAuthn = TRUE;
  
  /* ask for identity federation */
  LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->NameIDPolicy =
      strdup(LASSO_LIB_NAME_ID_POLICY_TYPE_FEDERATED);

  /* the user consents with the idea of identity federation */
  LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->consent =
      strdup(LASSO_LIB_CONSENT_OBTAINED);

(see API reference for other possible values)


Create the authentication request::

  lasso_login_build_authn_request_msg(login);


An URL is then defined in ``LASSO_PROFILE(login)->msg_url``; the user must be
redirected to it; for example, in a CGI::
  
  printf("Location: %s\n", LASSO_PROFILE(login)->msg_url);



Receiving an answer from the identity provider
----------------------------------------------

This part is handled on the *AssertionConsumerURL*.


Receiving an assertion
......................

The user has been directed to this URL.  If it was a redirect the query string
(the part of the URL after the question mark) will hold the artifact and may be
used to initialize the *LassoLogin* object.

::

  LassoLogin *login;
  
  login = lasso_login_new(server);
  lasso_login_init_request(login, query_string, LASSO_HTTP_METHOD_REDIRECT);
  lasso_login_build_request_msg(login);

If it was a form post it will have a ``LAREQ`` field.

::

  LassoLogin *login;

  login = lasso_login_new(server);
  lasso_login_init_request(login, lareq_field, LASSO_HTTP_METHOD_POST);
  lasso_login_build_request_msg(login);


The service provider must then check this artifact using a SOAP request to the
identity provider.  The URL is ``LASSO_PROFILE(login)->msg_url`` while the
request is ``LASSO_PROFILE(login)->msg_body``.  The request must succeed with
an HTTP 200 status code.  The SOAP answer body must then be passed to::

  lasso_login_process_response_msg(login, answer);

Receiving an authentication response
....................................

A form with a ``LARES`` field has been posted; this element holds the
authentication response.

::

  LassoLogin *login;
  
  login = lasso_login_new(server);
  lasso_login_process_authn_response_msg(lares_field);


Federating identities
.....................

There is then a ``nameIdentifier`` (accessible through
``LASSO_PROFILE(login)->nameIdentifier``) for the user identifying.  If this
name identifier is already known by the service provider the corresponding
identity and session must be restored.

::

  if (session_dump != NULL) {
      lasso_profile_set_session_from_dump(LASSO_PROFILE(login), session_dump);
  }
  if (identity_dump != NULL) {
      lasso_profile_set_identity_from_dump(LASSO_PROFILE(login), identity_dump);
  }


Process the authentication request, this will update (or create) the identity
and session.

::

  lasso_login_accept_sso(login);

Identity and session must then be saved and finally the ``login`` object can be
destroyed::

  lasso_login_destroy(login);

And a success web page may then be displayed.





Implementing the identity provider parts
========================================

XXX


