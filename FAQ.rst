Lasso FAQ
=========

Generalities
------------

1. What is Lasso ?

 Lasso is a C library which implements the identity federation and single-sign
 on protocol standards ID-FF 1.2 and SAML 2.0. It also implements attribute
 exchange

2. What does Lasso mean ?

 Lasso is the acronym of Liberty Alliance Single Sign On.

2. What is Liberty Alliance ?

 It'a consortium built to propose a common XML standard for transmitting
 information about authentication and identity, made in response to the
 Microsoft Passport technology. It has since been dismantled and all its assets
 are now managed by the Oasis standard body and the Kantara initiative.

 The more recent standard coming from the initial Liberty Alliance initiative
 is SAML 2.0.

Use of the library
------------------

1. How to make a simple POST assertion consumer using Python ?

Using Python&WSGI:

.. code-block:: python

    import sys
    import lasso
    from wsgiref.simple_server import make_server
    import logging
    import urlparse

    logging.basicConfig(level=logging.DEBUG)

    sp_metadata_xml = '''<?xml version="1.0"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
          xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
          entityID="http://localhost:8081/metadata">
      <SPSSODescriptor
          AuthnRequestsSigned="true"
          protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

        <AssertionConsumerService isDefault="true" index="0"
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          Location="http://localhost:8081/singleSignOnPost" />
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
      </SPSSODescriptor>
      <Organization>
         <OrganizationName xml:lang="en">Example SAML 2.0 metadatas</OrganizationName>
      </Organization>
    </EntityDescriptor>'''

    idp_metadata_xml = '''<?xml version="1.0"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        entityID="http://localhost:3001/saml/metadata">


      <IDPSSODescriptor
          WantAuthnRequestsSigned="true"
          protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue  xmlns="http://www.w3.org/2000/09/xmldsig#">
        <RSAKeyValue>
            <Modulus>4yalpsp9Sxlsj07PEI8jJxhSJdo4F0iW0H8u1dhwmsW5YQvRUw/yPlmC09q4WjImmnFVNCJarAOYeFgQCxfIoBasKNnUeBQpogo8W0Q/3mCuKl6lNSr/PIuxMVVNPDWmWkhHXJx/MVar2IREKa1P4jHL0Uxl69/idLwc7TtK1h8=</Modulus>
            <Exponent>AQAB</Exponent>
        </RSAKeyValue>
    </KeyValue>
          </ds:KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue  xmlns="http://www.w3.org/2000/09/xmldsig#">
        <RSAKeyValue>
            <Modulus>wLu5SdmwyS4o1On/aw4nElLGERFG931exvkzu0ewaM1/oUyD3dO7UC5xMGnPfc6IaH5BcJc3fLr6PJhX55ZrMR98ToPwoUFwuLKK43exwYBEBOOMe1CrCB/Bq+EH6/2sKNXKfgJqj06/3yzafLRiWpMxy2isllxMAvaZXrkpm4c=</Modulus>
            <Exponent>AQAB</Exponent>
        </RSAKeyValue>
    </KeyValue>
          </ds:KeyInfo>
        </KeyDescriptor>
      </IDPSSODescriptor>

    </EntityDescriptor>
    '''

    def app(environ, start_response):
        server = lasso.Server.newFromBuffers(sp_metadata_xml)
        server.addProviderFromBuffer(lasso.PROVIDER_ROLE_IDP, idp_metadata_xml)
        login = lasso.Login(server)
        try:
            data = environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))
            qs = urlparse.parse_qs(data)
            try:
                login.processAuthnResponseMsg(qs['SAMLResponse'][0])
            except (lasso.DsError, lasso.ProfileCannotVerifySignatureError):
                raise Exception('Invalid signature')
            except lasso.Error:
                raise Exception('Misc error')
            try:
                login.acceptSso()
            except lasso.Error:
                raise Exception('Invalid assertion')
        except Exception, e:
            start_response('500 Internal Error', [('content-type', 'text/plain')],
                sys.exc_info())
            return ['Erreur: ', str(e)]
        else:
            start_response('200 Ok', [('content-type', 'text/plain')], sys.exc_info())
            return ['You are identified as ', login.assertion.subject.nameId.content]

    s = make_server('0.0.0.0', 8081, app)
    s.serve_forever()

2. How to make a simple POST assertion consumer using PHP5 ?

Put the following content in a file named index.php:

.. code-block:: php

  <?
  require "lasso.php";

  $sp_metadata_xml = <<<'XML'
  <?xml version="1.0"?>
  <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        entityID="http://yourdomain.com/index.php?metadata">
    <SPSSODescriptor
        AuthnRequestsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

      <AssertionConsumerService isDefault="true" index="0"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://yourdomain.com/index.php?assertion_consumer" />
      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    </SPSSODescriptor>
    <Organization>
       <OrganizationName xml:lang="en">Example SAML 2.0 metadatas</OrganizationName>
    </Organization>
  </EntityDescriptor>
  XML;

  $idp_metadata_xml = <<<'XML'
  <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="http://localhost:3001/saml/metadata">


    <IDPSSODescriptor
        WantAuthnRequestsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <KeyValue  xmlns="http://www.w3.org/2000/09/xmldsig#">
      <RSAKeyValue>
          <Modulus>4yalpsp9Sxlsj07PEI8jJxhSJdo4F0iW0H8u1dhwmsW5YQvRUw/yPlmC09q4WjImmnFVNCJarAOYeFgQCxfIoBasKNnUeBQpogo8W0Q/3mCuKl6lNSr/PIuxMVVNPDWmWkhHXJx/MVar2IREKa1P4jHL0Uxl69/idLwc7TtK1h8=</Modulus>
          <Exponent>AQAB</Exponent>
      </RSAKeyValue>
  </KeyValue>
        </ds:KeyInfo>
      </KeyDescriptor>
      <KeyDescriptor use="encryption">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <KeyValue  xmlns="http://www.w3.org/2000/09/xmldsig#">
      <RSAKeyValue>
          <Modulus>wLu5SdmwyS4o1On/aw4nElLGERFG931exvkzu0ewaM1/oUyD3dO7UC5xMGnPfc6IaH5BcJc3fLr6PJhX55ZrMR98ToPwoUFwuLKK43exwYBEBOOMe1CrCB/Bq+EH6/2sKNXKfgJqj06/3yzafLRiWpMxy2isllxMAvaZXrkpm4c=</Modulus>
          <Exponent>AQAB</Exponent>
      </RSAKeyValue>
  </KeyValue>
        </ds:KeyInfo>
      </KeyDescriptor>
    </IDPSSODescriptor>

  </EntityDescriptor>
  XML;

  if (isset($_GET["metadata"])) {
    header('Content-Type: text/xml');
    echo $sp_metadata_xml;
    exit(0);
  }

  if (isset($_GET["assertion_consumer"])) {
    $server = LassoServer::newFromBuffers($sp_metadata_xml);
    $server->addProviderFromBuffer(LASSO_PROVIDER_ROLE_IDP, $idp_metadata_xml);
    $login = new LassoLogin($server);

    function error($msg) {
        header("HTTP/1.0 500 Internal Error");
        ?> <h1>Erreur:</h1><pre> <?  echo htmlentities($msg); ?></pre><?
        exit(0);
    }

    try {
        try {
            $login->processAuthnResponseMsg($_POST["SAMLResponse"]);
        } catch (LassoDsError $e) {
            error('Invalid signature');
        } catch (LassoProfileCannotVerifySignatureError $e) {
            error('Invalid signature');
        } catch (LassoError $e) {
            error('Misc error, ' . $e);
        }
        try {
            $login->acceptSso();
        } catch (LassoError $e) {
            error('Invalid assertion');
        }
    } catch (Exception $e) {
        error('Unexpected error: ' . $e);
    }
    ?> You are identified as <? echo $login->assertion->subject->nameId->content;

You must replace the ``$idp_metadata_xml`` variable by your identity provider metadata.
You can indicate to your identity provider the URL
http://yourdomain.com/index.php?metadata as the URL of your metadata file.
