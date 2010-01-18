======================
Common Lasso Knowledge
======================

Starting with basics on using Lasso in a given program.

Lasso Projects Basics
=====================

Lasso functions are defined in several header files typically located in
``/usr/include/lasso/`` or ``/usr/local/include/lasso/``.  It is possible to
include individual files even if the main lasso.h is sufficient most often.

The first thing to do is then to call ``lasso_init()``.  Similarly the last
thing will be to call ``lasso_shutdown()``.  The smallest and useless Lasso
project will therefore be::

  #include <lasso/lasso.h>

  int main(int argc, char *argv[])
  {
      lasso_init();
      printf("Hello world.\n");
      lasso_shutdown();
      return 0;
  }

Lasso uses a tool called ``pkg-config`` to know the necessary flags for
compilation and linking.

::

  $ pkg-config lasso --cflags
 -DXMLSEC_CRYPTO=\"openssl\" -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__
 -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO_OPENSSL=1
 -I/usr/include/lasso -I/usr/include/libxml2 -I/usr/include/xmlsec1 -I/usr/include/glib-2.0
 -I/usr/lib/glib-2.0/include
  $ pkg-config lasso --libs
 -llasso -lxmlsec1-openssl -lxmlsec1 -lssl -lcrypto -ldl -lgobject-2.0 -lxslt -lxml2
 -lpthread -lz -lm -lglib-2.0


Creating an executable from the previous sample *will then be* a simple
matter of calling gcc with the right flags

Creating an executable from the previous sample would then a simple matter of
calling ``gcc`` with the right flags.  But there is currently in bug in
XMLSec, the library used by Lasso to provide XML Signature and XML Encryption
support.  It is possible to workaround the bug::

  $ gcc hello.c -o hello $(pkg-config lasso --cflags --libs)
 <command line>:4:16: missing terminating " character
  $ gcc hello.c -o hello $(pkg-config xmlsec1 --cflags --libs | tr -d '\\')
  $ ./hello
 Hello world.


.. XXX talks about autoconf/automake; that really helps.  But that could be in
   an appendix.


Lasso Objects
=============

The Lasso Architecture chapter described the different objects provided by
Lasso.  The profile objects will be detailed in the following chapters; common
objects such as server, identity and session are explained here.


LassoServer
-----------

A ``LassoServer`` object may be created as follows:

::

  LassoServer *server;
  server = lasso_server_new("sp-metadata.xml",
  		NULL, "sp-private-key.pem", "sp-crt.pem", lassoSignatureMethodRsaSha1);
  lasso_server_add_provider(server, "idp-metadata.xml",
  		"idp-public-key.pem", "ca-crt.pem");

- ``sp-metadata.xml`` is the Liberty metadata file for the service provider
- ``idp-metadata.xml`` is the Liberty metadata file for the identity provider
- ``sp-private-key.pem`` is the service provider private key; used to sign
  documents
- ``sp-crt.pem`` is the service provider certificate; sent within signed
  documents
- ``idp-public-key.pem`` is the identity provider public key; used to verify
  signature in documents sent by the identity provider
- ``ca-crt.pem`` is the certificate of the certification authority used by the
  identity provider.

It is of course possible to have several calls to ``lasso_server_add_provider``
if there are more than one identity provider.

LassoProfile
------------

This is the virtual base class for profiles.  It notably provides access to the
identity and session parts of a profile.  See below for examples.


LassoIdentity
-------------

::

  /* profile is a pointer to a LassoProfile object */

  LassoIdentity *identity;

  if (lasso_profile_is_identity_dirty(profile)) {
      identity = lasso_profile_get_identity(profile);
      if (identity) {
          dump = lasso_identity_dump(identity);
      }
  }



LassoSession
------------

::

  /* profile is a pointer to a LassoProfile object */

  LassoSession *session;

  if (lasso_profile_is_session_dirty(profile)) {
      session = lasso_profile_get_session(profile);
      if (session) {
          dump = lasso_session_dump(session);
      }
  }



Serialization
-------------

``LassoServer``, ``LassoIdentity`` and ``LassoSession``objects can be
serialized into XML files.  Example with a ``LassoServer``::

  gchar *dump;
  FILE *fd;

  dump = lasso_server_dump(server);
  /* write dump into a file, a database, whatever */
  g_free(dump);

.. note:: ``lasso_server_dump`` (and other Lasso dump functions) allocates
          memory through GLib.  ``g_free`` is the function to use instead
	  of ``free`` to release memory.

It is then really easy to have properly constructed objects returned::

  LassoServer *server;
  gchar *dump;

  /* restore dump from file, database, whatever */
  server = lasso_server_new_from_dump(dump);

.. warning:: The server dump only contains the filenames; not the actual file
             contents.  Files should not be moved afterwards.

The functions are:

================   ====================  =============================
Object             Dump                  Restore
================   ====================  =============================
LassoServer        lasso_server_dump     lasso_server_new_from_dump
LassoIdentity      lasso_identity_dump   lasso_identity_new_from_dump
LassoSession       lasso_session_dump    lasso_session_new_from_dump
================   ====================  =============================

