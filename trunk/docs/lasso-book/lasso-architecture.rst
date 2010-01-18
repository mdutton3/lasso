======================
The Lasso Architecture
======================

Doesn't store, doesn't communicate.

Modeled on liberty profiles; one profile = one class

Objet oriented but in C.  Talks about how this work (necessary to know for the
lasso_profile functions)

------

Lasso provides the necessary functions to implement Liberty Alliance profiles,
as defined in the `Liberty ID-FF Bindings and Profiles Specification`_ and
explained in the previous chapter.  Each profile maps to a Lasso class:
 
=====================================    =============================
Single Sign-On and Federation            LassoLogin
Name Registration                        LassoRegisterNameIdentifier
Federation Termination Notification      LassoFederationTermination
Single Logout                            LassoLogout
Name Identifier Mapping                  LassoNameIdentifierMapping
Identity Provider Introduction           *not implemented*
Name Identifier Encryption               *not implemented*
=====================================    =============================


There are also a few other classes to know about:

- LassoServer holds the data about a provider, which other providers it knows,
  what certificates to use, etc.

- LassoIdentity holds the data about a Liberty federated identity
- LassoSession holds the data about an active Liberty session.

- LassoProfile is the base class for profiles.


Talk more about respective usage of Identity and Session.


.. _Liberty ID-FF Bindings and Profiles Specification:
   http://www.projectliberty.org/liberty/content/download/319/2369/file/draft-liberty-idff-bindings-profiles-1.2-errata-v2.0.pdf

