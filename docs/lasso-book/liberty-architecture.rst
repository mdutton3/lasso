========================
The Liberty Architecture
========================

Building on existing pieces, XML, SAML, SOAP, HTTP, SSL...

Points to specs; quick glossary; user = principal...

Maps use cases to profiles.

This chapter provides a quick overview of the different profiles; they will be
detailed and implemented in the next chapters.


Single Sign-On and Federation
=============================

A few paragraphs; what does single sign-on and federation really mean...


Artifact Profile
----------------

.. figure:: figures/single-sign-on.png

   Single Sign-On and Federation interactions, Artifact profile

1. the user clicks on a "login" button
2. the service provider answers with a redirect to the identity provider
3. the browser goes to the identity provider where the user logs in
4. the identity provider answers with a redirect, back to the service provider
5. the browser goes to the service provider telling it has been authenticated
6. the service provider makes a SOAP request to the identity provider asking
   if it is true that the user has been authenticated
7. the identity provider answers that yeah, everything is under control
8. the service provider answers to the browser and send a welcome page


Browser POST Profile
--------------------

Almost the Same thing.


Single Log-out
==============

A few words about the five different profiles.


Initiated by the Service Provider, using SOAP requests
------------------------------------------------------

.. figure:: figures/single-logout.png

   Single Log-out interactions; initiated at service provider, using SOAP


Should arrange the figure with the SP on the right; I think it would help read
the figure.


Initiated by the Service Provider, using HTTP Redirects
-------------------------------------------------------

3 more to go.



Liberty URLs
============

How does the identity provider knows the "SOAP endpoint" of the service
provider ?  That is metadata for you.

