INCLUDES = \
    -DPACKAGE=\"@PACKAGE@\" \
    -I$(top_srcdir) \
    -I$(top_srcdir)/lasso \
    $(LASSO_DEFINES) \
    $(LASSO_CFLAGS) \
    $(PHP_INCLUDES) 


ENVSOURCES = lasso_identity.c lasso_profile.c lasso_session.c lasso_federation.c lasso_login.c lasso_server.c lasso_logout.c

noinst_LIBRARIES = libenvirons.a
libenvirons_a_SOURCES = $(ENVSOURCES)

EXTRA_DIST = $(ENVSOURCES) 
