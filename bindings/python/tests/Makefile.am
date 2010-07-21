MAINTAINERCLEANFILES = Makefile.in
TESTS = #

TESTS_ENVIRONMENT=TOP_SRCDIR=$(top_srcdir)

if PYTHON_ENABLED
TESTS += profiles_tests.py binding_tests.py
endif

if WSF_ENABLED
TESTS += idwsf1_tests.py idwsf2_tests.py
endif

EXTRA_DIST = profiles_tests.py binding_tests.py idwsf1_tests.py idwsf2_tests.py \
	tests.py XmlTestRunner.py
