=============
Getting Lasso
=============

Lasso is licensed under the GNU General Public License.  That means users are
given several inalienable rights: the right to use the library, whatever the
purpose is; the right to study how it works, getting access to source code; the
right to distribute the library to others and the right to modify the library
and publish those modifications.

Talks about library and how Lasso will force the use of the GPL.


Binary packages
===============

Debian packages
---------------

The latest Lasso release should be available straight from any Debian mirror
worldwide in the ``etch`` or ``sid`` distribution.  Additionaly packages are
provided for the ``sarge`` release on a dedicated APT repository.  The
following line needs to be added to ``/etc/apt/sources.list``::

  deb http://www.entrouvert.org ./debian/lasso/

It is then a matter of running::

  apt-get install liblasso-dev


RPM packages
------------

RPM Bad.  A mess.


Microsoft Windows packages
--------------------------

Ah.  Isn't that funky ?  (need to ask Romain about cygwin, mingw32 and whatever
is needed to get Lasso working on Windows)


Sources
=======

The source code of the latest release is available at the following URL:
http://labs.libre-entreprise.org/project/showfiles.php?group_id=31

Lasso uses the GNU automake and autoconf to handle system dependency
checking.  It is developed and built locally on GNU/Linux (Debian) both
on x86 and PowerPC processors.

Compiling
---------

::

  ./configure

The ``configure`` shell script attempts to guess correct values for various
system-dependent variables used during compilation.  It uses those values to
create a ``Makefile`` in each directory of the package.  It may also create one
or more ``.h`` files containing system-dependent definitions.  Finally, it
creates a shell script ``config.status`` that can be run in the future to
recreate the configuration, and a file ``config.log`` containing compiler
output (useful mainly for debugging ``configure``).

``configure`` can take a lot of options, a complete list is available with the
``--help`` flag: ``./configure --help``

Installation Directories
........................

By default, Lasso will be installed in ``/usr/local/lib``.  It is possible to
specify an installation prefix other than ``/usr/local`` by giving the option
``--prefix=PATH``; for example ``--prefix=/usr``.


Optional Features
.................

There are optional features that you may want not to build, things like unit
tests, bindings for different languages, etc.

=====================    ============================
``--disable-java``       Disable the Java binding
``--disable-python``     Disable the Python binding
``--disable-php``        Disable the PHP binding
``--disable-csharp``     Disable the C# binding
``--disable-tests``      Disable the unit tests
=====================    ============================

On the other hand there are features you may want to activate.

======================   ====================================
``--enable-debugging``   Enable debugging messages
``--enable-profiling``   Enable profiling compilation flags
======================   ====================================

Once ``./configure`` has been executed it is time to compile the whole thing.

::

  make

It should take a few minutes.

::

  make install

Will then copy the library and header files to their final directories.

Bleeding Edge
-------------

CVS (Concurrent Versions System) is the version control system used by Lasso
developers to keep track of files, how and by whom they were modified.  It is
accessible anonymously for people to use the latest developments.

::

  export CVSROOT=:pserver:anonymous@cvs.labs.libre-entreprise.org:/cvsroot/lasso
  cvs login     # press enter
  cvs -z3 checkout lasso

.. note:: The CVS version requires more tools to build; notably automake,
          autoconf and libtool.

