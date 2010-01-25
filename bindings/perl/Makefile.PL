use 5.010000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my $TOP_SRCDIR = $ENV{'TOP_SRCDIR'};
my $TOP_BUILDDIR = $ENV{'TOP_BUILDDIR'};
my $SRCDIR = $ENV{'SRCDIR'};
my $VERSION = $ENV{'VERSION'};
my $BUILDDIR = $ENV{'BUILDDIR'};
my $CFLAGS = $ENV{'CFLAGS'};

if (undef($TOP_SRCDIR) || undef($TOP_BUILDDIR)) {
	exit(1);
}

$lasso_libs = `$TOP_BUILDDIR/lasso-src-config --libs`;

WriteMakefile(
    NAME              => 'Lasso',
    VERSION           => $VERSION,
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      ( AUTHOR         => 'Benjamin Dauvergne <bdauvergne@entrouvert.com>') : ()),
    LIBS              => ["-L$TOP_SRCDIR/lasso/.libs -llasso"], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => "-I. -I$SRCDIR -I../../../ $CFLAGS", # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => 'Lasso.o', # link all the C files too
    MAKEFILE          => 'Makefile.perl',

);
