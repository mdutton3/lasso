# File : Makefile.PL

use ExtUtils::MakeMaker;

$CFLAGS=$ENV{CFLAGS} || "";

WriteMakefile(
	      NAME    => 'lasso',	# Name of package
	      VERSION => '0.5.9',
	      LIBS    => ['-llasso'],  # Name of custom libraries
	      OBJECT  => 'lasso_wrap.o', # Object files
	      AUTHOR  => 'Frederic Peters <fpeters@entrouvert.com>',
	      MAKEFILE => 'Makefile.perl',
	      DEFINE    => "-DHAVE_CONFIG_H $CFLAGS",
);
