# File : Makefile.PL

use ExtUtils::MakeMaker;

$CC=$ENV{CC} || "cc";
$CFLAGS=$ENV{CFLAGS} || "";

my $objects="lasso_wrap.o ";

if(-r '../lasso-src-config') {
  my $lasso_libs=`../lasso-src-config --libs`;
  chomp $lasso_libs;
  $objects .= $lasso_libs;
}

my $includes="-I$TOP_SRCDIR/lasso";
my $version=$ENV{VERSION};

# I'm forced to do this since BASEEXT is defined in a non-overridable method.
push(@ExtUtils::MakeMaker::Overridable, "init_main");

sub MY::init_main {
  my($self)=@_;
  package MY; # so that "SUPER" works right
  $self->SUPER::init_main();

  # Stop perl linking with anything in the destination dir, it might
  # be entirely the wrong library such as a previous version.
  $self->{LDFLAGS} =~ s/-L\S+//;
  $self->{LDDLFLAGS} =~ s/-L\S+//;
}


WriteMakefile(
	      NAME    => 'lasso',	# Name of package
	      VERSION => $version,
	      OBJECT  => "$objects",
	      AUTHOR  => 'Frederic Peters <fpeters@entrouvert.com>',
	      MAKEFILE => 'Makefile.perl',
	      DEFINE    => "-DHAVE_CONFIG_H $CFLAGS",
	      CC => $CC,
);
