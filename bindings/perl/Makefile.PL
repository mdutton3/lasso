use 5;
use ExtUtils::MakeMaker;


if (not grep /^LIBS=/, @ARGV) {
	$LIBS=`pkg-config --libs lasso 2>&1`;
	die "pkg-config cannot find lasso" if $?;
}

WriteMakefile(
    NAME              => 'Lasso',
    VERSION           => $VERSION,
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      ( AUTHOR         => 'Benjamin Dauvergne <bdauvergne@entrouvert.com>') : ()),
    LIBS              => [ "$LIBS" ],
    MAKEFILE          => 'Makefile.perl',
    dynamic_lib       => { OTHERLDFLAGS => '-Wl,--as-needed' }
);
