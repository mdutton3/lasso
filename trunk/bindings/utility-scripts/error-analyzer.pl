#! /usr/bin/perl -w
    eval 'exec /usr/bin/perl -S $0 ${1+"$@"}'
        if 0; #$running_under_some_shell

use strict;
use File::Find ();
use Data::Dumper;

# Set the variable $File::Find::dont_use_nlink if you're using AFS,
# since AFS cheats.

# for the convenience of &wanted calls, including -eval statements:
use vars qw/*name *dir *prune/;
*name   = *File::Find::name;
*dir    = *File::Find::dir;
*prune  = *File::Find::prune;

sub wanted;

sub unique {
    my @in = @_;
    my @ret = ();

    for my $x (@in) {
        push @ret, $x if (! grep /$x/, @ret);
    }
    return @ret;
}

my $functions = {};

my $p = $ARGV[0];

# Traverse desired filesystems
-d $p && File::Find::find({wanted => \&wanted}, $p);

foreach my $function (keys %$functions) {
    potential_errors($function);
}

foreach my $name (sort (keys %$functions)) {
    my $record = $functions->{$name};
    next if $record->{'return-type'} !~ /\bg?int\b/ || $record->{'return-type'} =~ /\bstatic\b/;
    my @derr = @{$record->{'errors'}};
    my @inherr = @{$record->{'inherited-errors'}[0]};
    my $path = $record->{'file'};
    print "$name ";
    my %temp = ();
    @temp{@inherr} = ();
    for (@derr) {
        delete $temp{$_};
        print "$_ ";
    }
    if (keys %temp) {
        foreach (keys %temp) {
            print "$_ ";
        }
    }
    print "\n";
}

exit;

sub potential_errors {
    my $function = shift;


    return ([],[[],[]]) if ! exists $functions->{$function};
    my $record = $functions->{$function};

    return ([],[[],[]]) if $record->{'return-type'} !~ /\bg?int\b/ || $record->{'recursing'};

    if (! exists $record->{'inherited-errors'}) {
        my @inheritederrors;
        my @froms;
        $record->{'recursing'} = 1;

        foreach my $call (@{$record->{'calls'}}) {
            my ($err,$inh) = potential_errors($call);
            my ($suberr,$subfrom) = @$inh;

            if (@$err || @$suberr) {
                push @froms, $call;
                push @inheritederrors, (@$err, @$suberr);
            }
        }
        $record->{'inherited-errors'} = [[ unique(@inheritederrors) ],[@froms]];
        delete $record->{'recursing'};
    }
    return ($record->{'errors'},$record->{'inherited-errors'});
}
    

sub parse_file {
    my $file = shift;
    my $path = shift;
    my $lastline;
    my $curfunction;
    my $curtype;
    my @curerrors;
    my @curcalls;
    my $infunction = 0;
    open FD, "<$file";
    while (<FD>) {

        MATCHING: {
            if ($infunction) {
                if (/^\}/) {
                    #print "finished funcctions $curfunction\n";
                    $functions->{$curfunction} = { name => $curfunction, 'return-type' => $curtype, 'errors' => [ unique(@curerrors) ], 'calls' => [ @curcalls], 'file' => $path};
                    $infunction = 0;
                    last MATCHING;
                }
                while (/(?:\breturn\b|=).*?([A-Za-z_]+)\(/g) {
                    push @curcalls, $1;
                }
                pos = 0;
                while (/(LASSO_[A-Z_]*_ERROR_[A-Z_]*|LASSO_ERROR_[A-Z_]*)/g) {
                    push @curerrors, $1;
                }
                last MATCHING;
            }
            if (/^([a-z_]+)\([^;]*$/) {
                $curfunction = $1;
                chop $lastline;
                $curtype = $lastline;
                @curerrors = ();
                @curcalls = ();
                last MATCHING;
            }
            if ($curfunction && /^\{/) {
                $infunction = 1;
                last MATCHING;
            }
        }
        $lastline = $_;

    }
    close FD;
}

sub wanted {
    my ($dev,$ino,$mode,$nlink,$uid,$gid);

    parse_file($_,$File::Find::name) if ($_ =~ /^.*\.c$/s && $File::Find::name !~ /^.*\.svn.*/);
}

