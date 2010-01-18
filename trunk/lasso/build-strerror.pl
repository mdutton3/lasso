open(H,"<errors.h");
while (<H>) {
	if (/#define (LASSO_\w+).*\/\*\s*(.*?)\s*\*\//) {
		$messages{$1} = $2;
	} elsif (/#define (LASSO_\w+)/) {
		$messages{$1} = $1;
	}
}
close(H);
open(C_IN,"<errors.c.in");
#open(C,">errors.c");
while (<C_IN>) {
	if (/@ERROR_CASE\@/) {
		foreach $k (sort (keys %messages)) {
			$msg = $messages{$k};
			print  "\t\tcase $k:\n";
			print  "\t\t\treturn \"$msg\";\n\n";
		}
	} else {
		print ;
	}
}
close(C_IN);
#close(C);
