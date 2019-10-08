#!/usr/bin/env perl

#error: maximum authentication attempts exceeded for root from 188.92.77.235 port 55541 ssh2 [preauth]
# error: maximum authentication attempts exceeded for

if ( $< == 0 ) {
  if ($ARGV[0] =~ /^[\d\.]+$/) {
    system('/sbin/pfctl', '-t', 'badhosts', '-T', 'add', $ARGV[0]);
  } else {
    die 'gtfo';
  }
  exit 0;
}

while (my $line = <STDIN>) {
  next unless $line =~ /maximum authentication attempts/;
  if ($line =~ /error: maximum authentication attempts exceeded for ([\w\s]+) from ([\d\.]+)/ ) {
    my $rc = system('/usr/bin/doas', '/home/coderz/flail2win.pl', $2);
    if ($rc) {
      system('/usr/bin/logger', '-p', 'auth.error', '"'.$2.'" cannot be blocked');
    }
  } else {
    open my $x, '>', '/tmp/oops';
    print $x $line;
    close $x;
  }
}

