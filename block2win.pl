#!/usr/bin/env perl

use Sys::Syslog qw(:standard :macros);
use Getopt::Std;

my $options = {};
getopts('df:t:', $options);

my $table = 'badhosts';
$table = $options->{t} if (exists $options->{t});

# when called as root modify the table
if ( $< == 0 ) {
  use Socket qw( inet_pton AF_INET AF_INET6);
  my $ip = inet_pton AF_INET, $ARGV[0];
  if ($ip) {
    exit system('/sbin/pfctl', '-t', $table, '-T', 'add', $ARGV[0]);
  }
  $ip = inet_pton AF_INET6, $ARGV[0];
  if ($ip) {
    exit system('/sbin/pfctl', '-t', $table, '-T', 'add', $ARGV[0]);
  }
  die 'gtfo';
}

# openlog for main daemon runned by syslog

my $sysopt = 'nofatal,ndelay,pid';
$sysopt .= 'perror' if (exists $options->{d});

openlog($0, 'nofatal,ndelay,pid', LOG_AUTH);

my $myself = 'blocker:'.$$;

# read matcher of IP from log

my @regexps = (
  'error: maximum authentication attempts exceeded for ([\w\s]+) from (?<ip>[\d\.]+)'
);

my $fileofmatcher = '/etc/blockers';
$fileofmatcher = $options->{f} if (exists $options->{f});

if ( -s $fileofmatcher ) {
  @regexps = ();
  open my $conf, '<', $fileofmatcher;
  while (my $entry = <$conf>) {
    next if ($entry =~ m/^\s*#/);
    unless ( $entry = m/\<ip\>/ ) {
      syslog(LOG_ERR, '%s, cannot use %s as a regexp', $myself, $entry);
      next;
    }
    chomp $entry;
    push @regexps, qr/$entry/;
    syslog(LOG_DEBUG, '%s, using %s as a regexp', $myself, $entry);
  }
}

# when log match , run ourself with doas

sub pushblock {
  return unless ($_[0] =~ m/$_[1]/);
  unless ( exists $+{ip} ) {
    return;
  }
  my $rc = system('/usr/bin/doas', '/home/coderz/block2win.pl', $2);
  if ($rc) {
    syslog(LOG_ERR, '%s, the log entry for %s:%s cannot failed to change the %s table'
    , $myself, $1, $2, $table);
  }
  return $rc;
}

#MAIN

while (my $line = <STDIN>) {
  next if (0 < index($line, $myself)); #never reparse ourself
  foreach my $re (@regexps) {
    pushblock( $line, $re);
  }
}
