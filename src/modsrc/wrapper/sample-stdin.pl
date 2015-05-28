#!/usr/bin/perl
#
#
# foo.pl -h 192.168.0.1 -u foo

$host = $ARGV[0];
$user = $ARGV[1];
pop(@ARGV);
pop(@ARGV);

while (<>) {
  chomp;
  $pass = $_;
 
  sleep(3);

  if ($pass eq "CORRECT_PASS")
  {
    print STDERR "LOGIN_RESULT_SUCCESS\n"; 
  }
  elsif ($pass eq "ERROR_PASS")
  {
    print STDERR "LOGIN_RESULT_ERROR\n"; 
  }
  else
  {
    print STDERR "LOGIN_RESULT_FAIL\n";
  }
}
