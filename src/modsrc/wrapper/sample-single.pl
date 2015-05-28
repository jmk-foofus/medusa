#!/usr/bin/perl
#
#
# foo.pl -h 192.168.0.20 -u foo -p bar

$host = $ARGV[0];
$user = $ARGV[1];
$pass = $ARGV[2];

sleep(1);

if ($pass eq "CORRECT_PASS")
{
  print "LOGIN_RESULT_SUCCESS\n";
}
elsif ($pass eq "ERROR_PASS")
{
  print "LOGIN_RESULT_ERROR\n";
}
else
{
  print "LOGIN_RESULT_FAIL\n";
}


