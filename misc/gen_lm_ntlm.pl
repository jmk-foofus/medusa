#!/usr/bin/perl 
use Crypt::SmbHash;

$username = $ARGV[0];
$password = $ARGV[1];

if ( !$password ) {
  print "Not enough arguments\n";
  print "Usage: $0 username password\n";
  exit 1;
}
   
ntlmgen $password, $lm, $nt;
printf "%s::%s:%s:::\n", $username, $lm, $nt;

#my @lm = split(//, $lm);
#print "LM: ";
#for($i=0; $i<32; $i=$i+2) { print "0x", $lm[$i], $lm[$i+1], ", "; }
#print "\n";

#my @nt = split(//, $nt);
#print "NT: ";
#for($i=0; $i<32; $i=$i+2) { print "0x", $nt[$i], $nt[$i+1], ", "; }
#print "\n";


