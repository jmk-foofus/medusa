#!/usr/bin/perl
#
# medusa -M wrapper -m TYPE:SINGLE -m PROG:./null-session.pl -m ARGS:"%H %U %P" -u 'foo' -p 'bar' -h 192.168.4.128
# foo.pl -h 192.168.0.20 -u foo -p bar
#
# W2K - RA=0                enumusers, lsaquery, lookupsids
# W2K - RA=1                lsaquery, lookupsids
# W2K - RA=2    
# XP SP1a                   lsaquery
# 2K3           
# 2K3 DC (Pre-W2K Comp.)    enumusers, lsaquery, lookupsids      
# 2K3 DC                    lsaquery, lookupsids
#
# other useful commands:
#   wksinfo, srvinfo, samgroupmem "Domain admins", samaliasmem BUILTIN\administrators

$host = $ARGV[0];
$user = $ARGV[1];
$pass = $ARGV[2];

#my $cmd = 'rpcclient -U "' . $user . '%' . $pass . '" -c "enumdomusers" ' . $host;
my $cmd = 'rpcclient -U "%" -c "enumdomusers" ' . $host;

open(HAND, "$cmd 2>&1|");
@results = <HAND>;
close(HAND);

#print "Results:\n----\n@results\n----\n";

if ( grep(/Error was NT_STATUS_ACCESS_DENIED/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/error: NT_STATUS_ACCESS_DENIED/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/Error was NT_STATUS_BAD_NETWORK_NAME/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/Error was NT_STATUS_CONNECTION_REFUSED/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/error: ERRnosupport/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/Error was NT_STATUS_UNSUCCESSFUL/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/failed session setup with NT_STATUS_LOGON_FAILURE/, @results) ) { print "LOGIN_RESULT_FAIL\n"; }
elsif ( grep(/user:/, @results) ) { print "LOGIN_RESULT_SUCCESS\n"; }
elsif ( grep(/result was NT_STATUS_ACCESS_DENIED/, @results) ) { print "LOGIN_RESULT_ERROR:Check lsaquery/lookupsids.\n"; }
else { print "LOGIN_RESULT_ERROR:Unknown error.\n"; }

