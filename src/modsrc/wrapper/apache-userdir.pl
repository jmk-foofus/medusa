#!/usr/bin/perl
#
#
# apache-userdir.pl 192.168.0.1 USER PASS 0 [NO SSL]
# apache-userdir.pl 192.168.0.1 USER PASS 1 [SSL]
#
# PASS is ignored...
#
# HEAD /~username HTTP/1.0
#
# medusa -M wrapper -h 192.168.0.1 -U users.txt -p DOESNOTMATTER -m TYPE:SINGLE -m ARGS:"%H %U %P 1" -m PROG:./apache-userdir.pl

use LWP::UserAgent;

$host = $ARGV[0];
$user = $ARGV[1];
$pass = $ARGV[2]; # ignored
$ssl = $ARGV[3];

pop(@ARGV);
pop(@ARGV);
pop(@ARGV);
pop(@ARGV);

my $ua = LWP::UserAgent->new(env_proxy => 1, keep_alive => 1, timeout => 3);
#$ua->proxy(['http', 'https'], 'http://localhost:8008/');

if ($ssl) { $req = new HTTP::Request GET => "https://$host/~$user"; }
else { $req = new HTTP::Request GET => "http://$host/~$user"; }
$req->user_agent('MS Internet Exploder/4.0');
my $res = $ua->request($req);

if ($res->is_success)   { print STDERR "LOGIN_RESULT_SUCCESS\n"; }
elsif ($res->code==403) { print STDERR "LOGIN_RESULT_SUCCESS\n"; } 
else                    { print STDERR "LOGIN_RESULT_FAIL\n"; }
