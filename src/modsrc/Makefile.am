
modulesdir = $(libdir)/medusa/modules

EXTRA_PROGRAMS = afp.mod cvs.mod ftp.mod http.mod imap.mod mssql.mod mysql.mod ncp.mod nntp.mod pcanywhere.mod \
                 pop3.mod postgres.mod rdp.mod rexec.mod rlogin.mod rsh.mod smbnt.mod smtp.mod smtp-vrfy.mod \
                 snmp.mod ssh.mod svn.mod telnet.mod vmauthd.mod vnc.mod web-form.mod wrapper.mod 

modules_PROGRAMS = 
if BUILD_MODULE_AFP
  modules_PROGRAMS += afp.mod
endif

if BUILD_MODULE_CVS
  modules_PROGRAMS += cvs.mod
endif

if BUILD_MODULE_FTP
  modules_PROGRAMS += ftp.mod
endif

if BUILD_MODULE_HTTP
  modules_PROGRAMS += http.mod
endif

if BUILD_MODULE_IMAP
  modules_PROGRAMS += imap.mod
endif

if BUILD_MODULE_MSSQL
  modules_PROGRAMS += mssql.mod
endif

if BUILD_MODULE_MYSQL
  modules_PROGRAMS += mysql.mod
endif

if BUILD_MODULE_NCP
  modules_PROGRAMS += ncp.mod
endif

if BUILD_MODULE_NNTP
  modules_PROGRAMS += nntp.mod
endif

if BUILD_MODULE_PCANYWHERE
  modules_PROGRAMS += pcanywhere.mod
endif

if BUILD_MODULE_POP3
  modules_PROGRAMS += pop3.mod
endif

if BUILD_MODULE_POSTGRES
  modules_PROGRAMS += postgres.mod
endif

if BUILD_MODULE_RDP
  modules_PROGRAMS += rdp.mod
endif

if BUILD_MODULE_REXEC
  modules_PROGRAMS += rexec.mod
endif

if BUILD_MODULE_RLOGIN
  modules_PROGRAMS += rlogin.mod
endif

if BUILD_MODULE_RSH
  modules_PROGRAMS += rsh.mod
endif

if BUILD_MODULE_SMBNT
  modules_PROGRAMS += smbnt.mod
endif

if BUILD_MODULE_SMTP
  modules_PROGRAMS += smtp.mod
endif

if BUILD_MODULE_SMTP_VRFY
  modules_PROGRAMS += smtp-vrfy.mod
endif

if BUILD_MODULE_SNMP
  modules_PROGRAMS += snmp.mod
endif

if BUILD_MODULE_SSH
  modules_PROGRAMS += ssh.mod
endif

if BUILD_MODULE_SVN
  modules_PROGRAMS += svn.mod
endif

if BUILD_MODULE_TELNET
  modules_PROGRAMS += telnet.mod
endif

if BUILD_MODULE_VMAUTHD
  modules_PROGRAMS += vmauthd.mod
endif

if BUILD_MODULE_VNC
  modules_PROGRAMS += vnc.mod
endif

if BUILD_MODULE_WEB_FORM
  modules_PROGRAMS += web-form.mod
endif

if BUILD_MODULE_WRAPPER
  modules_PROGRAMS += wrapper.mod
endif

afp_mod_SOURCES = afp.c ../medusa-trace.c
cvs_mod_SOURCES = cvs.c ../medusa-trace.c
ftp_mod_SOURCES = ftp.c ../medusa-trace.c
http_mod_SOURCES = http.c ntlm.c http-digest.c ../medusa-trace.c
imap_mod_SOURCES = imap.c ntlm.c ../medusa-trace.c
mssql_mod_SOURCES = mssql.c ../medusa-trace.c
mysql_mod_SOURCES = mysql.c ../medusa-trace.c sha1.c
ncp_mod_SOURCES = ncp.c ../medusa-trace.c
nntp_mod_SOURCES = nntp.c ../medusa-trace.c
pcanywhere_mod_SOURCES = pcanywhere.c ../medusa-trace.c
pop3_mod_SOURCES = pop3.c ntlm.c ../medusa-trace.c
postgres_mod_SOURCES = postgres.c ../medusa-trace.c
rdp_mod_SOURCES = rdp.c ../medusa-trace.c
rexec_mod_SOURCES = rexec.c ../medusa-trace.c
rlogin_mod_SOURCES = rlogin.c ../medusa-trace.c
rsh_mod_SOURCES = rsh.c ../medusa-trace.c
smbnt_mod_SOURCES = smbnt.c hmacmd5.c ../medusa-trace.c
smtp_mod_SOURCES = smtp.c ntlm.c ../medusa-trace.c
smtp_vrfy_mod_SOURCES = smtp-vrfy.c ../medusa-trace.c
snmp_mod_SOURCES = snmp.c ../medusa-trace.c
ssh_mod_SOURCES = ssh.c ../medusa-trace.c
svn_mod_SOURCES = svn.c ../medusa-trace.c
telnet_mod_SOURCES = telnet.c ../medusa-trace.c
vmauthd_mod_SOURCES = vmauthd.c ../medusa-trace.c
vnc_mod_SOURCES = vnc.c d3des.c ../medusa-trace.c
web_form_mod_SOURCES = web-form.c ../medusa-trace.c
wrapper_mod_SOURCES = wrapper.c ../medusa-trace.c

AM_CPPFLAGS = -I$(top_srcdir)/src $(all_includes)
afp_mod_LDFLAGS = -fPIC 
cvs_mod_LDFLAGS = -fPIC 
ftp_mod_LDFLAGS = -fPIC
http_mod_LDFLAGS = -fPIC
imap_mod_LDFLAGS = -fPIC
mssql_mod_LDFLAGS = -fPIC
mysql_mod_LDFLAGS = -fPIC
ncp_mod_LDFLAGS = -fPIC 
nntp_mod_LDFLAGS = -fPIC
pcanywhere_mod_LDFLAGS = -fPIC
pop3_mod_LDFLAGS = -fPIC
postgres_mod_LDFLAGS = -fPIC 
rdp_mod_LDFLAGS = -fPIC
rexec_mod_LDFLAGS = -fPIC
rlogin_mod_LDFLAGS = -fPIC
rsh_mod_LDFLAGS = -fPIC
smbnt_mod_LDFLAGS = -fPIC
smtp_mod_LDFLAGS = -fPIC 
smtp_vrfy_mod_LDFLAGS = -fPIC 
snmp_mod_LDFLAGS = -fPIC 
ssh_mod_LDFLAGS = -fPIC
svn_mod_LDFLAGS = -fPIC 
telnet_mod_LDFLAGS = -fPIC
vmauthd_mod_LDFLAGS = -fPIC 
vnc_mod_LDFLAGS = -fPIC
web_form_mod_LDFLAGS = -fPIC
wrapper_mod_LDFLAGS = -fPIC

LDADD = @MODULE_LIBS@

noinst_HEADERS = module.h d3des.h sha1.h hmacmd5.h http-digest.h ntlm.h
EXTRA_DIST = wrapper/*.pl
