#!/usr/bin/env python
import xmlrpclib,subprocess, urllib, tarfile,os,sys, socket
from SimpleXMLRPCServer import SimpleXMLRPCServer


def download_file ( url ):
	file = url.split( "/" )
	dir_name, bla = file[5].split(".tar")
	path = "/root/"
	(file_name, header) = urllib.urlretrieve(url)
	tar = tarfile.open(file_name)
	tar.extractall(path=path)
	tar.close()
	return dir_name

def configure( dir_path):
	os.chdir("/root/" + dir_path)
	#configure = subprocess.Popen( "./configure --enable-module-afp 2>&1",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	configure = subprocess.Popen( "./configure 2>&1",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	configure_messages = configure.read().split('\n')
	return configure_messages

def make_medusa():
	make = subprocess.Popen("export LC_CTYPE=C && make", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	make_messages = make.read().split('\n')
	return make_messages
	
def install_medusa():
	make_install = subprocess.Popen("export LC_CTYPE=C && make install", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	make_install_messages = make_install.read().split('\n')
	return make_install_messages
	
def cleanup_install_files():
	os.chdir("/root/")
	os.system("rm -rf /root/medusa-*")
	message = "done"
	return message

def medusa_module_test():
	medusa_module_test = subprocess.Popen("/usr/local/bin/medusa -d",  shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	medusa_module_test = medusa_module_test.read().split('\n')
	return medusa_module_test
	
	
def run_medusa_tests(service,target_host, usernames, passwords, options):
	medusa_test_output = subprocess.Popen("/usr/local/bin/medusa -M " + service + " -h " + target_host + " -e ns -u " + usernames + " -p '" + passwords + "' " + options ,  shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,).stdout
	medusa_output_data = medusa_test_output.read().strip('\n')
	return medusa_output_data


def main():
	print "Agent has started\n"
	server  = SimpleXMLRPCServer(('0.0.0.0', 31137))
	server.register_function (download_file, "download_file")
	server.register_function (configure, "configure")
	server.register_function (make_medusa,"make_medusa")
	server.register_function (install_medusa, "install_medusa")
	server.register_function (cleanup_install_files, "cleanup_install_files")
	server.register_function (medusa_module_test,"medusa_module_test")
	server.register_function (run_medusa_tests, "run_medusa_tests")
	server.serve_forever()


if __name__ == "__main__":
	try:
		main()
		sys.exit(0)
	except KeyboardInterrupt:
		print "\nEnding program. Have a nice day"
		sys.exit(1)
	
