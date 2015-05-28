#!/usr/bin/env python
import xmlrpclib, re, sys, socket
from optparse import OptionParser
from time import strftime

#static global variables 
MEDUSA_VER = "2.1_devel"
status_log = open("status.log",'a')
pattern = re.compile ('error', re.IGNORECASE)
module_pattern = re.compile('.*\.mod : .*? : version.*', re.IGNORECASE)
services_pattern = re.compile('error', re.IGNORECASE)
time = strftime("%Y-%m-%d %H:%M:%S")


#function time...wooo its function time. 
def test_medusa_modules(host):
	host_log = open(host.strip('\n'), 'a')
	module_error_flag = False
	host_log = open(host, 'a')
	host_ip = socket.gethostbyname(host)
	try:
		proxy = xmlrpclib.ServerProxy("http://" + host_ip + ":31137/")
	except socket.error:
		status_log.write("%s: Unable to connect %s.\n" %(time,host))
		return False
		
	#Test medusa modules
	try:
		module_test_data = proxy.medusa_module_test()
	except socket.error:
		status_log.write("%s: Unable to connect %s.\n" %(time,host))
		return False	
		
	for x in module_test_data:
		host_log.write( "%s: %s: Module build information:%s.\n" %(time,host,x.strip('\n')))
		#matches = module_pattern.search(str(x))
		#if matches != None:
		#	status_log.write( "%s: %s: Module failed to build:%s.\n" %(time,host,x.strip('\n')))
		#	module_error_flag = True
		
	#if not module_error_flag:
	#	host_log.write("%s: %s: Modules were complied correctly.\n" %(time, host,))

def test_medusa(host,config_file):		
	#test medusa services
	host_log = open(host.strip('\n'), 'a')
	host_log = open(host, 'a')
	
	host_ip = socket.gethostbyname(host)
	try:
		proxy = xmlrpclib.ServerProxy("http://" + host_ip + ":31137/")
	except socket.error:
		status_log.write("%s: Unable to connect %s.\n" %(time,host))
		return False
		
	tests = read_file(config_file)
	for x in tests:
		vars = x.split(':', 4)
		target_host = vars[0]
		service = vars[1]
		user_name = vars[2]
		passwd = vars[3]
		if len(vars) != 4 :
			options = vars[4]
		else:
			options = " "
		host_log.write("\n%s: Starting medusa tests for %s.\n" %(time, target_host))
		test_data = proxy.run_medusa_tests(service, target_host,user_name,passwd,options)
		matched  = services_pattern.search(test_data)
		if matched:
			host_log.write(test_data + "\n")
			status_log.write("%s: %s: Failed service test: %s on target: %s.\n" %(time,host,service,target_host))
		else:
			host_log.write(test_data + "\n")
			status_log.write("%s: %s: passed service test : %s on target host: %s.\n" %(time,host, service, target_host))
		
	return True


def install_medusa(host):
	fail_check_flag = False
	host_ip = socket.gethostbyname(host)
	try:
		proxy = xmlrpclib.ServerProxy("http://" + host_ip + ":31137/")
		file_path = proxy.download_file("http://www.foofus.net/jmk/tmp/medusa-%s.tar.gz"  %(MEDUSA_VER,))
	except socket.error:
		status_log.write("%s: Unable to connect %s\n" %(time,host,))
		return False
		
	#Open log after we make sure that we can open a connect to the remote host. 
	host_log = open(host.strip('\n'), 'a')	
	
	
	configure_log_data= proxy.configure(file_path)
	host_log.write("%s: Issuing configure:\n" %(time,))
	for x in configure_log_data:
		try:
			matches = pattern.search(str(x))
			if matches:
				status_log.write("%s: %s: Configure failed please check logs for %s.\n" %(time, host.strip('\n'),host.strip('\n')))
				host_log.write( x + "\n")
				fail_check_flag = True
			else:
				host_log.write(x + "\n")
		except UnicodeEncodeError:
                        pass

	make_log_data = proxy.make_medusa()
	host_log.write("%s: Issuing make:\n" %(time,))
	for x in make_log_data:
		try:
			matches = pattern.search(str(x))
			if matches:
				status_log.write("%s: %s: Make failed please check logs for %s.\n" %(time, host.strip('\n'),host.strip('\n')))
				host_log.write(x+ "\n")
				fail_check_flag = True
			else:
				host_log.write(x + "\n")
		except UnicodeEncodeError:
			pass

	make_install_log = proxy.install_medusa()
	host_log.write("%s: Issuing make install:\n" %(time,))
	for x in make_install_log:
		try:
			matches = pattern.search(str(x))
			if matches:
				status_log.write("%s: %s: Make install failed please check logs for %s.\n" %(time,host.strip('\n'),host.strip('\n')))
				host_log.write(x+ "\n")
				fail_check_flag = True
			else:
				host_log.write(x + "\n")
		except UnicodeEncodeError:
                        pass
		
	if not fail_check_flag:
		proxy.cleanup_install_files()
		status_log.write( "%s: %s: Passed medusa install.\n" %(time,host.strip('\n')))
		return True
	else:
		return False
	

def build_medusa(host):
	fail_check_flag = False
	host_ip = socket.gethostbyname(host)
	try:
		proxy = xmlrpclib.ServerProxy("http://" + host_ip + ":31137/")
		file_path = proxy.download_file("http://www.foofus.net/jmk/tmp/medusa-%s.tar.gz"  %(MEDUSA_VER,))
	except socket.error:
		status_log.write("%s: Unable to connect %s\n" %(time,host,))
		return False
		
	#Open log after we make sure that we can open a connect to the remote host. 
	host_log = open(host.strip('\n'), 'a')	
	
	configure_log_data= proxy.configure(file_path)
	host_log.write("%s: Issuing configure:\n" %(time,))
	for x in configure_log_data:
		try:
			matches = pattern.search(str(x))
			if matches:
				status_log.write("%s: %s: Configure failed please check logs for %s.\n" %(time, host.strip('\n'),host.strip('\n')))
				host_log.write( x + "\n")
				fail_check_flag = True
			else:
				host_log.write(x + "\n")
		except UnicodeEncodeError:
                        pass

	make_log_data = proxy.make_medusa()
	host_log.write("%s: Issuing make:\n" %(time,))
	for x in make_log_data:
		try:
			matches = pattern.search(str(x))
			if matches:
				status_log.write("%s: %s: Make failed please check logs for %s.\n" %(time, host.strip('\n'),host.strip('\n')))
				host_log.write(x+ "\n")
				fail_check_flag = True
			else:
				host_log.write(x + "\n")
		except UnicodeEncodeError:
			pass
	if not fail_check_flag:
		proxy.cleanup_install_files()
		status_log.write( "%s: %s: Passed medusa configure and build.\n" %(time,host.strip('\n')))
		return True
	else:
		return False

def read_file ( filename):
	try:
		f = open( filename, 'r')
		list = f.readlines()
		return list
	except IOError:
		print "Error: Can not read %s.\n" %(filename,)
		sys.exit(1)

def options_list(usage):
	parser = OptionParser()
	parser.add_option( "-c", "--config",dest ="config_file", help="-c/--config: Configuration file for the device you want to test medusa against\n")
	parser.add_option("-f", "--file", dest="hosts_file", help="-f/--file: File with a lists of hosts to build medusa on\n")
	parser.add_option("-H","--host", dest="host", help="-H/--host:  host to build medusa on\n")
	parser.add_option("-i", "--install", dest ="install_medusa" ,action="store_true", help= "-i/--install: used to install medusa on host\n")
	parser.add_option("-t", "--test", dest="test_medusa", action="store_true", help="-t/-test:Just run medusa tests on hosts\n")
	parser.add_option("-b", "--build", dest="build_medusa", action="store_true", help="-b/--build will download and build medusa. It will not install it.")
	(options, args) = parser.parse_args()
	config_file = options.config_file
	hosts_file = options.hosts_file
	host = options.host
	install_medusa_flag = options.install_medusa
	test_medusa_flag = options.test_medusa
	build_medusa_flag = options.build_medusa
	
	if hosts_file == None and host == None:
		print "Missing option.\nUsage: %s\n" %(usage,)
		sys.exit(1)
	elif config_file == None and test_medusa_flag == True:
		print "Missing option.\nUsage: %s\n" %(usage,)
		sys.exit(1)
	
	else:
		if hosts_file == None:
		   hosts_file = 0
		return (hosts_file,host,config_file, install_medusa_flag, test_medusa_flag, build_medusa_flag)


def main():
	usage = "-f/--file: File with a list of hosts to build medusa on\n-H/--host: Host to build medusa on\n-c/--config: Configuration file for the device you want to test medusa on\nFile format is as follows: host:service:user:pass.\n-i/--install: used to install medusa on host.\n-t/--test:Just run medusa tests on hosts.\n-b/-build will download and build medusa. It will not install it.\n"
	(hosts_file,host, config_file, install_medusa_flag, test_medusa_flag, build_medusa_flag) = options_list(usage)
		
	if hosts_file != 0:
		hosts = read_file(hosts_file)
		if install_medusa_flag and test_medusa_flag == 1:
			print "Plase wait while Medusa is installed and tested are being run.\n"
			for host in hosts:
				status = install_medusa(host.strip('\n'))
				if status:
					test_medusa_modules(host.strip('\n'))
					test_medusa(host.strip('\n'), config_file)	
		elif  install_medusa_flag == 1:
			print "Plase wait while medusa is being installed\n"
			for host in hosts:
				install_medusa(host.strip('\n'))
				test_medusa_modules(host.strip('\n'))
		elif test_medusa_flag == 1:
			print "Please wait while medusa is being tested\n"
			for host in hosts:
				test_medusa(host.strip('n'), config_file)
		elif build_medusa_flag == 1:
			print "Please wait while medusa is being build\n"
			for host in hosts:
				build_medusa(host.strip('\n'))
		else:
			print "Do you know what you are doing?\n" + usage + "\n"
			sys.exit(1)
	else: 
		if install_medusa_flag and test_medusa_flag == 1:
                	print "Plase wait while Medusa is installed and tested are being run.\n"
                        status = install_medusa(host)
                        if status:
				test_medusa_modules(host)
                        	test_medusa(host, config_file)	
        	elif  install_medusa_flag == 1:
                	print "Plase wait while medusa is being installed\n"
                        install_medusa(host)
			test_medusa_modules(host)
        	elif test_medusa_flag == 1:
                	print "Please wait while medusa is being tested\n"
                        test_medusa(host, config_file)
		elif build_medusa_flag == 1:
			build_medusa(host.strip('\n'))
		else:
		    print "Do you know what you are doing?\n" + usage + "\n"
		    sys.exit(1)

	


if __name__ == "__main__":
	try:
		main()
		print "Program completed"
	except KeyboardInterrupt:
		print "\noooo got a CTL-C from the console. Exiting. I hope next time you know what you are doing."
