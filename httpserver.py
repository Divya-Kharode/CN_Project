#!/usr/bin/python
from socket import *
from datetime import datetime
import threading
import time
import sys
import os.path
from os import path
import os
import shutil
import re
import random
import hashlib
import base64
from pymemcache.client import base


byte_ext = [".mp3", ".jpeg", ".jpg", ".png", ".mp4", ".pdf", ".ppt", ".zip"]
day_name= ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday','Sunday']

lock = threading.Lock()

def error_log(p, ip, f, c):
	global EL
	pid = os.getpid()
	tid = threading.get_ident()
	now = datetime.now()
	dt = "[" + now.strftime("%a ") + now.strftime("%b %d ")+ now.strftime("%H:%M:%S:%f") +now.strftime(" %Y") + "]"
	if c == "404":
		e_log = dt + " " + "[core:info]  [pid " + str(pid) + ":tid " + str(tid) + "] [client " + ip + ": " + p + "] AH00128: File does not exist: " + f+"\n"
	elif c == "200" or c == "201":
		e_log = dt + " " + "[authz_core:debug]  [pid " + str(pid) + ":tid " + str(tid) + "] "+ "mod_authz_core.c(817):" +" [client " + ip + ": " + p + "]  AH01626: authorization result of Require all granted: granted\n"
	elif c == "403":
		e_log = dt + " " + "[core:error]  [pid " + str(pid) + ":tid " + str(tid) + "] (13)Permission denied: [client " + ip + ": " + p + "]  AH00132: file permissions deny server access: "+ f + "\n"
			
	if path.exists(EL):
		log_file = open(EL, 'a')
		log_file.write(e_log)
		log_file.close()
	else:
		log_file = open(EL, 'w')
		log_file.write(e_log)
		log_file.close()    


def parse_cookie(c):
	i = c.find("=")
	key = c[:i]
	value = c[i+1:]
	value1 = get_c(key)
	if decode_c(value) == value1.decode():
		return 1
	else:
		return 0

	
def set_c(k, v):
	client = base.Client('localhost')
	if client.set(k, v):
		return 1
	else:
		return 0

def get_c(k):
	client = base.Client('localhost')
	k = decode_c(k)
	return(client.get(k))

def decode_c(message):
	base64_bytes = message.encode('ascii')
	message_bytes = base64.b64decode(base64_bytes)
	message = message_bytes.decode('ascii')

	return message

def encode_c(message):
	message_bytes = message.encode('ascii')
	base64_bytes = base64.b64encode(message_bytes)
	base64_message = base64_bytes.decode('ascii')

	return base64_message
	
def find_date(rq_d):
	for i in rq_d:
		if i.find("If-Modified-Since: ") != -1:
			mdate = i.split(": ")
			m = mdate[1]
			return m			
def rangeh(rq):
	rq = rq.split("=")
	ran = rq[1]
	ran = ran.split(",")
	lis = []
	for i in ran:
		s = i.split("-")
		lis.append(s)
	return lis
	
def forbidden(request, header, ip_address, token):
	global AL
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	data = "HTTP/1.1 403 Forbidden\r\n"
	st_code = "403"
	now = datetime.now()
	data += "Content-Type: text/html\r\n"
	data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
	data += "\r\n"
	text = open("error/403_forbidden.html")
	bytes = text.read()
	size = len(bytes)
	if token == 1:
		data += bytes
	access_log(request, ip_address, header, st_code, size)
	return data
	
def not_found(request, header, ip_address, token):
	global AL
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	data = "HTTP/1.1 404 Not Found\r\n"
	now = datetime.now()
	st_code = "404"
	data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
	data += "Server: 127.0.0.1\r\n"
	data += "Content-Type: text/html\r\n"
	data += "Connection: close\r\n"
	data += "\r\n"
	text = open("error/404_not_found.html")
	bytes = text.read()
	size = len(bytes)
	if token == 1:
		data += bytes
	access_log(request, ip_address, header, st_code, size)
	return data
	
def not_modified(request, header, ip_address):
	global AL
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	data = "HTTP/1.1 304 Not Modified\r\n"
	st_code = "304"
	now = datetime.now()
	data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
	data += "Server: 127.0.0.1\r\n"
	data += "Content-Type: text/html\r\n"
	data += "Connection: close\r\n"
	now = datetime.now()
	date =now.strftime("%d/%b/%Y:%H:%M:%S ") + "+0530"
	date = "["+ date +"]"
	if "User-Agent:" in request:
		agent = request[request.index("User-Agent:")+1]
	else:
		agent = ""
	header = "\"" + header +"\""
	agent = "\"" + agent +"\""
	url =  "\"" + url + "\""
	log = ip_address + ":"+ " - - " + date + " " + header + " " + str(st_code)+ " " + "0"+ " " + url+ " " + agent+"\n"
	if path.exists(AL):
		log_file = open(AL, 'a')
		log_file.write(log)
		log_file.close()
	else:
		log_file = open(AL, 'w')
		log_file.write(log)
		log_file.close()
	data += "\r\n"
	return data


def not_satisfy(request, header, ip_address, s):
	global AL
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	data = "HTTP/1.1 416 Range Not Satisfiable\r\n"
	st_code = "416"
	now = datetime.now()
	data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
	data += "Content-Range: bytes */" + str(s) + "\n"
	data += "Connection: close\r\n"
	now = datetime.now()
	date =now.strftime("%d/%b/%Y:%H:%M:%S ") + "+0530"
	date = "["+ date +"]"
	if "User-Agent:" in request:
		agent = request[request.index("User-Agent:")+1]
	else:
		agent = ""
	header = "\"" + header +"\""
	agent = "\"" + agent +"\""
	url =  "\"" + url + "\""
	log = ip_address + ":"+ " - - " + date + " " + header + " " + str(st_code)+ " " + "0" + " " + url+ " " + agent+"\n"	
	if path.exists(AL):
		log_file = open(AL, 'a')
		log_file.write(log)
		log_file.close()
	else:
		log_file = open(AL, 'w')
		log_file.write(log)
		log_file.close()
		data += "\r\n"	
	print(data)
	return data
	
def access_log(request, ip_address, header, st_code, size):
	global AL
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	now = datetime.now()
	date =now.strftime("%d/%b/%Y:%H:%M:%S ") + "+0530"
	date = "["+ date +"]"
	if "User-Agent:" in request:
		agent = request[request.index("User-Agent:")+1]
	else:
		agent = ""
	header = "\"" + header +"\""
	agent = "\"" + agent +"\""
	url =  "\"" + url + "\""
	log = ip_address + ":"+ " - - " + date + " " + header + " " + str(st_code)+ " " + str(size)+ " " + url+ " " + agent+"\n"
	if path.exists(AL):
		log_file = open(AL, 'a')
		log_file.write(log)
		log_file.close()
	else:
		log_file = open(AL, 'w')
		log_file.write(log)
		log_file.close()


def execute(clientsocket):
	global connection_list
	while(1):
		try:
			rd = clientsocket.recv(5000).decode()
			request = rd.split()
			print(rd)
			rq_d = rd.split("\n")
			rq_header = rd.split('\n')[0]	
			rq_header = rq_header[:-1]
			if(len(request)> 0):
				if  request[0] == "GET":
					get_request(clientsocket, request, rq_header, rq_d)
				elif  request[0] == "PUT":
					output1 = list(rd.split('\r\n\r\n'))[-1]
					put_request(clientsocket, request, output1, rq_header)
				elif request[0] == "POST":
					post_request(clientsocket, request, rq_header)
				elif request[0] == "DELETE":
					delete_request(clientsocket, request, rq_header)
				elif request[0] == "HEAD":
					head_request(clientsocket, request, rq_header, rq_d)					
			else:
				clientsocket.close()
				break
			clientsocket.close()
		except:
			continue


#GET REQUEST
#---------------
def get_request(client, request, header, rq_d):
	global DocumentRoot
	global AL
	name, ext = os.path.splitext(request[1][1:])
	file_name = DocumentRoot+ "/" +request[1][1:]	
	fname =  "/" +request[1][1:]	
	st_code = -1
	length = 0
	add = str(client).split("raddr=(")[-1]
	ip_address = add.split(",")[0]
	pt = add.split(",")[1][1:-2]
	start = '\''
	end = '\''
	ip_address = (ip_address.split(start))[1].split(end)[0]
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	start = -1
	end = -1
	flag = 1
	if request[1][1:] == "":
		data = "HTTP/1.1 200 OK\r\n"
		now = datetime.now()
		st_code = "200"
		error_log(pt, ip_address, fname, "200")
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Server: 127.0.0.1\r\n"
		data += "Content-Type: text/html\r\n"
		data += "Connection: close\r\n"
		data += "\r\n"
		text = open(DocumentRoot+ "/"+ "index.html")
		byte = text.read()
		size = len(byte)
		data += byte
		access_log(request, ip_address, header, st_code, size)
		client.sendall(data.encode())
		client.close()
		
	if path.exists(file_name):
		if os.access(file_name, os.R_OK):
			if ext == ".html" or ext == ".htm":
				ct = "text/html"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".jpeg" or ext == ".jpg" or ext == ".png":
				ct = "image/jpg"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".xml":
				ct = "text/xml"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".mp3":
				ct = "audio/mp3"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".mp4":
				ct = "video/mp4"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".txt":
				ct = "text/plain"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".csv":
				ct = "text/csv"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".pdf":
				ct = "application/pdf"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".zip":
				ct = "application/zip"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".ppt" or ext == ".pptx":
				ct = "application/vnd.ms-powerpoint"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			
			#For Range: Header
			if ext in byte_ext:
				cont = bytearray()
			else:
				cont = ""
			if "Range:" in request:
				i = request.index("Range:")
				range = request[i+1]
				rn = rangeh(range)
				for r in rn:
					start = r[0]
					end = r[1]
					if start == "" or start == "\r":
						start = -1
					else:
						start = int(start)
					if end == "" or end == "\r":
						end = -1
					else:
						end = int(end)
					if start != -1 and end != -1:
						if ext in byte_ext:
							cont = cont + byte[start:end]
						else:
							cont += byte[start:end] + "\n"
					elif start != -1 and end == -1:
						if ext in byte_ext:
							cont = cont + byte[start:]
						else:
							cont += byte[start:] + "\n"
					elif end != -1 and start == -1:
						if ext in byte_ext:
							cont = cont + byte[:end]
						else:
							cont += byte[:end] + "\n"
					if start >= -1 and end <= size and start <= size and end >= -1:
						flag = 1
					else:
						flag = 0 
						break
			else:
				cont = byte
			dat = str(cont)
			result = hashlib.md5(bytes(dat,'utf-8'))
			result = result.digest()
			result = bytes(result)
			md5 = base64.b64encode(result)
			md5 = md5.decode('utf-8')
			string = "Content-md5 : " + md5 + "\r\n"
			if flag == 0:
				data = not_satisfy(request, header, ip_address, size)
				client.sendall(data.encode())
				client.close()
				
			modTimesinceEpoc = os.path.getmtime(file_name)
			# Convert seconds since epoch to readable timestamp
			modificationTime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(modTimesinceEpoc))
			if "If-Modified-Since:" in request:
				mdate = str(find_date(rq_d))
				if str(mdate).strip() != str(modificationTime).strip():
					if len(cont) == size:
						data = "HTTP/1.1 200 OK\r\n"
						st_code = "200"
					else:
						data = "HTTP/1.1 206 Partial Content\r\n"
						st_code = "206"
					error_log(pt, ip_address, fname, "200")
					now = datetime.now()
					data += "Date: " +  now.strftime("%a") + ", " +  now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"	
					data += "Server: 127.0.0.1\r\n"
					data += "Last-Modified: " + modificationTime + "\r\n"
					data += "Content-Length: " + str(len(cont)) + "\r\n"
					data += "Content-Type:"+ ct +"\r\n"
					data += string
					if "Cookie:" not in request:
						key = ip_address
						value = ip_address + "-" + str(random.randint(1, 10000))
						k = encode_c(key)
						v = encode_c(value)
						if set_c(key, value):
							data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n" 
					else:
						i = request.index("Cookie:")
						cookies = request[i+1]
						b = parse_cookie(cookies)
						if b == 0:
							key = ip_address
							value = ip_address + "-" + str(random.randint(1, 10000))
							k = encode_c(key)
							v = encode_c(value)
							if set_c(key, value):
								data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n"
					data += "Connection: close\r\n"	
					data += "\r\n" 	 
					access_log(request, ip_address, header, st_code, len(cont))
					if ext in byte_ext:
						client.sendall(data.encode())
						client.send(cont)
					else:
						data += cont
						client.sendall(data.encode())
					client.close()
				else:
					data = not_modified(request, header, ip_address)
					client.sendall(data.encode())
					client.close()
					
			else:
				modTimesinceEpoc = os.path.getmtime(file_name)
				# Convert seconds since epoch to readable timestamp
				modificationTime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(modTimesinceEpoc))
				if len(cont) == size:
					data = "HTTP/1.1 200 OK\r\n"
					st_code = "200"
				else:
					data = "HTTP/1.1 206 Partial Content\r\n"
					st_code = "206"
				error_log(pt, ip_address, fname, "200")
				now = datetime.now()
				data += "Date: " +  now.strftime("%a") + ", " +  now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"	
				data += "Server: 127.0.0.1\r\n"
				data += "Last-Modified: " + modificationTime + "\r\n"
				data += "Content-Length: " + str(len(cont)) + "\r\n"
				data += "Content-Type:"+ ct +"\r\n"
				data += string
				if "Cookie:" not in request:
					key = ip_address
					value = ip_address + "-" + str(random.randint(1, 10000))
					k = encode_c(key)
					v = encode_c(value)
					if set_c(key, value):
						data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n" 
				else:
					i = request.index("Cookie:")
					cookies = request[i+1]
					b = parse_cookie(cookies)
					if b == 0:
						key = ip_address
						value = ip_address + "-" + str(random.randint(1, 10000))
						k = encode_c(key)
						v = encode_c(value)
						if set_c(key, value):
							data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n"
				data += "Connection: close\r\n"	
				data += "\r\n" 	 
				access_log(request, ip_address, header, st_code, len(cont))
				if ext in byte_ext:
					client.sendall(data.encode())
					client.send(cont)
				else:
					data += cont
					client.sendall(data.encode())
				client.close()
		else:
			data = forbidden(request, header, ip_address, 1)
			error_log(pt, ip_address, fname, "403")
			client.sendall(data.encode())
			client.close()
			
	else:
		data = not_found(request, header, ip_address, 1)
		error_log(pt, ip_address, fname, "404")
		client.sendall(data.encode())
		client.close()
			
	


#HEAD_REQUEST
#-----------------
def head_request(client, request, header, rq_d):
	global DocumentRoot
	global AL
	name, ext = os.path.splitext(request[1][1:])
	file_name = DocumentRoot+ "/" +request[1][1:]	
	fname =  "/" +request[1][1:]	
	st_code = -1
	length = 0
	add = str(client).split("raddr=(")[-1]
	ip_address = add.split(",")[0]
	pt = add.split(",")[1][1:-2]
	start = '\''
	end = '\''
	ip_address = (ip_address.split(start))[1].split(end)[0]
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	start = -1
	end = -1
	flag = 1
	if request[1][1:] == "":
		data = "HTTP/1.1 200 OK\r\n"
		now = datetime.now()
		st_code = "200"
		error_log(pt, ip_address, fname, "200")
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Server: 127.0.0.1\r\n"
		data += "Content-Type: text/html\r\n"
		data += "Connection: close\r\n"
		data += "\r\n"
		text = open(DocumentRoot+ "/"+ "index.html")
		byte = text.read()
		size = len(byte)
		access_log(request, ip_address, header, st_code, size)
		client.sendall(data.encode())
		client.close()
		
	if path.exists(file_name):
		if os.access(file_name, os.R_OK):
			if ext == ".html" or ext == ".htm":
				ct = "text/html"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".jpeg" or ext == ".jpg" or ext == ".png":
				ct = "image/jpg"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".xml":
				ct = "text/xml"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".mp3":
				ct = "audio/mp3"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".mp4":
				ct = "video/mp4"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".txt":
				ct = "text/plain"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".csv":
				ct = "text/csv"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".pdf":
				ct = "application/pdf"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".zip":
				ct = "application/zip"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".ppt" or ext == ".pptx":
				ct = "application/application/vnd.ms-powerpoint"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			
			modTimesinceEpoc = os.path.getmtime(file_name)
			# Convert seconds since epoch to readable timestamp
			modificationTime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(modTimesinceEpoc))
			if "If-Modified-Since:" in request:
				mdate = find_date(rq_d)
				if str(mdate).strip() != str(modificationTime).strip():
					data = "HTTP/1.1 200 OK\r\n"
					st_code = "200"
					error_log(pt, ip_address, fname, "200")
					now = datetime.now()
					data += "Date: " +  now.strftime("%a") + ", " +  now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"	
					data += "Server: 127.0.0.1\r\n"
					data += "Last-Modified: " + modificationTime + "\r\n"
					data += "Content-Length: " + str(size) + "\r\n"
					data += "Content-Type:"+ ct +"\r\n"
					if "Cookie:" not in request:
						#print("ff")
						key = ip_address
						value = ip_address + "-" + str(random.randint(1, 10000))
						k = encode_c(key)
						v = encode_c(value)
						if set_c(key, value):
							data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n" 
					else:
						i = request.index("Cookie:")
						cookies = request[i+1]
						#print(cookies)
						b = parse_cookie(cookies)
						if b == 0:
							key = ip_address
							value = ip_address + "-" + str(random.randint(1, 10000))
							k = encode_c(key)
							v = encode_c(value)
							if set_c(key, value):
								data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n"
					data += "Connection: close\r\n"	
					data += "\r\n" 	 
					access_log(request, ip_address, header, st_code, size)
					if ext in byte_ext:
						client.sendall(data.encode())
						#client.send(byte)
					else:
						#data += byte
						client.sendall(data.encode())
					client.close()
				else:
					data = not_modified(request, header, ip_address)
					client.sendall(data.encode())
					client.close()
					
			else:
				modTimesinceEpoc = os.path.getmtime(file_name)
				# Convert seconds since epoch to readable timestamp
				modificationTime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(modTimesinceEpoc))
				data = "HTTP/1.1 200 OK\r\n"
				st_code = "200"
				error_log(pt, ip_address, fname, "200")
				now = datetime.now()
				data += "Date: " +  now.strftime("%a") + ", " +  now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"	
				data += "Server: 127.0.0.1\r\n"
				data += "Last-Modified: " + modificationTime + "\r\n"
				data += "Content-Length: " + str(size) + "\r\n"
				data += "Content-Type:"+ ct +"\r\n"
				if "Cookie:" not in request:
					#print("ff")
					key = ip_address
					value = ip_address + "-" + str(random.randint(1, 10000))
					k = encode_c(key)
					v = encode_c(value)
					if set_c(key, value):
						data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n" 
				else:
					i = request.index("Cookie:")
					cookies = request[i+1]
					#print(cookies)
					b = parse_cookie(cookies)
					if b == 0:
						key = ip_address
						value = ip_address + "-" + str(random.randint(1, 10000))
						k = encode_c(key)
						v = encode_c(value)
						if set_c(key, value):
							data += "Set-Cookie: "+ str(k) + "=" + str(v) + "\r\n"
				data += "Connection: close\r\n"	
				data += "\r\n" 	 
				access_log(request, ip_address, header, st_code, size)
				if ext in byte_ext:
					client.sendall(data.encode())
					#client.send(byte)
				else:
					#data += byte
					client.sendall(data.encode())
				client.close()
		else:
			data = forbidden(request, header, ip_address, 0)
			error_log(pt, ip_address, fname, "403")
			client.sendall(data.encode())
			client.close()
			
	else:
		data = not_found(request, header, ip_address, 0)
		error_log(pt, ip_address, fname, "404")
		client.sendall(data.encode())
		client.close()
		
#DELETE REQUEST
#-----------------

def delete_request(client, request, header):
	global DocumentRoot
	global AL
	st_code = -1
	fname =  "/" +request[1][1:]	
	size = 0
	length = 0
	add = str(client).split("raddr=(")[-1]
	ip_address = add.split(",")[0]
	pt = add.split(",")[1][1:-2]
	start = '\''
	end = '\''
	ip_address = (ip_address.split(start))[1].split(end)[0]
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	if len(request[1]) > 1:
		#print(request[1])
		if os.access(DocumentRoot+ "/" +request[1][1:], os.F_OK):
			if os.access(DocumentRoot+ "/" +request[1][1:], os.W_OK) and os.access(DocumentRoot+"/"+request[1][1:], os.X_OK):
				name, ext = os.path.splitext(request[1][1:])
				if ext == ".html" or ext == ".htm":
					ct = "text/html"
				elif ext == ".jpeg" or ext == ".jpg" or ext == ".png":
					ct = "image/jpg"
				elif ext == ".xml":
					ct = "text/xml"
				elif ext == ".mp3":
					ct = "audio/mp3"
				elif ext == ".mp4":
					ct = "video/mp4"
				elif ext == ".txt":
					ct = "text/txt"
				elif ext == ".zip":
					ct = "application/zip"
				elif ext == ".pdf":
					ct = "application/pdf"
				elif ext == ".ppt" or ext == ".pptx":
					ct = "application/application/vnd.ms-powerpoint"
				os.remove(DocumentRoot+ "/" +request[1][1:])
				data = "HTTP/1.1 200 OK \r\n"
				st_code = "200"
				error_log(pt, ip_address, fname, "200")
				data += "Connection: close\r\n"
				now = datetime.now()
				data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
				data += "Content-Type: text/html\r\n"
				access_log(request, ip_address, header, st_code, size)
				data += "\r\n"
				text = open("error/200_delete.html")
				data += text.read()
				client.sendall(data.encode())
			else:
				data = forbidden(request, header, ip_address, 1)
				error_log(pt, ip_address, fname, "403")
				client.sendall(data.encode())
				client.close()
		else:
			data = not_found(request, header, ip_address, 1)
			error_log(pt, ip_address, fname, "404")
			client.sendall(data.encode())
			client.close()
	else:
		data = "HTTP/1.1 400 Bad Request\r\n"
		st_code = "400"
		now = datetime.now()
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Server: 127.0.0.1\r\n"
		data += "Content-Type: text/html\r\n"
		data += "Connection: close\r\n"
		now = datetime.now()
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Content-Type: text/html\r\n"
		access_log(request, ip_address, header, st_code, size)
		data += "\r\n"
		text = open("error/400_bad_request.html")
		byte = text.read()
		size = len(byte)
		data += byte
		client.sendall(data.encode())
	client.close()


#PUT REQUEST
#---------------

def put_request(client, request, content, header):
	global DocumentRoot
	global AL
	fname =  "/" +request[1][1:]	
	st_code = -1
	size = 0
	length = 0
	add = str(client).split("raddr=(")[-1]
	ip_address = add.split(",")[0]
	pt = add.split(",")[1][1:-2]
	start = '\''
	end = '\''
	ip_address = (ip_address.split(start))[1].split(end)[0]
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	file_name = DocumentRoot+ "/" +request[1][1:]
	if len(request[1]) > 1:
		if len(content) != 0:
			if path.exists(file_name):
				if os.access(DocumentRoot+ "/" +request[1][1:], os.W_OK):
					f = open(file_name, "w")
					f.write(content)
					f.close()
					size = len(content)
					data = "HTTP/1.1 200 OK\r\n"
					error_log(pt, ip_address, fname, "200")
					st_code = "200"
					now = datetime.now()
					data += now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
					data += "Content-Location: {}\r\n".format(DocumentRoot+request[1])
					data += "Content-Type: text/html\r\n"
					data += "Connection: close\r\n"
					now = datetime.now()
					data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
					access_log(request, ip_address, header, st_code, size)
					data += "\r\n"
					f = open("error/200_OK.html")
					data += f.read()
					client.sendall(data.encode())
				else:
					data = forbidden(request, header, ip_address, 1)
					error_log(pt, ip_address, fname, "403")
					client.sendall(data.encode())
					client.close()
				
			else:
				f = open(file_name, "w")
				f.write(content)
				f.close()
				size = len(content)
				data = "HTTP/1.1 201 Created\r\n"
				error_log(pt, ip_address, fname, "201")
				st_code = "201"
				now = datetime.now()
				data += now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
				data += "Content-Location: {}\r\n".format(DocumentRoot+request[1])
				data += "Content-Type: text/html\r\n"
				data += "Connection: close\r\n"
				now = datetime.now()
				data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
				access_log(request, ip_address, header, st_code, size)
				data += "\r\n"
				f = open("error/201.html")
				data += f.read()
				client.sendall(data.encode())
		else:
			data = "HTTP/1.1 204 No Content \r\n"
			st_code = "204"
			data += "Connection: close\r\n"
			now = datetime.now()
			access_log(request, ip_address, header, st_code, size)
			data += "\r\n"
			'''text = open("error/204.html")
			data += text.read()'''
			client.sendall(data.encode())	
	else:
		data = "HTTP/1.1 400 Bad Request\r\n"
		st_code = "400"
		now = datetime.now()
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Server: 127.0.0.1\r\n"
		data += "Content-Type: text/html\r\n"
		data += "Connection: close\r\n"
		text = open("error/400_bad_request.html")
		byte = text.read()
		size = len(byte)
		access_log(request, ip_address, header, st_code, size)
		data += "\r\n"
		data += byte
		client.sendall(data.encode())
	client.close()		


#POST REQUEST
#---------------
		
def post_request(client, request, header):
	name, ext = os.path.splitext(request[1][1:])
	file_name = DocumentRoot+ "/" +request[1][1:]
	fname =  "/" +request[1][1:]	
	st_code = -1
	length = 0
	add = str(client).split("raddr=(")[-1]
	ip_address = add.split(",")[0]
	pt = add.split(",")[1][1:-2]
	start = '\''
	end = '\''
	ip_address = (ip_address.split(start))[1].split(end)[0]
	if "Referer:" in request:
		i = request.index("Referer:")
		url = request[i+1]
	else:
		url = ""
	if request[1][1:] == "":
		data = "HTTP/1.1 200 OK\r\n"
		now = datetime.now()
		st_code = "200"
		error_log(pt, ip_address, fname, "200")
		data += "Date: " + now.strftime("%a") + ", " + now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"
		data += "Server: 127.0.0.1\r\n"
		data += "Content-Type: text/html\r\n"
		data += "Connection: close\r\n"
		data += "\r\n"
		text = open(DocumentRoot+ "/"+ "index.html")
		byte = text.read()
		size = len(byte)
		data += byte
		access_log(request, ip_address, header, st_code, size)
		client.sendall(data.encode())
		client.close()
		
	if path.exists(file_name):
		if os.access(file_name, os.R_OK):
			modTimesinceEpoc = os.path.getmtime(file_name)
			# Convert seconds since epoch to readable timestamp
			modificationTime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(modTimesinceEpoc))
			if ext == ".html" or ext == ".htm":
				ct = "text/html"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".jpeg" or ext == ".jpg" or ext == ".png":
				ct = "image/jpg"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".xml":
				ct = "text/xml"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".mp3":
				ct = "audio/mp3"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".mp4":
				ct = "video/mp4"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".txt":
				ct = "text/plain"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".csv":
				ct = "text/csv"
				text = open(file_name)
				byte = text.read()
				size = len(byte)
			elif ext == ".pdf":
				ct = "application/pdf"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".zip":
				ct = "application/zip"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
			elif ext == ".ppt" or ext == ".pptx":
				ct = "application/application/vnd.ms-powerpoint"
				image = open(file_name, 'rb')
				byte = image.read()
				size = len(byte)
				
			dat = str(byte)
			result = hashlib.md5(bytes(dat,'utf-8'))
			result = result.digest()
			result = bytes(result)
			md5 = base64.b64encode(result)
			md5 = md5.decode('utf-8')
			string = "Content-md5 : " + md5 + "\r\n"
			
			data = "HTTP/1.1 200 OK\r\n"
			st_code = "200"
			now = datetime.now()
			error_log(pt, ip_address, fname, "200")
			data += "Date: " +  now.strftime("%a") + ", " +  now.strftime("%d %b %Y ") + now.strftime("%H:%M:%S") + " GMT\r\n"	
			data += "Server: 127.0.0.1\r\n"
			data += "Last-Modified: " + modificationTime + "\r\n"
			data += "Content-Length: " + str(size) + "\r\n"
			data += "Content-Type:"+ ct +"\r\n"
			data += string						 
			data += "Connection: close\r\n"
			data += "\r\n"
			access_log(request, ip_address, header, st_code, size)
			if ext in byte_ext:
				client.sendall(data.encode())
				client.send(byte)
			else:
				data += byte
				client.sendall(data.encode())
			client.close()
		else:
			data = forbidden(request, header, ip_address, 1)
			error_log(pt, ip_address, fname, "403")
			client.sendall(data.encode())
			client.close()
	else:
		data = not_found(request, header, ip_address, 1)
		error_log(pt, ip_address, fname, "404")
		client.sendall(data.encode())
		client.close()

			
def config(filen):
	line = []
	with open (filen, 'rt') as myfile:
		for myline in myfile:              # For each line, read to a string,
			if myline[0] != "#":
				#print(myline)
				l = myline[:-1]
				if len(l):
					line.append(l)
	for l in line:
		ls = l.split(" ")
		if ls[0] == "DocumentRoot":
			DR = ls[1]
		elif ls[0] == "MaxSimulateneousConnections":
			Maxsc = ls[1]
		elif ls[0] == "Listen":
			Lis = ls[1]
		elif ls[0] == "AccessLog":
			AL = ls[1]
		elif ls[0] == "ErrorLog":
			EL = ls[1] 
	return DR, Maxsc, Lis, AL, EL

#create a serverSocket
serverSocket = socket(AF_INET,SOCK_STREAM)

#For Configuration of server
DocumentRoot, Maxsc, Listen, AL, EL = config("http.conf")
serverPort = int(Listen)
serverSocket.bind(('',serverPort))
serverSocket.listen(1)
#connection_list = []
client = base.Client('localhost')

print("Access http://localhost:{0}".format(serverPort))
while True:
	connectionSocket,addr = serverSocket.accept()
	#connection_list.append(connectionSocket)
	#creating a new thread for each user
	t1 = threading.Thread(target = execute,args=(connectionSocket,))
	t1.daemon = True
	t1.start()

serverSocket.close()  
	
