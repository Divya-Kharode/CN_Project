import requests
import threading
import random

def req(r, f):
	url = "http://localhost:9000/" + f
	if r == "GET":
		x = requests.get(url)
	elif r == "POST":
		x = requests.post(url)
	elif r == "HEAD":
		x = requests.head(url)
	elif r == "DELETE":
		x = requests.delete(url)
	elif r == "PUT":
		x = requests.put(url, data ={'key':'value'}) 

	#print("\n" + str(i)+" : " + str(x) + " ------> " + r + " /" + f + "/" + str(x.headers) + "\n" )
	print(r + " /" +f + " " +str(x))
	for i in x.headers:
		print(i + ": " + x.headers[i])
	print("\n")

def req_h(f):
	url = "http://localhost:9000/" + f
	header = {"Range": "bytes=0-100"}
	x = requests.get(url, headers=header)
	print(x)
	for i in x.headers:
		print(i + ": " + x.headers[i])
	print("\n")
	assert len(x.text) <= 101 
	

count = 0
request = ["HEAD", "GET", "POST"]
files = ["data.txt", "data.html", "xyz.xml", "video2.mp4", "music.mp3", "doc.pdf", "data.csv", "images.jpg", "lec.ppt", "a.zip"]

file_not = ["d.jpg", "in.html", "video.mp4", "hello.ppt", "hj.pdf"]


#---------------------------------------------------------
#200 OK 
#Single Get Request for all file format

for file in files:
	req("GET", file)

#Single Head Request for all file format
for file in files:
	req("HEAD", file)

#single post request for all file format
for file in files:	
	req("POST", file)

#delete request for file
req("DELETE", "a.txt") 
	
#put request for file
req("PUT", "a.txt")


#---------------------------------------------------------
#Checking File Not Found header
#404 Not found

#Single Get file not found Request for all file format

for file in file_not:
	req("GET", file)

#Single Head file not found Request for all file format
for file in file_not:
	req("HEAD", file)

#single post file not found request for all file format
for file in file_not:	
	req("POST", file)

#delete request file not found for file
req("DELETE", "ahj.txt") 


#---------------------------------------------------------
#Checking Permission denied i.e,403 Forbidden

file = "abbbc.txt"                        #file name for which to read write execute permission granted

#Single Get Permission denied  Request 
req("GET", file)

#Single Head Permission denied  Request 
req("HEAD", file)

#single post Permission denied  request
req("POST", file)

#delete request Permission denied  for file
req("DELETE", file) 


#-----------------------------------------------------------
#Single Get Request with range header for all file format
#It will check for 206 Partial content and 416 Not satifiable ranges

for file in files:
	req_h(file)

	
	
	
	
