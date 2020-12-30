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

	#print("\n" + str(i)+" : " + str(x) + " ------> " + r + " /" + f + "/" + str(x.headers) + "\n" )
	print(r + " /"+ f+ " "+str(x))
	for i in x.headers:
		print(i + ": " + x.headers[i])
	print("\n")


count = 0
request = ["HEAD", "GET", "POST"]
files = ["data.txt", "data.html", "xyz.xml", "video2.mp4", "music.mp3", "doc.pdf", "data.csv", "images.jpg", "lec.ppt", "a.zip"]


while count <= 100:
	count = count + 1
	file = random.choice(files)
	reqst = random.choice(request)
	t1 = threading.Thread(target = req,args=(reqst,file, ))
	t1.start()	

