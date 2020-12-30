HTTP Server Implements HTTP Protocol

* Packages Used
 -------------------------
		- datetime
		- threading
		- time
		- random
		- hashlib
		- base64
		- pymemcache
		- requests

* Packages to Download
 ----------------------------
 		
 	- Use command for downloading pymemcache
 	
 		$ pip install pymemcache
 	
 	- Use command for downloading requests
 	
 		$ pip install requests

 		


* Setup HTTP server as a service on your system
 ------------------------------------------------
 
 	 - Create a service file for the systemd as following. The file must have .service extension under /lib/systemd/system/ directory
 	
 		$ sudo vi /lib/systemd/system/httpserver.service
 		
 	 - and add the following content in it. Change locations according to your system.
 	   Change WorkingDirectory and ExecStart Locations accordingly
 	  	
 	  		[Unit]
			Description=Http Server

			[Service]
			WorkingDirectory=/home/intel123/Project/
			User = intel123
			ExecStart= /usr/bin/python3.8  /home/intel123/Project/httpserver.py

			[Install]
			WantedBy=multi-user.target

	 -  Enable Newly Added Service
	 
	 	$ sudo systemctl daemon-reload
	 	
	 	$ sudo systemctl enable httpserver.service


* For Running HTTP Server
  -------------------------------

	- Use this Command for starting server
	
		$ sudo systemctl start httpserver.service
		
		OR
		
		$ sudo service httpserver start

	- Use this Command for stopping server
		
		$ sudo systemctl stop httpserver.service
		
		OR
		
		$ sudo service httpserver stop
		


* The configuration layout for an Http web server is as follows:
 -----------------------------------------------------------------
 
/Project/
|-- http.conf
| 
|-- logs
|       |-- access.log
|       `-- error.log
|-- www
|       `-- html
|               `--*
|--Test_files
|            | -- conformance_test.py
|             `-- stress_testing.py
|--error
|       |-- *


	- *http.conf* is the main configuration file. It specifies all configuration Information like DocumentRoot,etc.
	- *logs/access.log* records all info about requests, its status code, etc.
	- *logs/error.log* records all info about requests and error.
	- *www/html* is DocumentRoot which is the directory where server-side content is located.
	- *Test_files/* is a directory where automated testing program located.
	- *error/* contains error html pages for 204, 403, 404, etc.
	- *logo/* folder contains images which are used in error pages. 


* References
 ------------------
 	- https://pypi.org/project/pymemcache/
 	- https://tecadmin.net/setup-autorun-python-script-using-systemd/


