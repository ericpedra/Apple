#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#By coded: Eric Pedra
import time, logging, threading , sys, pycurl, io
from urllib import error, parse, request

emailslist = []
logging.basicConfig(level=logging.DEBUG,
                      format='[%(levelname)s] %(message)s',)
                      
logging.info("Apple Email Validator")
logging.info("Contact Facebook : Eric Pedra")
logging.info("Gunakan dengan bijaksana ")
logging.info("Bermasalah dengan code, contact!\n")
try:
	textfile = sys.argv[1]
	loglive = open('live.txt','a')
except Exception as Err:
	logging.info(f"File List Not Found! ,using {sys.argv[0]} list.txt")
	sys.exit()
	
with open(textfile , "r") as f:
	emails = f.readlines()
    
for email in emails:
	email = email.rstrip('\n')
	emailslist.append(email)
total = len(emails)

def Totals():
	logging.info(f"Mailist found : {total}")
	logging.debug('Starting valid...')
	

def main(kontol):
	live = "Access denied. Your account does not have permission to access this application."
	locked = "This Apple ID has been locked for security reasons."
	invalid = 'password was entered incorrectly.'
	url = "https://idmsac.apple.com/authenticate"
	data = { 'accountPassword': 'xxxxxx', 'appleId': kontol, 'appIdKey': 'b620e4e967223e666348ace19c4c710e973a63da2e3d03eef6f2b436a6148c43'}
	data = parse.urlencode(data)
	headers = [("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"), ("Accept-Encoding: gzip, deflate, br"), ("Accept-Language: en-US,en;q=0.9"), ("Cache-Control: max-age=0"), ("Connection: keep-alive"), ("Content-Type: application/x-www-form-urlencoded"), ("Upgrade-Insecure-Requests: 1")]
	curl = pycurl.Curl()
	curl.setopt(pycurl.URL, url)
	curl.setopt(pycurl.FOLLOWLOCATION, 1)
	curl.setopt(pycurl.HTTPHEADER, headers)
	curl.setopt(pycurl.SSL_VERIFYPEER, 0)
	curl.setopt(pycurl.SSL_VERIFYHOST, 0)
	curl.setopt(pycurl.ENCODING, "gzip")
	curl.setopt(pycurl.POSTFIELDS, data)
	curl.setopt(pycurl.POST, 1)
	b = io.BytesIO()
	curl.setopt(pycurl.WRITEFUNCTION, b.write)
	try:
		curl.perform()
		response_string = b.getvalue().decode('iso-8859-1')
		if live in response_string:
			print(f"LIVE : {kontol}")
			loglive.write(email+"\n")
		elif invalid in response_string:
			print(f"DEAD : {kontol}")
		elif locked in response_string:
			print(f"LOCKED : {kontol}")
	except Exception as e:
		print(e)
	
def mantap():
	for em in emailslist:
		threads = []
		# Parallel Multithreading The Easy way using threading module
		t = threading.Thread(target=main, args=(em,))
		threads.append(t)
		t.start()
		t.join()
		time.sleep(1)
		
if __name__ == "__main__":
	Totals()
	mantap()
	
