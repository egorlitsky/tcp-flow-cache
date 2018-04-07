#!/usr/bin/python

import threading
import time
import os
import subprocess
from datetime import datetime

exitFlag = 0

class User (threading.Thread):
   def __init__(self, user_id, username, url, count):
      threading.Thread.__init__(self)
      self.user_id  = user_id
      self.username = username
      self.url      = url
      self.count    = count 
   
   def run(self):
      print "User %s is downloading %s ..." % (self.username, self.url)
      self.download_file(self.username, self.url, self.count)
      print "User %s finished download." % self.username

   def download_file(self, username, url, count):
      while count:
         if exitFlag:
	    username.exit()
      
         cmd = "wget " + "\'" + url + "\'"
         run_cmd(cmd)
         count -= 1


urls = [
   "http://www.sustainablesites.org/sites/default/files/styles/article_format__948x375_/public/field/image/hempstead.jpg",
   "http://www.sustainablesites.org/sites/default/files/styles/article_format__948x375_/public/field/image/SITES%20%281%29.png",
   "http://sefan.ru/data/loads/video/Tecktonik/!new/obuchaem/electro-gen/electro-gen-1_wap-sefan-ru.3gp?lan=en&page=1",
   "http://slideplayer.com/3603175/13/images/20/TCP%2FIP+View+of+Encapsulation.jpg"
];

def run_cmd(cmd):
   subprocess.call(cmd, shell=True,
   stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)


users       = [];
users_count = len(urls);

for i in range(users_count):
   users.append(User(i, "%s" % i, urls[i], 2))
  
start_time = datetime.now() 

for i in range(users_count):
   users[i].start()

for i in range(users_count):
   users[i].join()

time_elapsed = datetime.now() - start_time 
print('Time elapsed (hh:mm:ss.ms) {}'.format(time_elapsed))




