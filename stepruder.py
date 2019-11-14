#!/usr/bin/python
import sys
import argparse
import re
import json
import requests
import urllib3

from http.server import BaseHTTPRequestHandler
from io import BytesIO

#cass for parsing the HTTP request from text - adapted from https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#parse payloads from config
#returns number of iterations based on minimal number of payload lists
def parse_payloads():
	#perform substitutions and do a substitution requestbulk
	if config['payloads']:
		iterations = sys.maxsize
		for key in config['payloads']:
			payloads[key] = []
			if config['payloads'][key]['type'] == 'numeric':
				#parse payloads from the given range
				for i in range(int(config['payloads'][key]['start']), int(config['payloads'][key]['end']), int(config['payloads'][key]['step'])):
					payloads[key].append(i)
			elif config['payloads'][key]['type'] == 'list':
				#parse payloads from the list
				try:
					with open(config['payloads'][key]['path'], 'r', encoding='utf-8') as payloadlist:
						line = payloadlist.readline()
						while line and line != "":
							#stripping from newlines and whitespaces before adding
							payloads[key].append(line.strip())
							line = payloadlist.readline()
				except:
					print ("Can't parse/understand payloads in config json - can't open list", config['payloads'][key1]['path'])
					sys.exit(0)
			else:
				print ("Can't parse/understand payloads in config json - unknown payload type")
				sys.exit(0)
			iterations = iterations if iterations < len(payloads[key]) else len(payloads[key])
	else:
		iterations = 0
	return iterations
		
#send signle request given the string request
def send_request(rstr, sequence_number, iteration_number):
	
	#embed payloads
	for pkey, pvalue in payloads.items():
		#print (pkey, pvalue[iteration_number])
		rstr = rstr.replace(pkey, str(pvalue[iteration_number]))
	
	#automatic request parsing
	rbytes = rstr.strip().encode('utf-8')
	try:
		request = HTTPRequest(rbytes)
	except:
		print ("Can't parse/understand HTTP requests from file")
		return
	
	#forming the url line - assuming first word is always method
	if request.requestline.split(" ")[1].startswith('http'):
		#full url is already included in the requestline
		url = request.requestline.split(" ")[1]
	else:
		#requestline is only a path + queryargs
		if sslconfig:
			url = "https://" + request.headers['host'].split(":")[0] + ":" + str(port) + request.requestline.split(" ")[1]
		else:
			url = "https://" + request.headers['host'].split(":")[0] + ":" + str(port) + request.requestline.split(" ")[1]

	if (args.verbose):
		print ('Sending {0} request {1} to {2}'.format(request.command, sequence_number, url))

	try:
		if (request.command == 'GET'):
			r = requests.get(
				url,
				headers=request.headers,
				verify=False)
		elif (request.command == 'POST'):
			#get data first, if PUT/PUSH methods are added move this out of the branching statement
			#according to RFC, we expect at least one line in the request body 
			rdata = rstr.split("\n\n")[1]
				
			r = requests.post(
				url,
				headers=request.headers, 
				data=rdata,
				verify=False)
		else:
			#other methods are easy to add
			print ("Unsupported method")
			return
	except:
			print ("Error sending request " + str(sequence_number))
			return

	#print (r.request.body)
	if (args.verbose):
		print ("Status:{0}#####Content length:{1}#####Response time:{2}#####Content:{3}".format(r.status_code, 
				len(r.content), 
				r.elapsed.total_seconds(),
				r.content))
	else:
		print ("{0}#####{1}".format(r.status_code, len(r.content)))
		
		
#send the sequence of requests given the array of string requests
def send_sequence(request_list, iteration):
	num = 0
	print ("Iteration " + str(iteration) + " - starting sequence")
	for rstr in request_list:
		num+=1
		send_request(rstr, num, iteration)
	print ("Iteration " + str(iteration) + " - sequence finished")
	
	
#MAIN FUNCTION	
# Argument parsing
parser = argparse.ArgumentParser(description='Script that parses requests file and configuration json. It applies substitutions from config file and sends the requests in order.')
parser.add_argument("requestsfile", help="Text file containing sequence of HTPP requests, each separated by separator line (default #####)")
parser.add_argument("configfile", help="JSON file containing variables substitutions and other config")
parser.add_argument("-s", "--separator", help="custom separator between requests in requestsfile")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
args = parser.parse_args()

try:
	with open(args.requestsfile, 'r') as requestsfile:
   			requestbulk = requestsfile.read()
except:
	print ("Can't open requests file", args.requests)
	sys.exit(0)

#parse config file as json
#try:
with open(args.configfile, 'r') as configfile:
	config = json.load(configfile)
		#config = configfile.read()
#except:
#	print ("Can't load json from file", args.configfile)
#	sys.exit(0)

#parse the ssl config
sslconfig = False
port = 80
if 'ssl' in config and config['ssl']:
	sslconfig = True
	port = 443
if 'port' in config:
	port = config['port']

#substitutions are perofmed once before starting the iterations
substitutions = config['substitutions']
for key, value in substitutions.items(): 
	#we can assume the format for substitution is "key: value"
	requestbulk = requestbulk.replace(key, value)

#parse the bulk and get a list of requests
if args.separator:
	request_list = re.split(args.separator, requestbulk)
else:
	request_list = re.split(r'#####', requestbulk)
	
payloads = {}
if 'payloads' in config.keys():
	iterations = parse_payloads()
else:
	iterations = 1

if (args.verbose):
	print ("Parsed: {0} substitutions and {1} injection points; payload sequence length is {2}; total requests to be sent {3}.".format(
		len(config['substitutions']), 
		len(payloads), 
		iterations,
		len(request_list)*iterations))

for i in range(0, iterations, 1):
	send_sequence(request_list, i)
	