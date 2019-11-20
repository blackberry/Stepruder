#!/usr/bin/python
import sys
import argparse
import re
import json
import requests
import urllib3

from collections import defaultdict
from http.server import BaseHTTPRequestHandler
from io import BytesIO

#cass for parsing the HTTP request from text - adapted from https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class ParsedHTTPRequest(BaseHTTPRequestHandler):
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
#returns number of iterations based on minimal size of payload lists
def parse_payloads():
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

#parse the response and retrieve the value based on json key
#if multiple values appear the behavior is undefined
def retrieve_responsevar_json(resp, json_exp):
	try:
		respdict = json.loads(resp.content)	#json parse just the body of the response
		value = respdict[json_exp]	#TODO: what happens if 2 duplicate keys present? Python dictionary does not support duplicate keys BTW
		return value
	except Exception as e:
		#return none if something goes south
		if args.verbose:
			print ("Error trying to match JSON response:", e)
		return None

#parse the response and retrieve the value based on the first regex match
#if capturing group is defined in the regex - the first matching capturing group is captured
#if capturing group is not defined in the regex - the whole match is returned
def retrieve_responsevar_regex(resp, regex_exp):
	try:
		value = re.search(regex_exp, str(resp.content))
		return value
	except Exception as e:
		#return none if something goes south
		if args.verbose:
			print ("Error trying to match regex response:", e)
		return None

#send signle request given the request string
def send_request(rstr, sequence_number, iteration_number):
	
	#embed responsevar substitutions if any
	#in first request first iteration there should be no substitutions
	for skey, svalue in current_step_substitutions.items():
		if svalue:
			rstr = rstr.replace(skey, str(svalue))
			if args.verbose:
				print ("Replacement in current step request: replaced {0} with {1}", skey, svalue)
					
	##embed payloads if any
	for pkey, pvalue in payloads.items():
		rstr = rstr.replace(pkey, str(pvalue[iteration_number]))
		if args.verbose:
			print ("Replacement in payload request: replaced {0} with {1}", pkey, pvalue[iteration_number])
		
	#automatic request parsing
	rbytes = rstr.strip().encode('utf-8')
	try:
		request = ParsedHTTPRequest(rbytes)
	except Exception as e:
		print ("Can't parse/understand HTTP requests from file:", e)
		current_step_substitutions.clear()	#no response - no substitutions
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
		if logfile:
			logfile.write(request.command + " ");
			logfile.write(url + "\n");
			logfile.write(str(request.headers) + "\n");

		if (request.command == 'GET'):
			r = requests.get(
				url,
				headers=request.headers,
				verify=False,
				timeout=(2,2))	#2s should to connect and read the response TODO should this be in config?
		elif (request.command == 'POST'):
			#get data first, if PUT/PUSH methods are added move this out of the branching statement
			#according to RFC, we expect at least one line in the request body 
			#limiting number of spits to 1 to only split on the first newline in case there are multiple
			rdata = rstr.split("\n\n", 1)[1]
			if logfile:
				logfile.write(rdata + "\n");

			r = requests.post(
				url,
				headers=request.headers, 
				data=rdata,
				verify=False,
				timeout=(2,2)) #TODO should timeout be part of the config?
		else:
			#other methods are easy to add
			print ("Unsupported method")
			current_step_substitutions.clear()	#no response - no substitutions
			return
	except Exception as e:
			print ("Error sending request " + str(sequence_number) + " " + e)
			current_step_substitutions.clear()	#no response - no substitutions
			return

	#fill up current (next) step substitutions
	#if this is the last response in the sequence - carry over to the next iteration
	for skey, svalue in step_substitutions[sequence_number % len(request_list)].items():
		if svalue[0] == 'json':
			current_step_substitutions[skey] = retrieve_responsevar_json(r, svalue[1])
		elif svalue[0] == 'regex':
			current_step_substitutions[skey] = retrieve_responsevar_regex(r, svalue[1])
		else:
			print ("Error while performing substitutions")

	print ("{0}#####{1}".format(r.status_code, len(r.content)))
	if logfile:
		logfile.write("---------------------\n" + str(r.content) + "\n======================\n");
	
		
#send the sequence of requests given the array of string requests
def send_sequence(request_list, iteration):
	num = 0
	print ("Iteration " + str(iteration) + " - starting sequence")

	#first request does not have response - init the current_step_substitutions with trivial value
	current_step_substitutions.clear()
	
	for rstr in request_list:
		num+=1
		send_request(rstr, num, iteration)
	print ("Iteration " + str(iteration) + " - sequence finished")
	
#GLOBAL VARS
constant_substitutions = {}
payloads = {}
sslconfig = False
port = 80

#MAIN FUNCTION	
# Argument parsing
parser = argparse.ArgumentParser(description='Script that parses requests file and configuration json. It applies substitutions from config file and sends the requests in order.')
parser.add_argument("requestsfile", help="Text file containing sequence of HTPP requests, each separated by separator line (default #####)")
parser.add_argument("configfile", help="JSON file containing variables substitutions and other config")
parser.add_argument("-s", "--separator", help="Custom separator between requests in requestsfile")
parser.add_argument("-l", "--log", help="Traffic log for debug purposes")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
args = parser.parse_args()

#read requests file
try:
    with open(args.requestsfile, 'r') as rf:
        requestbulk = rf.read()
		#config = configfile.read()
except Exception as e:
	print ("Can't open requests file " + args.requestsfile + ": " + e)
	sys.exit(0)

#parse config file as json
try:
    with open(args.configfile, 'r') as configfile:
        config = json.load(configfile)
		#config = configfile.read()
except Exception as e:
	print ("Can't load json from file " + args.configfile + " " + e)
	sys.exit(0)

try:
	logfile = None
	if args.log:
		logfile = open(args.log, 'w')
except Exception as e:
	print ("Can't open log file for writing:" + args.log + " " + e)
	sys.exit(0)

#parse the ssl config
if 'ssl' in config and config['ssl']:
	sslconfig = True
	port = 443
if 'port' in config:
	port = config['port']

#constant substitutions are perofmed once before starting the iterations
if 'substitutions' in config.keys() and 'constants' in config['substitutions'].keys():
    constant_substititions = config['substitutions']['constants']
for key, value in constant_substitutions.items(): 
	#we can assume the format for substitution is "key: value"
	requestbulk = requestbulk.replace(key, value)
	if args.verbose:
		print ("Replacement in constant request: replaced {0} with {1}", key, value)

#parse the bulk and get a list of requests
if args.separator:
	request_list = re.split(args.separator, requestbulk)
else:
	request_list = re.split(r'#####', requestbulk)

#payloads parsing if any	
if 'payloads' in config.keys():
	iterations = parse_payloads()
else:
	iterations = 1

step_substitutions = [dict() for x in range(len(request_list))]
current_step_substitutions = {}
step_substitutions_num = 0
if ('substitutions' in config.keys()) and ('responsevars' in config['substitutions'].keys()):
    for key,value in config['substitutions']['responsevars'].items():
        step_substitutions_num += 1
        if 'json' in value.keys():
            if 'steps' in value.keys():
                for i in value['steps']:
                    step_substitutions[i][key] = ('json',value['json'])
            else:
                for i in range(0,len(request_list),1):
                    step_substitutions[i][key] = ('json',value['json'])
        elif 'regex' in value.keys():
            if 'steps' in value.keys():
                for i in value['steps']:
                    step_substitutions[i][key] = ('regex',value['regex'])
            else:
                for i in range(0,len(request_list),1):
                    step_substitutions[i][key] = ('regex',value['regex'])
        else:
            print("Can't parse config file - invalid responsevar")
            if logfile:
                logfile.close()
            sys.exit(0)

if (args.verbose):
	print ("Parsed: {0} constant substitutions, {1} response variables and {2} injection points; payload sequence length is {3}; total requests to be sent {4}.".format(
		len(constant_substititions),
		step_substitutions_num,
		len(payloads), 
		iterations,
		len(request_list)*iterations))

#main sending loop
for i in range(0, iterations, 1):
	send_sequence(request_list, i)
	
if logfile:
	logfile.close()