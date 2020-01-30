#!/usr/bin/python
import sys
import argparse
import re
import json
import requests
import urllib3
import logging
import time
import http.client

from collections import defaultdict
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from globals import *

#class for parsing the HTTP request from text - adapted from https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class ParsedHTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

#helper function to evaluate expression
def repl(m):
    expr = m.group(1)
    return str(eval(expr))

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
					print ("Error - can't parse/understand payloads in config json - can't open list {0}, exiting.".format(config['payloads'][key]['path']))
					sys.exit(1)
			else:
				print ("Error - can't parse/understand payloads in config json - unknown payload type, exiting.")
				sys.exit(1)
			iterations = iterations if iterations < len(payloads[key]) else len(payloads[key])
	else:
		iterations = 0
	return iterations

#parse the response and retrieve the value based on json key
#if multiple values appear the behavior is undefined
def retrieve_responsevar_json(resp, json_exp):
	try:
		respdict = json.loads(resp.text)	#json parse just the body of the response
		value = respdict[json_exp]	#TODO: what happens if 2 duplicate keys present? Python dictionary does not support duplicate keys BTW
		return value
	except Exception as e:
		#return none if something goes south
		if args.verbose:
			print ("Error trying to match JSON response: {0} with expression {1}, exiting.".format(resp, json_exp))
		sys.exit(1)

#parse the response and retrieve the value based on the first regex match
#if capturing group is defined in the regex - the first matching capturing group is captured
#if capturing group is not defined in the regex - the whole match is returned
def retrieve_responsevar_regex(resp, regex_exp):
	try:
		#first search the body
		value = re.search(regex_exp, resp.text)
		if value:
			if args.verbose:
				print ('Match for {0} : {1}'.format(regex_exp, value.group(1)))
			return value.group(1)
		#if nothing matches - search the headers
		for headername, headerval in resp.headers.items():
			value = re.search(regex_exp, headerval)
			if value:
				if args.verbose:
					print ('Match for {0} : {1}'.format(regex_exp, value.group(1)))
				return value.group(1)
		if args.verbose:
			print ('No match for {0}'.format(regex_exp))
	except Exception as e:
		#return none if something goes south
		if args.verbose:
			print ("Error trying to match regex {0} in response {1}, exiting.".format(regex_exp, resp.text))
		sys.exit(1)

#send signle request given the request string
def send_request(rstr, request_number, iteration_number):
	
	#embed responsevar substitutions if any
	#in first request first iteration there should be no substitutions
	for skey, svalue in current_step_substitutions.items():
		if svalue:
			#if args.verbose:
			#	print ("Considering substitutions: " + str(skey) + " with " + str(svalue))
			rstr = rstr.replace(skey, str(svalue))
			#if args.verbose:
			#	print ('Replacement in current iteration request: replaced {0} with {1}'.format(skey, svalue))
	
	#evaluate request-scope expressions - starting with ${!
	try:
		rstr = re.sub("\\${!(.*?)}", repl, rstr)
	except Exception as e:
		print ("Error evaluating request-scope expression in sequence {0}, request{1}, exiting.".format(str(sequence_number), iteration))
		current_step_substitutions.clear()	#no response - no substitutions
		sys.exit(1)
									
	#automatic request parsing
	rbytes = rstr.strip().encode('utf-8')
	try:
		request = ParsedHTTPRequest(rbytes)
	except Exception as e:
		print ("Error trying parse/understand HTTP requests from file, exiting: ", e)
		current_step_substitutions.clear()	#no response - no substitutions
		sys.exit(1)
	
	#forming the url line - assuming first word is always method
	if request.requestline.split(" ")[1].startswith('http'):
		#full url is already included in the requestline
		url = request.requestline.split(" ")[1]
	else:
		#requestline is only a path + queryargs
		if sslconfig:
			url = "https://" + request.headers['host'].split(":")[0] + ":" + str(port) + request.requestline.split(" ")[1]
		else:
			url = "http//" + request.headers['host'].split(":")[0] + ":" + str(port) + request.requestline.split(" ")[1]

	if (args.verbose):
		print ('Sending {0} request {1} to {2}'.format(request.command, request_number, url))

	try:
		if logfile:
			logfile.write(request.command + " ")
			logfile.write(url + "\n")
			logfile.write(str(request.headers))

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
			rdata = rstr.split("\n\n", 1)[1].strip().encode('utf-8')
			if logfile:
				logfile.write(str(rdata) + "\n")

			r = requests.post(
				url,
				headers=request.headers, 
				data=rdata,
				verify=False,
				proxies=proxies,
				timeout=(2,2)) #TODO should timeout be part of the config?
		else:
			#other methods are easy to add
			print ("Unsupported method")
			current_step_substitutions.clear()	#no response - no substitutions
			return
	except Exception as e:
			print ("Error sending request {0}, exiting.".format(request_number))
			current_step_substitutions.clear()	#no response - no substitutions
			sys.exit(1)

	#fill up current (next) step substitutions
	#TODO: if this is the last response in the sequence - carry over to the next iteration?
	for skey, svalue in step_substitutions[request_number % len(request_list)].items():
		if svalue[0] == 'json':
			#for json it only makes sense to scan the response body
			new_value = retrieve_responsevar_json(r, svalue[1])
			#we are only interested in non-trivial values, otherwise leave it the same substitution
			if new_value != None:
				current_step_substitutions[skey] = new_value
		elif svalue[0] == 'regex':
			#for regex we want to scan both the body and headers (f.e. cookies)
			new_value = retrieve_responsevar_regex(r, svalue[1])
			#we are only interested in non-trivial values, otherwise leave it the same substitution
			if new_value != None:
				current_step_substitutions[skey] = new_value
		else:
			print ("Error while performing substitutions - unrecognized response var, continuing.")
	
	print ("{0}#####{1}".format(r.status_code, len(r.content)))
	if logfile:
		logfile.write("---------------------\n" + str(r.content) + "\n======================\n")

	# if last payload and grep_result is present check for response
	if grep_last_response_regex and request_number == len(request_list):
		value = re.search(grep_last_response_regex, r.text)
		if value: 
			print ("Grep match found in last response: " + value.string)
		else:
			print ("Grep match not found in last response.")

#send the sequence of requests given the array of string requests
def send_sequence(request_list, iteration):
	num = 0
	print ("Iteration " + str(iteration) + " - starting sequence")
	
	#first request does not have response - init the current_step_substitutions with trivial value
	current_step_substitutions.clear()
	
	request_list_post_sequence_scope__subs = []
	for rstr in request_list:	
		try:
			for pkey, pvalue in payloads.items():
				rstr = re.sub(pkey, str(pvalue[iteration]).replace('"', '\\"'), rstr)
		
			rstr = re.sub("\\${#(.*?)}", repl, rstr)
		except Exception as e:
			print ("Error matching sequence-scope regex in sequence {0}, exiting.".format(iteration))
			current_step_substitutions.clear()	#no response - no substitutions
			sys.exit(1)	
		
		request_list_post_sequence_scope__subs.append(rstr)

	print ("Status#####ResponseLen")	
	for rstr in request_list_post_sequence_scope__subs:
		num+=1
		send_request(rstr, num, iteration)

	print ("Iteration " + str(iteration) + " - sequence finished")
	if logfile:
		logfile.write("\n\n********************************************** End of the iteration **********************************************\n\n")
	
#MAIN FUNCTION	
# Argument parsing
parser = argparse.ArgumentParser(
	description='This is a mix between Stepper and Intruder script that automates payload injection into the long request sequences rather than into an individual request. It parses requests file and configuration json. It applies then substitutions from the config file, injects the payloads and sends the processed requests in order.',
	formatter_class=argparse.RawTextHelpFormatter,
	epilog=help_string)
parser.add_argument("requestsfile", help="Text file containing sequence of HTPP requests, each separated by separator line (default #####)")
parser.add_argument("configfile", help="JSON file containing variables substitutions and other configs")
parser.add_argument("-s", "--separator", help="Custom separator between requests in requestsfile")
parser.add_argument("-l", "--log", help="Traffic log for debug purposes")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
args = parser.parse_args()

#networking and logging config
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
if args.verbose:
	http.client.HTTPConnection.debuglevel = 1
	logging.basicConfig()
	logging.getLogger().setLevel(logging.DEBUG)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.DEBUG)
	requests_log.propagate = True
else:
	http.client.HTTPConnection.debuglevel = 0
	logging.basicConfig()
	logging.getLogger().setLevel(logging.ERROR)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.ERROR)
	requests_log.propagate = True

#read requests file
try:
    with open(args.requestsfile, 'r') as rf:
        requestbulk = rf.read()
except Exception as e:
	print ("Error - can't open requests file {0}, exiting.".format(args.requestsfile))
	sys.exit(1)

#parse config file as json
try:
    with open(args.configfile, 'r') as configfile:
        config = json.load(configfile)
		#config = configfile.read()
except Exception as e:
	print ("Error - can't load json from file {0}, exiting.".format(args.configfile))
	sys.exit(1)

try:
	logfile = None
	if args.log:
		logfile = open(args.log, 'w')
except Exception as e:
	print ("Error - can't open log file {0} for writing, exiting.".format(args.log))
	sys.exit(1)

#parse the ssl config
if 'ssl' in config and config['ssl']:
	sslconfig = True
	port = 443
if 'port' in config:
	port = config['port']
if 'proxies' in config and config['proxies']:
	proxies = config['proxies']

#constant substitutions are performed once before starting the iterations
if 'substitutions' in config.keys() and 'constants' in config['substitutions'].keys():
    constant_substitutions = config['substitutions']['constants']
for key, value in constant_substitutions.items(): 
	#we can assume the format for substitution is "key: value"
	if args.verbose:
		print("Considering constant substitutions: " + key + " with " + value)
	requestbulk = requestbulk.replace(key, value)
	if args.verbose:
		print ("Replacement in constant request: replaced {0} with {1}".format(key, value))

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

#initializing response vars and assigning them to the appropriate steps
step_substitutions = [dict() for x in range(len(request_list))]
current_step_substitutions = {}
step_substitutions_num = 0
if ('substitutions' in config.keys()) and ('responsevars' in config['substitutions'].keys()):
    for key,value in config['substitutions']['responsevars'].items():
        if 'json' in value.keys():
            if 'steps' in value.keys():
                for i in value['steps']:
                    step_substitutions[i][key] = ('json',value['json'])
            else:
                for i in range(0,len(request_list),1):
                    step_substitutions[i][key] = ('json',value['json'])
        elif 'regex' in value.keys():
            try:
                re.compile(value['regex'])
            except Exception as e:
                print ("Can't compile regex {0}, skipping and, continuing.".format(value['regex']))
                continue
            if 'steps' in value.keys():
                for i in value['steps']:
                    step_substitutions[i][key] = ('regex',value['regex'])
            else:
                for i in range(0,len(request_list),1):
                    step_substitutions[i][key] = ('regex',value['regex'])
        else:
            print("Error - can't parse config file - invalid responsevar, exiting.")
            if logfile:
                logfile.close()
            sys.exit(1)
        step_substitutions_num += 1

if 'grep_last_response' in config and config['grep_last_response']:
	try:
		re.compile(config['grep_last_response'])
		grep_last_response_regex = config['grep_last_response']
	except Exception as e:
		print ("Error - can't compile grep_last_response regex {0}, exiting.".format(value['regex']))
		sys.exit(1)

print ("Parsed: {0} constant substitutions, {1} response variables and {2} injection points; payload sequence length is {3}; total requests to be sent {4}.".format(
	len(constant_substitutions),
	step_substitutions_num,
	len(payloads), 
	iterations,
	len(request_list)*iterations))

#main sending loop
for i in range(0, iterations, 1):
	send_sequence(request_list, i)
	
if logfile:
	logfile.close()