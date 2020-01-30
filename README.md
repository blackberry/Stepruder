# Stepruder

This is a pen-testing tool that implements Intruder-like functionality in Python. In addition, it adds another dimension and allows to send a sequence of requests for every payload iteration. In other words a mix between Stepper (new Burp extenstion) and Intruder.

# Installation

Python3 installation required as this project is a python script designed to run under Python3. Tested on Ubuntu / CentOS / Windows.

# Usage

Usage: stepruder.py [-h] [-s SEPARATOR] [-l LOG] [-v] requestsfile configfile

This is a mix between Stepper and Intruder script that automates payload injection into the long request sequences rather than into an individual request. It parses requests file and configuration json. It applies then substitutions from the config file, injects the payloads and sends the processed requests in order.

Positional arguments:
* requestsfile          Text file containing sequence of HTPP requests, each separated by separator line (default #####)
*   configfile            JSON file containing variables substitutions and other configs

Optional arguments:
* -h, --help            show this help message and exit
*   -s SEPARATOR, --separator SEPARATOR Custom separator between requests in requestsfile
*   -l LOG, --log LOG     Traffic log for debug purposes
*   -v, --verbose         Increase output verbosity


Requestsfile should contain a plaintext sequence of request templates with potential substitution variables and eval expressions. Substitution variables can be of 3 different scopes:
1. Constant substitutions
2. Sequence-scope substitutions
3. Request-scope substitutions

Constant substitutions defined under "substitutions" in config json as "constants", are replaced only once before the start of the sending process. This will be a simple string replace substitution. These are useful for variables that stay constants through entire program but may be 
different between the program runs (i.e. cookie).

Sequence-scope substitutions defined in config json as "payloads", are replaces before the beginning of each sequence. Number of different payloads will define the number of sequence iterations. Lack of any payloads will only send the sequence once. These are useful to define injected payloads.

Request-scope substitutions defined under "substitutions" in config json as "responsevars", because the are defined as matches from response content and as such can change after every response. The match can be "json" or "regex" with json working only on json response bodies and regex working on any response body plus response header values, in that order. These substitutions are potentially replaced before sending every new request depending on whether the previous response contained the match or not. If the response does not contain the match, then the responsevar value does not change. Responsevars are useful to keep alive interaction between client and server (i.e. updating CSRF tokens, keeping client-server sync in Vaadin etc.)

Eval expression are substitutions on steroids. Eval expressions enclosed in ${#...} are sequence-scoped (i.e. evaluated once in the beginning 
of the sequence); eval expressions enclosed in ${!...} are request-scoped. Eval expression by itself is a Python eval expression that returns 
one value. This value is then substituted into the request sequence. The eval expression may or may not include variables (i.e. ${!time.time()} vs ${#len(PAYLOAD)}). The expression should only use Python modules imported already in the script (see list at the beginning of the stepruder.py) or import its own modules.

The simplified overall flow of the program looks as following:

`Parsing requestfile and config json
        Form payloads arrays, identify number of sequences
        Constant substitutions
        While more sequences - start sequence i:
                Payload #1 injection
                Evaluation of sequence-scope eval expressions
                While more requests in the sequence:
                        Substitute responsevars from j-1 response
                        Evaluate request-scope eval expressions
                        Send request j
                        Parse responsevars from j response`

In addition, config json may include following connection configs: ssl (Boolean), port (Numeric), proxies (Dictionary) and response parsing regex "grep_final_response". For example:
        "ssl": true,
        "port": 443,
        "grep_last_response": "Invalid credentials",
        "proxies": {
                "http": "https://127.0.0.1:8080"
                "https": "https://127.0.0.1:8080"
        },
        "substitutions": {...

Current Stepruder limitations:
1. No parallel sequence sending yet. This should improve the performance dramatically.
2. No different payload injection combos (i.e. only Sniper or Pitchfork in Intruder terms).
3. No advanced encoding/decoding capabilities yet. Payloads / substitutions that include special characters might interfere with JSON parsing and regex matching.
