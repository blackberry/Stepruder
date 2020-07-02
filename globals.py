################################################################################
# Name   : Stepruder - globals definitions
# Author : Shay Berkovich
#
# Copyright 2020 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################
import sys

#GLOBAL VARS
constant_substitutions = {}
payloads = {}
separator = None
grep_last_response_regex = None
sslconfig = False
port = 80
proxies = {}
maxresponsebody = sys.maxsize

help_string = "Requestsfile should contain a plaintext sequence of request templates with potential substitution \
variables and eval expressions. Substitution variables can be of 3 different scopes: \n(1) Constant substitutions \
\n(2) Sequence-scope substitutions \n(3) Request-scope substitutions \n\n\
Constant substitutions defined under \
\"substitutions\" in config json as \"constants\", are replaced only once before the start of the sending process. \
This will be a simple string replace substitution. These are useful for variables that stay constants through \
entire program but may be different between the program runs (i.e. cookie). \n\n\
Sequence-scope substitutions defined \
in config json as \"payloads\", are replaces before the beginning of each sequence. Number of different payloads \
will define the number of sequence iterations. Lack of any payloads will only send the sequence once. These are \
useful to define injected payloads.\n\n\
Request-scope substitutions defined under \"substitutions\" in config json as \"responsevars\", because the are defined\
 as matches from response content and as such can change after every response. The match can be \"json\" or \"regex\" \
with json working only on json response bodies and regex working on any response body plus response header values, in \
that order. These substitutions are potentially replaced before sending every new request depending on whether the previous \
response contained the match or not. If the response does not contain the match, then the responsevar value does not \
change. Responsevars are useful to keep alive interaction between client and server (i.e. updating CSRF tokens, \
keeping client-server sync in Vaadin etc.)\n\n\
Eval expression are substitutions on steroids. Eval expressions enclosed in ${#...} are sequence-scoped\
 (i.e. evaluated once in the beginning of the sequence); eval expressions enclosed in ${!...} are request-scoped. Eval\
 expression by itself is a Python eval expression that returns one value. This value is then substituted into the \
request sequence. The eval expression may or may not include variables (i.e. ${!time.time()} vs ${#len(PAYLOAD)}). \
The expression should only use Python modules imported already in the script (see list at the \
beginning of the stepruder.py) or import its own modules.\n\n\
The simplified overall flow of the program looks as following:\n\
\tParsing requestfile and config json\n\
\tForm payloads arrays, identify number of sequences\n\
\tConstant substitutions\n\
\tWhile more sequences - start sequence i:\n\
\t\tPayload #1 injection\n\
\t\tEvaluation of sequence-scope eval expressions\n\
\t\tWhile more requests in the sequence:\n\
\t\t\tSubstitute responsevars from j-1 response\n\
\t\t\tEvaluate request-scope eval expressions\n\
\t\t\tSend request j\n\
\t\t\tParse responsevars from j response\n\
\
\n\nIn addition, config json may include following connection configs: ssl (Boolean), port (Numeric), proxies \
(Dictionary) and response parsing regex \"grep_final_response\". For example:\n\
\t\"ssl\": true,\n\
\t\"port\": 443,\n\
\t\"request_separator\": \"#####\",\n\
\t\"grep_last_response\": \"Invalid credentials\",\n\
\t\"proxies\": {\n\
\t\t\"http\": \"https://127.0.0.1:8080\"\n\
\t\t\"https\": \"https://127.0.0.1:8080\"\n\
\t},\n\
\t\"substitutions\": {...\
\
\n\nCurrent Stepruder limitations:\n\
(1) No parallel sequence sending yet. This should improve the performance dramatically.\n\
(2) No different payload injection combos (i.e. only Sniper or Pitchfork in Intruder terms).\n\
(3) No advanced encoding/decoding capabilities yet. Payloads / substitutions that include special characters \
might interfere with JSON parsing and regex matching.\n"