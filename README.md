# Stepruder

This is a pen-testing tool that implements Intruder-like functionality in Python. In addition, it sends a sequence of requests for every payload iteration. The result is a combination of Stepper (new Burp extenstion) and Intruder functionlity.

## Getting Started

Complete the following instructions to set up and run your project on your local machine for development and testing purposes. No special deployment for production environment is provisioned.

Getting the source:
```
git clone https://github.com/blackberry/Stepruder
```

### Installing

Python3 installation is required as this project is a python script designed to run under Python3. Tested on Ubuntu / CentOS / Windows.

### Usage 

Usage: stepruder.py [-h] [-s SEPARATOR] [-l LOG] [-v] requestsfile configfile

This script automates payload injection into the long request sequences rather than into an individual request. It parses *requestsfile* and *configfile* json. Then it applies substitutions from the config file, injects the payloads and sends the processed requests in order.

Positional arguments:
* requestsfile - Text file containing sequence of HTPP requests, each separated by separator line (default #####)
* configfile - JSON file containing variables substitutions and other configs

Optional arguments:
* -h, --help            show this help message and exit
*   -s SEPARATOR, --separator SEPARATOR Custom separator between requests in requestsfile
*   -l LOG, --log LOG     Traffic log for debug purposes
*   -v, --verbose         Increase output verbosity

```
python stepruder.py -l debug.log -v requests/requests_login.txt configs/config_login.json
```

### How this works

Requestsfile should contain a plaintext sequence of request templates with potential substitution variables and eval expressions. 
Substitution variables can be three different scopes:
1. Constant substitutions
2. Sequence-scope substitutions
3. Request-scope substitutions

**Constant substitutions** are defined under "substitutions" in config json as "constants" and replaced only once before the start of the sending process. This will be a simple string replacement substitution. These are useful for variables that stay constant through the entire program but may be 
different between the program runs (i.e. cookie).

**Sequence-scope substitutions** are defined in config json as "payloads" and replaces before the beginning of each sequence. The number of different payloads will define the number of sequence iterations. Lack of any payloads will only send the sequence once. These are useful to define injected payloads.

**Request-scope substitutions** are defined under "substitutions" in config json as "responsevars", because they are defined as matches from response content and therefore can change after every response. The match can be "json" or "regex". Use "json" when working only on json response bodies and use "regex" when working on any response body plus response header values, in that order. These substitutions are potentially replaced before sending every new request depending on whether the previous response contained the match or not. If the response does not contain the match, then the responsevar value does not change. Responsevars are useful to keep interaction between client and server alive (i.e. updating CSRF tokens, keeping client-server sync in Vaadin etc.).

**Eval expression** are substitutions on steroids. Eval expressions enclosed in ${#...} are sequence-scoped (i.e. evaluated once in the beginning of the sequence). eval expressions enclosed in ${!...} are request-scoped. Eval expression by itself is a Python eval expression that returns 
one value. This value is then substituted into the request sequence. The eval expression may or may not include variables (i.e. ```${!time.time()}``` vs ```${#len(PAYLOAD)}```). The expression should only use Python modules imported already in the script (see list at the beginning of the stepruder.py) or import its own modules.

The simplified overall flow of the program is as follos:

```
Parsing requestfile and config json
        Form payloads arrays, identify number of sequences
        Constant substitutions
        While more sequences - start sequence i:
                Payload #1 injection
                Evaluation of sequence-scope eval expressions
                While more requests in the sequence:
                        Substitute responsevars from j-1 response
                        Evaluate request-scope eval expressions
                        Send request j
                        Parse responsevars from j response
```

In addition, config json may include the following connection configs: ssl (Boolean), port (Numeric), proxies (Dictionary) and response parsing regex "grep_final_response". For example:
```
        "ssl": true,
        "port": 443,
        "grep_last_response": "Invalid credentials",
        "proxies": {
                "http": "https://127.0.0.1:8080"
                "https": "https://127.0.0.1:8080"
        },
        "substitutions": {...
```

### Limitations

Current Stepruder limitations:
1. No parallel sequence sending yet. This should improve the performance dramatically.
2. No different payload injection combos (i.e. only Sniper or Pitchfork in Intruder terms).
3. No advanced encoding/decoding capabilities yet. Payloads / substitutions that include special characters might interfere with JSON parsing and regex matching.

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

* **Shay Berkovich** - *Initial work* - [sshayb](https://github.com/sshayb)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

