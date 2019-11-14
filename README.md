# Stepruder

This is a pen-testing tool that implements Intruder-like functionality in Python. In addition, it adds another dimension and allows to send a sequence of requests for every payload iteration. In other words a mix between Stepper (new ) and Intruder.

# Installation

No installation required. This project is a python script designed to run under Python3. Tested on Ubuntu / CentOS / Windows.

# Usage

usage: sequencer.py [-h] [-s SEPARATOR] [-v] requestsfile configfile

Script that parses requests file and configuration json. It applies
substitutions from config file and sends the requests in order.

positional arguments:
  requestsfile          Text file containing sequence of HTPP requests, each
                        separated by separator line (default #####)
  configfile            JSON file containing variables substitutions and other
                        config

optional arguments:
  -h, --help            show this help message and exit
  -s SEPARATOR, --separator SEPARATOR
                        custom separator between requests in requestsfile
  -v, --verbose         increase output verbosity
