# apivoid.py

apivoid.py is a simple script that will allow you to specify an IPv4 address, Domain, or URL address to retrieve intel using apivoid's API.

## Installation

```bash
python3 -m pip install -r requirements.txt
```

## Usage

```python
usage: apivoid lookup script [-h] [-i IPADDRESS] [-d DOMAIN] [-u URL] [-sT SITETRUST] [-t THREATLOG] [-sL SSL]

Python script to query IPv4 , Domain, or URL functions through the use of apivoid.com's Threat Analysis APIs

optional arguments:
  -h, --help            show this help message and exit
  -i IPADDRESS, --ipaddress IPADDRESS
                        Input IPv4 address to run the IP reputation function
  -d DOMAIN, --domain DOMAIN
                        Input domain to run the domain blacklist function
  -u URL, --url URL     Input URL to run the URL reputation function
  -sT SITETRUST, --sitetrust SITETRUST
                        Input domain to run the Site Trustworthiness record function
  -t THREATLOG, --threatlog THREATLOG
                        Input domain to run the ThreatLog function
  -sL SSL, --ssl SSL    Input domain to run the SSL lookup function


examples:
python3 apivoid.py -i 1.1.1.1
python3 apivoid.py -d google.com
python3 apivoid.py -u https://google.com
python3 apivoid.py -sT google.com
python3 apivoid.py -t google.com
python3 apivoid.py -sL google.com
```