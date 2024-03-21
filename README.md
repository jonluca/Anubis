# Anubis

[![Build Status](https://travis-ci.org/jonluca/Anubis.svg?branch=master)](https://travis-ci.org/jonluca/Anubis) ![Coverage](https://github.com/jonluca/Anubis/blob/master/coverage.svg) [![GitHub issues](https://img.shields.io/github/issues/jonluca/Anubis.svg)](https://github.com/jonluca/Anubis/issues) [![GitHub license](https://img.shields.io/github/license/jonluca/Anubis.svg)](https://github.com/jonluca/Anubis/blob/master/LICENSE)

```
        d8888                   888      d8b
       d88888                   888      Y8P
      d88P888                   888
     d88P 888 88888b.  888  888 88888b.  888 .d8888b
    d88P  888 888 "88b 888  888 888 "88b 888 88K
   d88P   888 888  888 888  888 888  888 888 "Y8888b.
  d8888888888 888  888 Y88b 888 888 d88P 888      X88
 d88P     888 888  888  "Y88888 88888P"  888  88888P'
```

Anubis is a subdomain enumeration and information gathering tool. Anubis collates data from a variety of sources,
including HackerTarget, DNSDumpster, x509 certs, VirusTotal, Google, Pkey, Shodan, Spyse, and NetCraft.
Anubis also has a sister project, [AnubisDB](https://github.com/jonluca/Anubis-DB), which serves as a centralized
repository of subdomains.

[Original Medium article release](https://medium.com/@jonluca/introducing-anubis-a-new-subdomain-enumerator-and-information-gathering-tool-d25b39ad98f2)

## Getting Started

### Prerequisites

* Nmap (if wanting to run port scans and certain certificate scans)

If you are running Linux, the following are also required:

`sudo apt-get install python3-pip python-dev libssl-dev libffi-dev`

### Installing

Note: Python 3 is required

`pip3 install anubis-netsec`

### Install From Source

Please note Anubis is still in beta.

```
git clone https://github.com/jonluca/Anubis.git
cd Anubis
pip3 install  -r requirements.txt
pip3 install .
```

## Usage

    Usage:
      anubis (-t TARGET | -f FILE) [-o FILENAME]  [-abinoprsSv] [-w SCAN] [-q NUM]
      anubis -h
      anubis (--version | -V)
      
    Options:
      -h --help                       show this help message and exit
      -t --target                     set target (comma separated, no spaces, if multiple)
      -f --file                       set target (reads from file, one domain per line)
      -n --with-nmap                  perform an nmap service/script scan
      -o --output                     save to filename
      -i --additional-info            show additional information about the host from Shodan (requires API key)
      -p --ip                         outputs the resolved IPs for each subdomain, and a full list of unique ips
      -a --dont-send-to-anubis-db     don't send results to Anubis-DB
      -r --recursive                  recursively search over all subdomains
      -s --ssl                        run an ssl scan and output cipher + chain info
      -S --silent                     only out put subdomains, one per line
      -w --overwrite-nmap-scan SCAN   overwrite default nmap scan (default -nPn -sV -sC)
      -v --verbose                    print debug info and full request output
      -q --queue-workers NUM          override number of queue workers (default: 10, max: 100)
      -V --version                       show version and exit
    
    Help:
      For help using this tool, please open an issue on the Github repository:
      https://github.com/jonluca/anubis

Note: If you'd like to use the shodan.io API, make sure to prefix the command with `SHODAN_API_KEY=yourkey`

### Basic

#### Common Use Case

`anubis -tip  domain.com -o out.txt`

Set's target to `domain.com`, (`t`) outputs additional information (`i`) like server and ISP or server hosting provider,
then attempts to resolve all URLs (`p`) and outputs list of unique IPs and sends to Anubis-DB (`a`). Finally, writes all
results to out.txt (`o`).

#### Other

```anubis -t reddit.com``` Simplest use of Anubis, just runs subdomain enumeration

```
Searching for subdomains for 151.101.65.140 (reddit.com)

Testing for zone transfers
Searching for Subject Alt Names
Searching HackerTarget
Searching VirusTotal
Searching Pkey.in
Searching NetCraft.com
Searching crt.sh
Searching DNSDumpster
Searching Anubis-DB
Found 193 subdomains
----------------
fj.reddit.com
se.reddit.com
gateway.reddit.com
beta.reddit.com
ww.reddit.com
... (truncated for readability)
Sending to AnubisDB
Subdomain search took 0:00:20.390
```

`anubis -t reddit.com -ip` (equivalent to `anubis -t reddit.com --additional-info --ip`) - resolves IPs and outputs list
of uniques, and provides additional information through https://shodan.io

```
Searching for subdomains for 151.101.65.140
Server Location: San Francisco US - 94107
ISP: Fastly
Found 27 domains
----------------
http://www.np.reddit.com: 151.101.193.140
http://nm.reddit.com: 151.101.193.140
http://ww.reddit.com: 151.101.193.140
http://dg.reddit.com: 151.101.193.140
http://en.reddit.com: 151.101.193.140
http://ads.reddit.com: 151.101.193.140
http://zz.reddit.com: 151.101.193.140
out.reddit.com: 107.23.11.190
origin.reddit.com: 54.172.97.226
http://blog.reddit.com: 151.101.193.140
alb.reddit.com: 52.201.172.48
http://m.reddit.com: 151.101.193.140
http://rr.reddit.com: 151.101.193.140
reddit.com: 151.101.65.140
http://www.reddit.com: 151.101.193.140
mx03.reddit.com: 151.101.193.140
http://fr.reddit.com: 151.101.193.140
rhs.reddit.com: 54.172.97.229
http://np.reddit.com: 151.101.193.140
http://nj.reddit.com: 151.101.193.140
http://re.reddit.com: 151.101.193.140
http://iy.reddit.com: 151.101.193.140
mx02.reddit.com: 151.101.193.140
mailp236.reddit.com: 151.101.193.140
Found 6 unique IPs
52.201.172.48
151.101.193.140
107.23.11.190
151.101.65.140
54.172.97.226
54.172.97.229
Execution took 0:00:04.604
```

### Advanced

```anubis -t reddit.com --with-nmap -o temp.txt -i --overwrite-nmap-scan "-F -T5"```

```
Searching for subdomains for 151.101.65.140 (reddit.com)

Testing for zone transfers
Searching for Subject Alt Names
Searching HackerTarget
Searching VirusTotal
Searching Pkey.in
Searching NetCraft.com
Searching crt.sh
Searching DNSDumpster
Searching Anubis-DB
Searching Shodan.io for additional information
Server Location: San Francisco, US - 94107
ISP  or Hosting Company: Fastly
To run a DNSSEC subdomain enumeration, Anubis must be run as root
Starting Nmap Scan
Host : 151.101.65.140 ()
----------
Protocol: tcp
port: 80	state: open
port: 443	state: open
Found 195 subdomains
----------------
nm.reddit.com
ne.reddit.com
sonics.reddit.com
aj.reddit.com
fo.reddit.com
f5.reddit.com
... (truncated for readability)
Sending to AnubisDB
Subdomain search took 0:00:26.579
```

## Running the tests

Run tests on their own, in native pytest environment

```pytest```

## Built With

* CLI Boilerplate by [Skele-CLI](https://github.com/rdegges/skele-cli)

## Contributing

Please read [CONTRIBUTING.md](https://github.com/jonluca/Anubis/blob/master/CONTRIBUTING.md) for details on our code of
conduct, and the process for submitting pull requests to us.

## Authors

* **JonLuca DeCaro** - *Initial work* - [Anubis](https://github.com/Anubis)

See also the list of [contributors](https://github.com/jonluca/Anubis/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [/r/netsec](https://reddit.com/r/netsec)

* [BitQuark for the most common subdomains](https://github.com/bitquark/dnspop/tree/master/results)

