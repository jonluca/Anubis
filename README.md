# Anubis

            d8888                   888      d8b
           d88888                   888      Y8P
          d88P888                   888
         d88P 888 88888b.  888  888 88888b.  888 .d8888b
        d88P  888 888 "88b 888  888 888 "88b 888 88K
       d88P   888 888  888 888  888 888  888 888 "Y8888b.
      d8888888888 888  888 Y88b 888 888 d88P 888      X88
     d88P     888 888  888  "Y88888 88888P"  888  88888P'

Welcome to Anubis, a subdomain enumerator and information gathering tool.

## Requirements

``pip install -r requirements``

* Python 3.6
* Nmap

## Usage

    Usage:
      anubis -t TARGET [-o FILENAME] [--with-nmap] [-iv]
      anubis -h
      anubis --version
      
    Options:
      -h --help               show this help message and exit
      -t --target             set target
      --with-nmap             perform an nmap service/script scan
      -o --output             save to filename
      -i --additional-info    show additional information about the host from Shodan (requires API key)
      --version               show version and exit
      -v --verbose            print debug info/full info dumps
    
    Help:
      For help using this tool, please open an issue on the Github repository:
      https://github.com/jonluca/anubis
      
## Sample Output

```anubis -t reddit.com --with-nmap -o out.txt -i``` 

```
        d8888                   888      d8b
       d88888                   888      Y8P
      d88P888                   888
     d88P 888 88888b.  888  888 88888b.  888 .d8888b
    d88P  888 888 "88b 888  888 888 "88b 888 88K
   d88P   888 888  888 888  888 888  888 888 "Y8888b.
  d8888888888 888  888 Y88b 888 888 d88P 888      X88
 d88P     888 888  888  "Y88888 88888P"  888  88888P'
	
Searching for subdomains for 151.101.1.140
Server Location: San Francisco US - 94107
ISP: Fastly
Starting nmap scan (options -nPn -sV -sC
Host : 151.101.1.140 ()
----------
Protocol: tcp
port: 53	state: open
port: 80	state: open
	service: Varnish
port: 443	state: open
	service: Varnish
	ssl-cert:
	 Subject: commonName=*.reddit.com/organizationName=Reddit Inc./stateOrProvinceName=California/countryName=US
	 Subject Alternative Name: DNS:*.reddit.com, DNS:reddit.com, DNS:*.redditmedia.com, DNS:engine.a.redditmedia.com, DNS:redditmedia.com, DNS:*.redd.it, DNS:redd.it, DNS:www.redditstatic.com, DNS:imgless.reddituploads.com, DNS:i.reddituploads.com, DNS:*.thumbs.redditmedia.com
	 Not valid before: 2015-08-17T00:00:00
	 Not valid after:  2018-08-21T12:00:00
Found 136 domains
----------------
imgless.reddituploads.com
ca.reddit.com
http://re.reddit.com
roosterteeth.reddit.com
*.reddit.com
www.reddit.com
ss.reddit.com
us.reddit.com
...
```

Additionally, it would write out to a file called "out.txt" in the directory in which it was called.


## Credits

CLI Boilerplate by [Skele-CLI](https://github.com/rdegges/skele-cli)