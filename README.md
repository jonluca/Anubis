# Anubis

            d8888                   888      d8b
           d88888                   888      Y8P
          d88P888                   888
         d88P 888 88888b.  888  888 88888b.  888 .d8888b
        d88P  888 888 "88b 888  888 888 "88b 888 88K
       d88P   888 888  888 888  888 888  888 888 "Y8888b.
      d8888888888 888  888 Y88b 888 888 d88P 888      X88
     d88P     888 888  888  "Y88888 88888P"  888  88888P'

Welcome to Anubis, a subdomain enumerator and information gathering tool. [Original Medium article release](https://medium.com/@jonluca/introducing-anubis-a-new-subdomain-enumerator-and-information-gathering-tool-d25b39ad98f2)

## Requirements

## Easy Install

`pip3 install anubis-netsec`

## More information

Note: If you have both __python3__ and __python2__ installed on your system, you might have to replace all instances of `pip` to `pip3` in the commands below.

``pip3 install  -r requirements.txt``

* Python **3.6**
* Nmap

If running on Linux distros, openssl and python dev will be required as well, witch `sudo apt-get install python3-pip python-dev libssl-dev`

## Installation

Please note Anubis is still in beta. 

`pip3 install -e .`

Will install it as  CLI program, most likely to `/usr/local/bin/anubis` on *nix machines.


## Usage

    Usage:
      anubis -t TARGET [-noispbdv] [-o FILENAME] [-w SCAN]
      anubis -h
      anubis --version
      
    Options:
      -h --help                         show this help message and exit
      -t --target                       set target
      -n --with-nmap                    perform an nmap service/script scan
      -o --output                       save to filename
      -i --additional-info              show additional information about the host from Shodan (requires API key)
      -s --ssl                          run an ssl scan and output cipher + chain info
      -p --ip                           outputs the resolved IPs for each subdomain, and a full list of unique ips
      -d --no-anubis-db                 don't send results to anubisdb
      -w --overwrite-nmap-scan          overwrite default nmap scan (default -nPn -sV -sC)
      -v --verbose                      print debug info and full request output
      --version                         show version and exit
      
    Help:
      For help using this tool, please open an issue on the Github repository:
      https://github.com/jonluca/anubis 
         
## About

Anubis collates data from a variety of sources, including HackerTarget, DNSDumpster, x509 certs, VirusTotal, Google, Pkey, and NetCraft.

Anubis also has a sister project, [AnubisDB](https://github.com/jonluca/Anubis-DB), which serves as a centralized repository of subdomains. Subdomains are *automatically* sent to AnubisDB - to disable this functionality, pass the `d` flag when running Anubis.
 
## Sample Output

### Basic

#### Simple Use Case

`anubis -tip  domain.com -o out.txt`

Set's target to `domain.com`, outputs additional information like server and ISP or server hosting provider, then attempts to resolve all URLs and outputs list of unique IPs. Finally, writes all results to out.txt.

#### Other

```anubis -t reddit.com``` 

```
Searching for subdomains for 151.101.129.140
Found 126 domains
----------------
aa.reddit.com
ss.reddit.com
qu.reddit.com
roosterteeth.reddit.com
http://dg.reddit.com
pp.reddit.com
i.reddit.com
http://www.reddit.com
di.reddit.com
bj.reddit.com
augustames.reddit.com
so.reddit.com
www.reddit.com
http://reddit.com
http://nj.reddit.com
space.reddit.com
api.reddit.com
... (truncated for readability)
```

`anubis -t reddit.com -ip` (equivalent to `anubis -t reddit.com --additional-info --ip`)

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
```anubis -t reddit.com --with-nmap -o temp.txt -is --overwrite-nmap-scan "-F -T5"``` 

```
Searching for subdomains for 151.101.129.140
Running SSL Scan
Available TLSv1.0 Ciphers:
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA
Available TLSv1.2 Ciphers:
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA
 * Certificate Information:
     Content
       SHA1 Fingerprint:                  f8d1965323111e86e6874aa93cc7c52969fb22bf
       Common Name:                       *.reddit.com
       Issuer:                            DigiCert SHA2 Secure Server CA
       Serial Number:                     11711178161886346105980166697563149367
       Not Before:                        2015-08-17 00:00:00
       Not After:                         2018-08-21 12:00:00
       Signature Algorithm:               sha256
       Public Key Algorithm:              RSA
       Key Size:                          2048
       Exponent:                          65537 (0x10001)
       DNS Subject Alternative Names:     ['*.reddit.com', 'reddit.com', '*.redditmedia.com', 'engine.a.redditmedia.com', 'redditmedia.com', '*.redd.it', 'redd.it', 'www.redditstatic.com', 'imgless.reddituploads.com', 'i.reddituploads.com', '*.thumbs.redditmedia.com']

     Trust
       Hostname Validation:               OK - Certificate matches reddit.com
       AOSP CA Store (7.0.0 r1):          OK - Certificate is trusted
       Apple CA Store (OS X 10.11.6):     OK - Certificate is trusted
       Java 7 CA Store (Update 79):       OK - Certificate is trusted
       Microsoft CA Store (09/2016):      OK - Certificate is trusted
       Mozilla CA Store (09/2016):        OK - Certificate is trusted
       Received Chain:                    *.reddit.com --> DigiCert SHA2 Secure Server CA
       Verified Chain:                    *.reddit.com --> DigiCert SHA2 Secure Server CA --> DigiCert Global Root CA
       Received Chain Contains Anchor:    OK - Anchor certificate not sent
       Received Chain Order:              OK - Order is valid
       Verified Chain contains SHA1:      OK - No SHA1-signed certificate in the verified certificate chain

     OCSP Stapling
       OCSP Response Status:              successful
       Validation w/ Mozilla Store:       OK - Response is trusted
       Responder Id:                      0F80611C823161D52F28E78D4638B42CE1C6D9E2
       Cert Status:                       good
       Cert Serial Number:                08CF7DA9B222C9D983C50D993F2F5437
       This Update:                       Dec 10 16:18:57 2017 GMT
       Next Update:                       Dec 17 15:33:57 2017 GMT
Server Location: San Francisco US - 94107
ISP: Fastly
Starting Nmap Scan
Host : 151.101.129.140 ()
----------
Protocol: tcp
port: 53	state: open
port: 80	state: open
port: 443	state: open
Found 126 domains
----------------
nd.reddit.com
askreddit.reddit.com
roosterteeth.reddit.com
qu.reddit.com
cp.reddit.com
mx02.reddit.com
nh.reddit.com
... (truncated for readability)
```

Additionally, it would write out to a file called "out.txt" in the directory in which it was called.


## Credits

* CLI Boilerplate by [Skele-CLI](https://github.com/rdegges/skele-cli)

* [sslyze](https://github.com/nabla-c0d3/sslyze)

* [/r/netsec](https://reddit.com/r/netsec)

* [BitQuark for the most common subdomains](https://github.com/bitquark/dnspop/tree/master/results)
