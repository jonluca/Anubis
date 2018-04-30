import requests

headers = {
    'dnt': '1',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,it;q=0.8',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36',
    'accept': 'application/json, text/plain, */*',
    'referer': 'https://transparencyreport.google.com/https/certificates?cert_search_auth=&cert_search_cert=&cert_search=include_expired:true;include_subdomains:true;domain:jonlu.ca&lu=cert_search',
    'authority': 'transparencyreport.google.com',
    'cookie': 'CONSENT=YES+US.en+20160626-17-1; S=billing-ui-v3=byGO2FQ0oKX4524MCFVKC53gA1oZPF_Q:billing-ui-v3-efe=byGO2FQ0oKX4524MCFVKC53gA1oZPF_Q; SID=DQaIfBKBTPfGxQ5f6fnTJuysMXmk4Gnv_dX8qe-92ZzfhScpoksqAhEH8O8V54xMbB75yw.; HSID=Ai0jlX1Fbrk9-WBBZ; SSID=AUbFycs4aZiC7LcHk; APISID=qEYnfH7NU0FkHRhF/A4qbY0VAokfGqeYRg; SAPISID=s6JI2nV3vfOZ9fx2/A8bEhxnk4rU15crNL; NID=129=mSf1NSS7lnln2Ef5bOlBVYHsAjDrSG2qPo7GVpL2WFchFhbU6q_q8M9mjklAZyaYmMSP87tA1-SDXDVJ8M9ZXUHSQ0bdo9XLs7kIEcpPwNYSIaQHh-BzvlBv3_zYVHmzHPcS_AsA5IE0mzsJgFytBw5h1Ek-nOQxA88mAdakqqC6N3Jewbm3lNpLWV4UmLCTo5Ow43rSjKAiZAbmGncJ2mmK7aI0Lc-hl10fA_oz5NzpAr_24RV033lx6ci2AMTXRnbv_8AvedvXY5AobGJx29L7eMPTXjt8ltNYtZsM51A; 1P_JAR=2018-4-27-22; SIDCC=AEfoLeYyzxNxkt_myLHitnqasNjc4fzTlDIngeyfhgIBAIF2qUGfso82YIjndIgaMydjWRNY10zY',
    'x-client-data': 'CKy1yQEIlLbJAQiitskBCMS2yQEIqZ3KAQioo8oBGJKjygE=',
}

params = (
    ('include_expired', 'true'),
    ('include_subdomains', 'true'),
    ('domain', 'jonlu.ca'),
)

response = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch', headers=headers, params=params)

#NB. Original query string below. It seems impossible to parse and
#reproduce query strings 100% accurately so the one below is given
#in case the reproduced version is not "correct".
# response = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=jonlu.ca', headers=headers)
