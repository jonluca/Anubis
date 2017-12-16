import requests


# TODO - implement searching google, bing, yahoo, baidu, and ask
def search_google(self):
  print("Searching Google")
  base_url = "https://google.com/search?q="
  append = "&hl=en-US&start="
  query = "site:" + self.options["TARGET"]
  for domain in self.domains:
    query += " -" + domain
  page_num = 0
  url = base_url + query + append + str(page_num)
  res = requests.get(url)
