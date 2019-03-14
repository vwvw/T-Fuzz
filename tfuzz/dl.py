from bs4 import BeautifulSoup

import requests
url = "https://people.sc.fsu.edu/~jburkardt/data/png/png.html"
r  = requests.get(url)
data = r.text
soup = BeautifulSoup(data)

for link in soup.find_all('a'):
    href = link.get("href")
    if href is not None and href.endswith(".png"):

       print(link.get('href'))
       r = requests.get('https://people.sc.fsu.edu/~jburkardt/data/png/' + link.get("href"))
       open(link.get('href'), 'wb').write(r.content)
