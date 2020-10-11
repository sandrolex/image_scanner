from registry import Registry


url = 'https://lobs.local'
user = 'testuser'
passwd = 'testpassword'

r = Registry(url, user, passwd)
r.getTags(1)
print(r._tags)
