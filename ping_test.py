import urllib.request, urllib.parse
try:
    data = urllib.parse.urlencode({'username':'admin','password':'admin123'}).encode()
    req = urllib.request.Request('http://127.0.0.1:5000/login', data=data, method='POST')
    with urllib.request.urlopen(req, timeout=5) as r:
        print('status', r.status)
        print('headers:', r.getheaders())
        print('body:', r.read().decode())
except Exception as e:
    print('ERROR', e)
