import requests

IP = 'http://13.126.93.66:8080/'

print(requests.get(IP).json())