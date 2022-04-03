import hashlib
import json

import requests

s = requests.Session()
server_host = 'http://10.0.1.5:8000'

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded'
}
payload = {
    # 'grant_type': '',
    'username': 'test',
    'password': 'p@ssw0rd',
    # 'scope': '',
    # 'client_id': '',
    # 'client_secret': ''
}
print("Server: --> Authenticate and get JWT token")

user_login = s.post(f"{server_host}/login/token", data=payload, headers=headers)
user = user_login.json()
token = user['access_token']

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'Authentication': f"Bearer {token}"
}

print("Server: --> Retreive all devices stored")

retreive_devices = s.get(f"{server_host}/devices/all/", headers=headers)

for device in retreive_devices.json():
    print(device)
    yesno = 's' if device['secure'] else ''
    plc_host = f"http{yesno}://{device['ip_address']}"
   # auth_url = "http://192.168.246.31/sdcard/cpt/app/signin.php?user[name]=admin"
    auth_url = f"{plc_host}/sdcard/cpt/app/signin.php?user[name]={device['username']}"
    login_url = f'{plc_host}/sdcard/cpt/app/signin.php'

    print(auth_url)

    sh = requests.Session()

    print("PLC: --> Authenticate and get JWT token")

    headers = {'X-Requested-With': 'XMLHttpRequest'}

    resp = sh.get(auth_url, headers=headers)
    print(resp.status_code)
    print('Retrieved auth token', resp.json()['authToken'])
    print('--')
    sections = resp.json()['authToken'].split('_')

    token1 = sections[0]
    token2 = sections[1]

    str = 'hellocpt' + token1
    hex1 = hashlib.new("sha1", str.encode('utf-8'))

    str2 = hex1.hexdigest() + token2
    hex2 = hashlib.new('sha1', str2.encode('utf-8'))
    latest = hex2.hexdigest()

    print('---')
    print('Calculated this sha1', latest)
    #
    json_payload = {
        'user[name]': 'admin',
        'user[authHash]': latest
    }

    post = sh.post(login_url, data=json_payload, headers=headers)
    print(post.status_code)
    print(post.text)

    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authentication': f"Bearer {token}"
    }

    print(f"Server: --> Retreive all folders by device {device['name']}")

    retreive_folders_by_device = s.get(f"{server_host}/folders/by_device/{device['id']}/", headers=headers)

    for folder in retreive_folders_by_device.json():
        print(folder)

