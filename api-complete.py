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
        folderp = folder['name']
        
        call_path_url = f'{http}://{ip_address}/sdcard/cpt/app/data_api.php?url=/app/objects/{folder}/*'  # Ad_out'
        req = sh.get(call_path_url, headers=headers3)
        data = req.json()['response']['data'][0]

        for da in data:
            check = ""
            print(f"Server: --> Retreive all folders by device {device['name']}")

            retreive_folders_by_device = s.get(f"{server_host}/paths/read/{folder['id']}/{da['path']}/{da['type']}/", headers=headers)
            
            
            if Path.objects.filter(folder=folder_obj, name=da['path'], type_path=da['type']).count() == 0:
                path_obj = Path.objects.create(folder=folder_obj, name=da['path'], type_path=da['type'])
            else:
                path_obj = Path.objects.filter(folder=folder_obj, name=da['path'], type_path=da['type'])[0]

            gen_uuid = uuid.uuid4()
            for child in da['slots']:
                if child['name'] == 'out':
                    Slot.objects.create(uuid=gen_uuid, path=path_obj, name=child['name'], slotType=child['slotType'], type=child['type'], value=child['value'])

        

