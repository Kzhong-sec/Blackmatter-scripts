import time

import requests

ALGORITHM = 'add_ror13'


def resolve_api_hash(hash: int, algorithm: str = ALGORITHM, xor: int = None):
    if xor:
        xor = str(xor)
        hashdb_api = f'https://hashdb.openanalysis.net/hash/{algorithm}/{hash}/{xor}'
    else:
        hashdb_api = f'https://hashdb.openanalysis.net/hash/{algorithm}/{hash}'
    
        
    while True:
        response = requests.get(hashdb_api)
        if response.status_code == 429:
            print("Getting rate limited")
            time.sleep(60)
            continue
        else:
            data = response.json()
        

        string = None
        hashes = data.get('hashes')
        if hashes:
            first_hash = hashes[0]
            string_data = first_hash.get('string')
            if string_data:
                string = string_data.get('string')
        return string
