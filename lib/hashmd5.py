#!/usr/bin/python
'''
Version: 0.1
Data: 05/10/2022
email: gseg@novobanco.pt
'''
from hashlib import md5

def file_hash(fname):
    hash_md5 = md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()