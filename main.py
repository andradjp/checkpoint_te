#!/usr/bin/python

'''
Version: 0.1
Data: 05/10/2022
email: gseg@novobanco.pt
'''

from lib import te_checkpoint
import sys

if __name__ == '__main__':
    t = te_checkpoint.ThreatPrevention()
    file_hash = t.upload_file(sys.argv[1])
    t.query_hash(file_hash)
    
