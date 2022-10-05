#!/usr/bin/python
'''
Version: 0.1
Data: 05/10/2022
email: contact@joaopaulo.it
'''
import requests
import json
import time
import os
import lib.hashmd5 as hashmd5
from config import config


class ThreatPrevention:

    #Define the request header
    def __init__(self):
        print('[+]---Exploração de Segurança---')
        print('[+]Starting script!')
        print('[+]Server: {}'.format(config.SERVER))
        print('[+]Using token {}'.format(config.API_TOKEN))
        self.url = 'https://{}/tecloud/api/v1/file/'.format(config.SERVER)
        self.headers = {'Authorization': '{}'.format(config.API_TOKEN)}

    #Query a hash file
    def query_hash(self, hash):
        #build the request body
        request = json.dumps({'request': {
            'md5': '{}'.format(hash),
            'features': ['av', 'te'],
            'te': {
                'reports': ['json']
            }
        }
        })
        try:
            print('[+]Analyzing the file...')
            response = requests.post(self.url + 'query', headers=self.headers, data=request)
            while response.json()['response']['av']['status']['code'] and response.json()['response']['te']['status']['code'] not in [1001,1006,1007]:
                response = requests.post(self.url + 'query', headers=self.headers, data=request)
                time.sleep(10)
            print('[+]--AntiMalware--')
            print('[-]Confidence: {}'.format(response.json()['response']['av']['malware_info']['confidence']))
            print('[-]Malware Family: {}'.format(response.json()['response']['av']['malware_info']['malware_family']))
            print('[-]Malware Type: {}'.format(response.json()['response']['av']['malware_info']['malware_type']))
            print('[-]Severity: {}'.format(response.json()['response']['av']['malware_info']['severity']))
            print('[-]Signature Name: {}'.format(response.json()['response']['av']['malware_info']['signature_name']))
            print('[+]--Threat Emulation--')
            print('[-]Combined Verdict: {}'.format(response.json()['response']['te']['combined_verdict']))
        except ConnectionError as c:
            print('[!]Connection error: ', c)

    #Verify usage quota
    def query_quota(self):
        print('---Query Quota---')
        try:
            response = requests.get(self.url + 'quota', headers=self.headers)
            print('[-]Action: {}'.format(response.json()['response'][0]
                                      ['action']))
            print('[-]Assigned quota for hour: {}'.format(response.json()['response'][0]
                                                       ['assigned_quota_hour']))
            print('[-]Assigned quota for month: {}'.format(response.json()['response'][0]
                                                        ['assigned_quota_month']))
            print('[-]Cloud hourly quota usage for ID: {}'.format(response.json()['response'][0]
                                                               ['cloud_hourly_quota_usage_for_quota_id']))
            print('[-]Cloud hourly quota usage for this gateway: {}'.format(response.json()['response'][0]
                                                                         ['cloud_hourly_quota_usage_for_this_gw']))
            print('[-]Cloud monthly period start: {}'.format(time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(
                response.json()['response'][0]['cloud_monthly_quota_period_start'])))))
            print('[-]Cloud monthly quota usage for quota ID: {}'.format(response.json()['response'][0]
                                                                      ['cloud_monthly_quota_usage_for_quota_id']))
            print('[-]Cloud monthly quota usage for this gateway: {}'.format(response.json()['response'][0]
                                                                      ['cloud_monthly_quota_usage_for_this_gw']))
            print('[-]Cloud quota max allow to exceed percentage: {}'.format(response.json()['response'][0]
                                                                          ['cloud_quota_max_allow_to_exceed_percentage']))
            print('[-]Hourly exceeded quota: {}'.format(response.json()['response'][0]
                                                     ['hourly_exceeded_quota']))
            print('[-]Hourly quota next reset: {}'.format(time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(
                response.json()['response'][0]['hourly_quota_next_reset'])))))
            print('[-]Monthly exceeded quota: {}'.format(response.json()['response'][0]
                                                     ['monthly_exceeded_quota']))
            print('[-]Monthly quota next reset: {}'.format(time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(
                response.json()['response'][0]['monthly_quota_next_reset'])))))
            print('[-]Pod time gmt: {}'.format(time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(
                response.json()['response'][0]['pod_time_gmt'])))))
            print('[-]Quota expiration: {}'.format(time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(
                response.json()['response'][0]['quota_expiration'])))))
            print('[-]Quota ID: {}'.format(response.json()['response'][0]
                                                ['quota_id']))
            print('[-]Remain quota hour: {}'.format(response.json()['response'][0]
                                                ['remain_quota_hour']))
            print('[-]Remain quota month: {}'.format(response.json()['response'][0]
                                                 ['remain_quota_month']))
            print('---Finish Quota---')
        except ConnectionError as c:
            print('[!]Connection error: ', c)

    #upload file to test
    def upload_file(self, file):
        data = json.dumps({'request': [{
            'md5': hashmd5.file_hash(file),
            'file_name': os.path.abspath(file),
            'features': ['te','av'],
            'te': {
                'reports': ['xml', 'summary'],
                'images': 
                    [{'id': 'e50e99f3-5963-4573-af9e-e3f4750b55e2',
                     'revision': 1}]
            },
            "extraction": {
                "method": "clean"
                            }
        }]})
        curr_file = {
            'request': (None, data, 'application/json'),
            'file': (file, open(os.path.abspath(file), 'rb'), 'multipart/form-data')
        }

        try:
            print('[+]Uploading...')
            response = requests.post(self.url + 'upload', headers=self.headers, files=curr_file)
            print('[+]Upload successful!')
            print('[-]File name: {}'.format(response.json()['response']['file_name']))
            print('[-]MD5: {}'.format(response.json()['response']['md5']))
            print('[-]SHA1: {}'.format(response.json()['response']['sha1']))
            print('[-]SHA256: {}'.format(response.json()['response']['sha256']))
            return (response.json()['response']['md5'])
        except ConnectionError as c:
            print('[!]Connection error: ', c)

    def download(self, id):
        response = requests.post(self.url+'download?id={}'.format(id), headers=self.headers)
        print(response.content)

