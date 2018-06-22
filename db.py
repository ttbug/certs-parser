#coding=utf-8
'''
store certificate in mongodb
'''

import pymongo
from pymongo.errors import DuplicateKeyError

client = pymongo.MongoClient(host='localhost', port=27017)
db = client['https']
collections = db['certs']

def insert_data(data):
    try:
        collections.insert(data)
        print 'Insert to mongodb success!'
    except DuplicateKeyError:
        print 'Duplicate host'
    else:
        pass
