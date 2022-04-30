import boto3
import cryptography
import base64
from cryptography.fernet import Fernet
import os
import json

s3 = boto3.resource('s3')

def create_key(id):
    kms_client = boto3.client('kms', region_name='eu-central-1')
    response = kms_client.generate_data_key(KeyId=id, KeySpec='AES_256')
    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])

def encrypt_file(file, id):
  f = open(file)
  file_contents = f.read()
  data_key, data_key_plaintext = create_key(id)
  filen = Fernet(data_key_plaintext)  
  file_contents_encrypted = filen.encrypt(bytes((file_contents), 'utf-8'))
  f = open(file, "w")
  f.write(str(file_contents_encrypted))

def decrypt_key(encrypted_key):
    kms_client = boto3.client('kms')
    response = kms_client.decrypt(CiphertextBlob=encrypted_key)
    return base64.b64encode((response['Plaintext']))

# decryption key needs work
# def decrypt_file(file, encrypted_key):
#   f = open(file)
#    file_contents = f.read()
#   data_key = decrypt_key(encrypted_key)
#   filen = Fernet(data_key)
#   file_contents_decrypted = filen.decrypt(bytes((file_contents), 'utf-8'))
#   f.write(file_contents_decrypted)

os.chdir("C:\\Users\\andre\\Documents\\Python personal\\python-encryption")
create_key('arn:aws:kms:eu-central-1:329080927726:key/0fc53ee3-ea51-4afe-aa34-170dfc351bcf')
encrypt_file("test.txt", 'arn:aws:kms:eu-central-1:329080927726:key/0fc53ee3-ea51-4afe-aa34-170dfc351bcf' )
decrypt_key(create_key('arn:aws:kms:eu-central-1:329080927726:key/0fc53ee3-ea51-4afe-aa34-170dfc351bcf')[0])
# decrypt_file('test.txt', create_key('arn:aws:kms:eu-central-1:329080927726:key/0fc53ee3-ea51-4afe-aa34-170dfc351bcf')[0])