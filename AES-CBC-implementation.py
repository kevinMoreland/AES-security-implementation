from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode

fileName = "cp-logo.bmp"
encryptFileName = "CBCcipher.bmp"

blockSize = 16
key = get_random_bytes(blockSize)
iv = get_random_bytes(blockSize)
cipher = AES.new(key, AES.MODE_ECB)

f = open(fileName, "rb")  
encryptF = open(encryptFileName, "wb")

#Add in header, unmodified
headerSize = 34
header = f.read(headerSize)
encryptF.write(header)

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    
#Encrypt File
pt = f.read(blockSize)
prevCt = iv
lastByte = pt
while(pt):
  lastByte = pt
  if(len(pt) == blockSize):
    ptXORed = byte_xor(pt, prevCt)
    ct = cipher.encrypt(ptXORed)
    encryptF.write(ct)
    prevCt = ct
  pt = f.read(blockSize)

num = blockSize - len(lastByte) if blockSize - len(lastByte) > 0 else blockSize
lastByte += bytes([num])*num
ptXORed = byte_xor(lastByte, prevCt)
ct = cipher.encrypt(ptXORed)
encryptF.write(ct)
encryptF.close()

#Decrypt File
decryptFileName = "CBCdecryptedFile.bmp"
encryptedFile = open(encryptFileName, "rb")

decryptF = open(decryptFileName, "wb")
readFileHeader = encryptedFile.read(headerSize)
decryptF.write(readFileHeader)

byte = encryptedFile.read(16)
prevCt = iv
while(byte):   
  ctDecrypted = cipher.decrypt(byte)
  pt = byte_xor(ctDecrypted, prevCt)
  decryptF.write(pt)
  prevCt = byte
  byte = encryptedFile.read(16)

decryptF.close()




