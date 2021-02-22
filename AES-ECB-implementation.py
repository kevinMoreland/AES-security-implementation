from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#Setup cryptography variables
fileName = "cp-logo.bmp"
encryptFileName = "cipher.bmp"
blockSize = 16
key = get_random_bytes(blockSize)
cipher = AES.new(key, AES.MODE_ECB)


#Encryption
f = open(fileName, "rb")  
encryptF = open(encryptFileName, "wb")

#Add in the bmp header unmodified
headerSize = 34
header = f.read(headerSize)
encryptF.write(header)

#Encrypt the remainder of the file after the header
byte = f.read(blockSize)
lastByte = byte
while(byte):
  lastByte = byte
  if(len(byte) == blockSize):
    encryptF.write(cipher.encrypt(byte))
  byte = f.read(blockSize)

num = blockSize - len(lastByte) if blockSize - len(lastByte) > 0 else blockSize
lastByte += bytes([num])*num
encryptF.write(cipher.encrypt(lastByte))
encryptF.close()

#Decryption
decryptFileName = "decryptedFile.bmp"
encryptedFile = open(encryptFileName, "rb")

decryptF = open(decryptFileName, "wb")
readFileHeader = encryptedFile.read(headerSize)
decryptF.write(readFileHeader)

byte = encryptedFile.read(16)
while(byte):    
  decryptF.write(cipher.decrypt(byte))
  byte = encryptedFile.read(16)
decryptF.close()



