from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
import sys

blockSize = 16
key = get_random_bytes(blockSize)
iv = get_random_bytes(blockSize)
cipher = AES.new(key, AES.MODE_ECB)

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def encrypt(inputText):
  encryptedText = b""
  pos = blockSize
  prevCt = iv
  while(pos <= len(inputText)):
    pt = bytes(inputText[pos - blockSize : pos], 'utf-8')
    ptXORed = byte_xor(pt, prevCt)
    ct = cipher.encrypt(ptXORed)
    encryptedText += ct
    prevCt = ct
    pos += blockSize

  remainingUnEncrypted = len(inputText) % blockSize
  lastIndex = len(inputText) - 1
  remainingPt = bytes(inputText[lastIndex - remainingUnEncrypted : ], 'utf-8')

  #Add appropriate padding
  num = blockSize - remainingUnEncrypted if blockSize - remainingUnEncrypted > 0 else blockSize
  remainingPt += bytes([num])*num
  ptXORed = byte_xor(remainingPt, prevCt)
  ct = cipher.encrypt(ptXORed)
  encryptedText += ct
  return encryptedText

def urlEncodeInput():
  urlEncodedString = ""
  for c in sys.argv[1]:
    if(c == "=" or c == ";"):
      urlEncodedString += "%" + str(hex(ord(c)))[2:]
    else:
      urlEncodedString += c
  return urlEncodedString

def submit():
  if(len(sys.argv) == 1):
    print("Error: Please enter text to encrypt as command line argument")
    return
  ptString = "userid=456;userdata=" + urlEncodeInput() + ";session-id=31337"
  return encrypt(ptString)

def decryptText(ctText):
  decryptedText = b""
  pos = blockSize
  prevCt = iv
  while(pos <= len(ctText)): 
    ct = ctText[pos - blockSize : pos]
    pt = cipher.decrypt(ct)
    pt = byte_xor(pt, prevCt)
    decryptedText += pt
    prevCt = ct
    pos += blockSize

  numPadding = decryptedText[len(decryptedText) - 1]
  return decryptedText[ : len(decryptedText) - numPadding]

def verify(ct):
  decryptedText = decryptText(ct)
  print("Decrypted Text: ")
  print(decryptedText)
  print("\n")
  print("result from running verify(encrypted):")
  return b";admin=true;" == decryptedText[len(decryptedText) - len(";admin=true;"):]


originalString = "userid=456;userdata=" + urlEncodeInput() + ";session-id=31337"
replaceString=";;;;;admin=true;"
print("Original Text:")
print(originalString)
print("\n")
encrypted = submit()
print("Original Encrypted Text:")
print(encrypted)
print("\n")
offsetInOriginal = len(originalString) - len(replaceString)
offsetInEncrypted = len(encrypted) - 48

for c in replaceString:
  originalBytes = originalString[offsetInOriginal].encode("utf-8")
  replaceBytes = c.encode("utf-8")
  encryptedBytes = bytes([encrypted[offsetInEncrypted]])
  encrypted = encrypted[:offsetInEncrypted] + byte_xor(replaceBytes, byte_xor(encryptedBytes, originalBytes)) + encrypted[offsetInEncrypted + 1:]
  offsetInOriginal += 1
  offsetInEncrypted += 1
print("Encrypted Text after Byte Flip Attack:")
print(encrypted)
print("\n")
print(verify(encrypted))



