#!/usr/bin/env python


import random
import base64
import argparse
from hashlib import sha1



def rc4(data, key):
    """RC4 algorithm"""

    #create S Box and initialize values
    sBox = [i for i in xrange(256)]

    x = 0
    #Create a random number for one side of the equation and then swap them with the initial (the otehr side)
    for i in range(256):
        x = (x + sBox[i] + ord(key[i % len(key)])) % 256
        sBox[i], sBox[x] = sBox[x], sBox[i]
    x = y = 0

    msg = []
    #PRGA
    for char in data:
        x = (x + 1) % 256
        y = (y + sBox[x]) % 256
        sBox[x], sBox[y] = sBox[y], sBox[x]
        msg.append(chr(ord(char) ^ sBox[(sBox[x] + sBox[y]) % 256]))

    return ''.join(msg)

def encrypt(data, key):
    """RC4 encryption with random salt and final encoding"""

    #Outline what encoding we want to use and the length of the salt
    encoding = base64.b64encode
    saltLength = 8

    #Formulate salt
    salt = ''
    for n in range(saltLength):
        #Use python built in RNG to get a random number and get ascii value for that num
        #This will be used for the salt
        salt += chr(random.randrange(256))
 
    #Send plaintext to rc4 algorithm to get ct
    ct = rc4(data, sha1(key + salt).digest())

    #add that ct to the salt 
    data = salt + ct

    #Encode the final output 
    data = encoding(data)

    return data

def decrypt(ct, key):
    """RC4 decryption of encoded data"""

    #Outline what encoding we want to use and the length of the salt
    decoding = base64.b64decode
    saltLength = 8

    #Decode 
    data = decoding(ct)

    #Chop off the salf
    salt = data[:saltLength]

    #decrypt the message
    pt = rc4(data[saltLength:], sha1(key + salt).digest())

    return pt

def readFile(_file):
    """If the user chooses to enter a file this function will return a list of the contents"""

    contents = []
    with open(_file, 'r') as f:
        contents = f.readlines()
        for line in contents:
            line = line.rstrip()
    f.close()
    return contents 

def writeFile(_file, contents):
    """Write to file the new contents"""

    with open(_file, 'wb') as f:
        for line in contents:
            f.write(line)
        f.close()

def main():
    #Check to see if any args were provided. Right now the only arg would be a csv.
    parser = argparse.ArgumentParser(description="Fully functional encryption/decryption tool using the RC4 algorithm.")
    parser.add_argument("-f", "--file",  action="store", dest="file", help="If you wish to encrypt/decrypt a whole file.", required=False)
    parser.add_argument("-e", "--encrypt",  action="store_true",  help="Utilize the encryption cipher.", required=False)
    parser.add_argument("-d", "--decrypt",  action="store_true",  help="Utilize the de cipher.", required=False)
    parser.add_argument("-k", "--key",  action="store", dest="key", help="Encryption/decryption key.", required=False)

    #Get grab users options
    args = parser.parse_args()

    #Validate that either -d or -e are selected
    if args.encrypt is False and args.decrypt is False:
        print "[ERROR] User must select -d (decrypt) or -e (encrypt)."
        exit()

    #Find out if encryption of decryption is being used
    toEncrypt = True
    if args.encrypt is False:
        toEncrypt = False

    #if no file is provided, get the data
    if args.file is None:
        data = raw_input('Data you would like encrypt/decrypt: ')

        #if no key provided, get the key
        if args.key is None:
            key = raw_input('Enter the key: ')
        else:
            key = args.key
    
    else:
        #Get key if not provided
        if args.key is None:
            print "[WARNING] If incorrect key entered while decrypting, you will lose the original file."
            key = raw_input('Enter the key: ')
        else:
            key = args.key
        
        #read the file
        contents = readFile(args.file)

        #If encryption is selected, send fileto be encrypted else, have it decrypted
        if toEncrypt is True:
            encContents = []
            for line in contents:     
                encContents.append(encrypt(line.rstrip(), key) + '\n')

            #Write encypted contents back to file
            writeFile(args.file, encContents)
        else:
            decContents = []
            for line in contents:     
                decContents.append(decrypt(line.rstrip(), key) + '\n')
            
            writeFile(args.file, decContents)

    #Print out ouput file not being used
    if toEncrypt is True:
        ct = encrypt(data, key)
        print ct
    else:
        pt = decrypt(data,key)
        print pt

if __name__ == '__main__':
    main()



