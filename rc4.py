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
    #saltLength = 8

    #Formulate salt
    #salt = ''
    #for n in range(saltLength):
        #Use python built in RNG to get a random number and get ascii value for that num
        #This will be used for the salt
    #    salt += chr(random.randrange(256))
 
    #Send plaintext to rc4 algorithm to get ct
    #ct = rc4(data, sha1(key + salt).digest())
    ct = rc4(data, sha1(key).digest())

    #add that ct to the salt 
    #data = salt + ct
    data = ct

    #Encode the final output 
    data = encoding(data)

    return data

def decrypt(ct, key):
    """RC4 decryption of encoded data"""

    #Outline what encoding we want to use and the length of the salt
    decoding = base64.b64decode
    #saltLength = 8

    #Decode 
    data = decoding(ct)

    #Chop off the salf
    #salt = data[:saltLength]

    #decrypt the message
    #pt = rc4(data[saltLength:], sha1(key + salt).digest())
    pt = rc4(data, sha1(key).digest())

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

def parseArgs():
    """Parse through the args and return the options"""

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


    return toEncrypt, args.file, args.key



def authUser(username, password):
    """This function will authenticate the user based on credentials provided by the user"""

    #Hash the password for comparison
    encoding = base64.b64encode
    hashedPass = sha1(password).digest()
    hashedPass = encoding(hashedPass)

    accessList = readFile("accessList")

    users, groups, hashes = [], [], []

    for line in accessList:
        try:
            line = line.split(":")
            users.append(line[0])
            groups.append(line[1])
            hashes.append(line[2])
        except IndexError:
            pass

    #Compare user input to what is in the Access list
    i, authenticated, group = 0, False, ''
    while i < len(users):
        if users[i] == username:
            if hashedPass == hashes[i].rstrip():
                authenticated, group = True, groups[i]
                break
        i += 1

    return authenticated, group

def performOperation(toEncrypt, _file, key):
    """Perform the operation requested by the user"""

    #if no file is provided, get the data and perform operation
    if _file is None:
        data = raw_input('Data you would like encrypt/decrypt: ')

        #if no key provided, get the key
        if key is None:
            key = raw_input('Enter the key: ')

        #Print out ouput file not being used
        if toEncrypt is True:
            ct = encrypt(data, key)
            print ct
        else:
            pt = decrypt(data, key)
            print pt
    else:
        #Get key if not provided
        if key is None:
            print "[WARNING] If incorrect key entered while decrypting, you will lose the original file."
            key = raw_input('Enter the key: ')
        
        #read the file
        contents = readFile(_file)

        #If encryption is selected, send fileto be encrypted else, have it decrypted
        if toEncrypt is True:
            encContents = []
            for line in contents:     
                encContents.append(encrypt(line.rstrip(), key) + '\n')

            #Write encypted contents back to file
            writeFile(_file, encContents)

        else:
            decContents = []
            for line in contents:     
                decContents.append(decrypt(line.rstrip(), key) + '\n')

            writeFile(_file, decContents)

def valOperation(group, toEncrypt):
    """Validate the user is able to perform the action requested"""

    valid = False

    #Automatically validate administrator
    if int(group) == 0:
        valid = True

    #Regular users can only decrypt 
    if int(group) == 1:
        if toEncrypt == False:
            valid = True

    #Attackers can only encrypt
    if int(group) == 2:
        if toEncrypt == True:
            valid = True

    return valid

    
def main():

    #Validate user
    username = raw_input("Enter your username: ")
    password = raw_input("Enter your password: ")

    authenticated, group = authUser(username, password)

    if authenticated is False:
        print "The password for " + username + " was incorrect or the user does not exists. Please try again."
        exit()

    #Parse args
    toEncrypt, _file, key = parseArgs()

    #Validate the user is in a group that is allowed to perform the action requested
    if valOperation(group, toEncrypt) == True:
        #Perform the operation requested
        performOperation(toEncrypt, _file, key)
    else:
        print username + " does not have the permission to perform the requested operation."
        exit()
    


if __name__ == '__main__':
    main()


