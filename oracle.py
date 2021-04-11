#!usr/bin/env python3
from Crypto.Cipher import AES
from Crypto import Random

# set the key length for AES
KEY_LENGTH = 16

# this is also 16
BLOCK_SIZE = AES.block_size

# make a random number generator and generate a key
generator = Random.new()
key = generator.read(KEY_LENGTH)

# method to add padding to a plaintext
def add_padding(plaintext):

    # figure out how much padding we need
    pad_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)

    # actually create the padding
    # chr converts int to unicode
    padding = chr(pad_length) * pad_length

    # concatenate padding with plaintext
    padded_plain = plaintext + padding 

    return padded_plain

# method to check if a plaintext is padded correctly
def check_padding(plaintext):

    # inspect the last character to determine padding length
    # ord converts from unicode to number
    pad_length = ord(plaintext[-1])

    # check if there is any padding
    if pad_length < 1 or pad_length > BLOCK_SIZE: 
       return False 
    
    # iterate through ciphertext
    for i in range(1,pad_length):

        # starting looking at characters from end
        # if character doesn't correspond to pad_length, padding is bad  
        if ord(plaintext[-i-1]) != pad_length:
            
            return False

    # otherwise, padding is correct
    return True

# method to encrypt a plaintext with AES using CBC mode
def encrypt(plaintext):

    # make a random IV
    iv = generator.read(AES.block_size)

    # initialize CBC mode with iv and key
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # pad the plaintext
    padded_plain = add_padding(plaintext)

    # perform the encryption 
    ciphertext  = cipher.encrypt(padded_plain)

    # append the iv to the ciphertext and return
    # note that the first block of the ciphertext will now be the iv
    
    return iv + ciphertext

# method to decrypt a ciphertext with AES using CBC mode
def decrypt(ciphertext):

    # extract the iv from the ciphertext
    iv = ciphertext[:BLOCK_SIZE];

    # initialize CBC mode with iv and key
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # perform the decryption
    # don't try to decrypt the IV
    plaintext = cipher.decrypt(ciphertext[BLOCK_SIZE:])

    return plaintext 

# the actual padding oracle which decrypts ciphertext 
# returns True if padding is good, False otherwise
def oracle(ciphertext):

    # call decrypt method
    plaintext = decrypt(ciphertext)

    # return if padding is good
    return(check_padding(plaintext))


# main method
if __name__ == '__main__':
    
    plaintext = "sloths are incredibly awesome"
    ciphertext = encrypt(plaintext)

    print("plaintext: ", plaintext)

    print("decrypted message:", decrypt(ciphertext))
    
