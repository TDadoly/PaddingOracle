#!usr/bin/env python3

from oracle import encrypt, oracle, BLOCK_SIZE

# utility method to split real ciphertext into a list of blocks
def blockify(ciphertext):

    # calculate number of blocks
    num_blocks = len(ciphertext)/16

    # make list of empty lists
    blocks = [[]] * num_blocks

    # break ciphertext into blocks
    for i in range(num_blocks):
        blocks[i] = ciphertext[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]

    return blocks

# utlity method to query oracle
# takes fakeciphertext block and real ciphertext block and combines them
# queries oracle, returns true if oracle returns true
def query_oracle(fake, realblock):

    # make a string that contains the fakeciphertext and the real ciphertext block
    # this is C1'C2
    # this is a string with 32 characters
    totalciphertext = ''.join(fake) + realblock

    return(oracle(totalciphertext))

def attack(ciphertext):

    # 1
    # blockify ciphertext to be [IV,C1,C2]
    iv,c1,c2 = blockify(ciphertext)
    block_length = 16

    # initialize fakeciphertext and plaintext to 16 char lists
    fakeciphertext = ['0'] * block_length   # c1'
    plaintext = ['0'] * block_length  # p2
    print("fakeciphertext: " + str(fakeciphertext))
    print("plaintext: " + str(plaintext))
    
    # loop through each character front to back
    for i, c in enumerate(fakeciphertext):
        print("LoopA#: " + str(i))
        index = block_length - i - 1
        if i == 3: break
        # try every value in range 256
        for v in range(256):
            # Set the current character of fakeciphertext to v. This is C1'[c]
            fakeciphertext[index] = chr(v)
            # Query the oracle by passing it fakeciphertext and the block you want to decrypt. This query represents C1’C2 # If it returns true, continue decryption
            if query_oracle(fakeciphertext, c2):
                # A) I2 = C1' xor P2'
                i2 = ord(fakeciphertext[index]) ^ (i + 1)
                # B) P2 =I2 xor C1 
                plaintext[index] = chr(i2 ^ ord(c1[index])) 
                # C) This is unfinished
                k = index
                while k < block_length:
                    # i2 = C1[k] ^ P2[k]
                    i2 = ord(c1[k]) ^ ord(plaintext[k])
                    # update fakeciphertext = i2 ^ P2'
                    fakeciphertext[k] = chr(i2 ^ (i + 1)) 
                    k += 1
                break

    # return our plaintext 
    return plaintext 



# test attack by encrypting a message and then calling attack method
def test_attack():

    message = "Sloths are incredibly awesome"
    output = attack(encrypt(message))
    print(output)
    
if __name__ == '__main__':
    test_attack()

