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
    # 1. Break ciphertext into blocks [IV,C1,C2]
    iv,c1,c2 = blockify(ciphertext)
    block_length = 16

    # 2. Initialize variables fakeciphertext (this is C1') and plaintext (this is P2) to be lists of 16 characters.
    fakeciphertext = ['0'] * block_length   # c1'
    plaintext = ['0'] * block_length  # p2
    
    # 3. For each character c in the block
    for i, c in enumerate(fakeciphertext):
        # (loop through the 16 characters going backwards)
        index = block_length - i - 1
        # Try every value in range 256
        for v in range(256):
            # Set the current character of fakeciphertext to v. This is C1'[c]
            fakeciphertext[index] = chr(v)
            # Query the oracle by passing it fakeciphertext and the block you want to decrypt. This query represents C1C2 
            #  If it returns true, continue decryption.
            #  If it returns false, continue to next v.
            if query_oracle(fakeciphertext, c2):
                # A) Compute the intermediate value
                # I2[c] = C1'[c] xor P2'[c] 
                i2 = ord(fakeciphertext[index]) ^ (i + 1)
                # Compute the value of the real PT character
                # B) P2[c] = I2[c] xor C1[c] 
                plaintext[index] = chr(i2 ^ ord(c1[index]))
                # C) Set up the next iteration
                # For every character k from the current character c to the last character
                k = index
                while k < block_length:
                    # Get the value of the real ciphertext. This is C1[k].
                    # I2[k] = C1[k] ^ P2[k]
                    i2 = ord(c1[k]) ^ ord(plaintext[k])
                    # Update fakeciphertext by computing
                    # C1'[k] = I2[k] ^ P2'[k]
                    fakeciphertext[k] = chr(i2 ^ i + 2) 
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

