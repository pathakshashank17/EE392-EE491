import random
import AES as AES

# Define Plaintext
P = "{T:32C, SOC:91%}"
# Define AES-128 bit encryption key
K = "42b836d070adb205"
# Define additional data greater than 128-bits
A = "4f77dc137ec3498e04f46530965dc859"
# Define initialisation vector (IV) (96-bits here)
IV = "f3c953042d0e"

# Function to convert integer into binary bits
def binary(int):
    m = '{0:08b}'.format(int)
    if len(m)>64:
        return '{0:0128b}'.format(int)
    return m

# Function that takes a list of 16-integers to output 128-bits
def bits(liste):
    res = ''
    for element in liste:   # Each element corresponds to a byte
        res += binary(element)
    return res

# Convert a 128-binary string to a list of 16-integers
def ToList(binary):
    l = []
    for i in range(int(len(binary)/8)):
        l.append(int(binary[i*8:(i+1)*8],2))
    return l

# Returns decimal number corresponding to a list of 16-integers corresponding to 128-bits representation
def Todecimal(lst):
    return int(bits(lst),2)

# Padding into 128-bit blocks
def AuthenticatedData(data):
    toBlocks = AES.MessageToMatrix(data)
    lastLength = len(toBlocks[-1])
    nul = [0 for i in range(4)]
    if lastLength < 4:
        diff = 4 - lastLength
        for i in range(diff):
            toBlocks[-1].append(0)
    totalLength = len(toBlocks)

    while totalLength % 4 != 0:
        toBlocks.append(nul)
        totalLength += 1

    A_blocks = []
    for i in range(int(totalLength/4)):
        A_blocks.append(toBlocks[i*4]+toBlocks[i*4+1]+toBlocks[i*4+2]+toBlocks[i*4+3])

    return A_blocks

# With this we can directly use the AES.MessageToMatrix function to have our blocks of 128-bits
def matrixToblocks(matrix):
    flat_matrix = [item for sublist in matrix for item in sublist]
    size = len(flat_matrix)
    res = []
    for i in range(int(size/16)):
        res.append(flat_matrix[i*16:(i+1)*16])

    diff = size % 16
    lst = flat_matrix[int(size/16)*16:]

    if diff != 0:
        res.append(lst)
    return res

# Construction of irreducible polynomial in binary string:
def irreductiblePoly():
    res=""
    indexs = [0,1,2,7,128]
    for i in range(129):
        if i in indexs:
            res += '1'
        else:
            res += '0'
    return res[::-1]

# Return the degree of a polynomial
def deg(poly):
    deg = len(bin(poly)[2:])-1
    return deg

# Polynomial multiplication in GF(2^128), input and output in decimal
# irreducible is the polynomial in decimal which define the Galois field
def polyMulti(p1, p2, irreducible):
    res = 0
    while p1 > 0:
        if p1 & 1:
            res = res^p2

        p1 = p1 >> 1
        p2 = p2 << 1

        if deg(p2) == deg(irreducible):
            p2 = p2^irreducible
    return res

# Polynomial addition with integer in input
def XOR(p1, p2):
    return p1 ^ p2


# Initial Counter Value
def computeInitialCounter(IV,H):
    size = len(IV)*8
    IV = AuthenticatedData(IV)

    if size == 96:
        # Computation of 32-bits concatenated in case of 96 bits for IV
        concate = ""
        for i in range(31):
            concate += '0'
        concate += '1'

        firstTerm = ''
        # Take only the first 96 bits
        for i in range(12):
            firstTerm += binary(IV[0][i])
        initialCounter = firstTerm+concate
        return int(initialCounter,2)

    # Computation of L_IV
    zeros64 = ''
    for i in range(64):
        zeros64 += '0'
    L_IV = zeros64+'{0:0064b}'.format(size)

    # We add L_IV to list containing IV values
    IV.append(ToList(L_IV))

    # Compute Initial counter
    # Define irreducible polynomial in integer
    irrec = int(irreductiblePoly(),2)

    H = AuthenticatedData(H)[0]

    for i in range(len(IV)-1):
        res = polyMulti(Todecimal(IV[i]),Todecimal(H),irrec)
        res = XOR(res,Todecimal(IV[i+1]))
        res = polyMulti(res,Todecimal(H),irrec)

    return res

# Convert a message/cipher of 128 bits to decimal value
def stringToInt(string):
    return int(bits(matrixToblocks(AES.MessageToMatrix(string))[0]),2)

# Convert a block of 16 integer to decimal
def blockToInt(block):
    return int(bits(block),2)

# Make the encryption of a counter easier because integer need some conversion
def counterEncryption(counter):
    matrixCounter = ToList(binary(counter))
    matrixCounter = [[matrixCounter[i * 4], matrixCounter[i * 4 + 1], matrixCounter[i * 4 + 2],matrixCounter[i * 4 + 3]] for i in range(4)]
    counterMessage = AES.MatrixToMessage(matrixCounter)
    C = AES.AES(counterMessage, K, AES.S_box, AES.MixColMatrix)
    return C

# Function that returns the decimal value with the nbr significant bits of the encrypted counter
def significantBits(counter,nbr):
    res = str(''.join(format(ord(i), 'b') for i in counter))
    res = res[0:nbr]
    return int(res,2)

def decimalToCipher(number):
    cipher = ''
    x = '{0:08b}'.format(number)

    # In case the binary representation is not a multiple of 8 we add 0 until it is
    while len(x) % 8 != 0:
        x = '0' + x

    for i in range(int(len(x)/8)):
        nb = int(x[i*8:i*8+8],2)

        cipher += chr(nb)

    return cipher

# Authentication with Galois Field
def Authentication(A,H,C_decimals,C_start_decimal):
    # Compute L using size of A and P
    size_A = len(A)
    size_P = len(P)
    L = int('{0:064b}'.format(size_A) + '{0:064b}'.format(size_P),2)

    # Put in the same format A and H to execute polynomial: list of 16-integer representation of a 128-bit word
    A = AuthenticatedData(A)
    H = AuthenticatedData(H)[0]

    # Define irreducible polynomial in integer
    irrec = int(irreductiblePoly(),2)

    # Authentication
    for i in range(len(A)-1):
        res = polyMulti(Todecimal(A[i]), Todecimal(H), irrec)
        res = XOR(res, Todecimal(A[i+1]))
        res = polyMulti(res, Todecimal(H), irrec)
    for i in range(len(C_decimals)):
        res = XOR(res, C_decimals[i])
        res = polyMulti(res, Todecimal(H), irrec)

    res = XOR(res, L)
    res = polyMulti(res, Todecimal(H), irrec)
    res = XOR(res, C_start_decimal)
    return res


def Encryption(P,IV,K,A):
    # Computation of Hash subkey
    nullMatrix = [[0 for i in range(4)] for j in range(4)]
    nullMessage = AES.MatrixToMessage(nullMatrix)
    H = AES.AES(nullMessage, K, AES.S_box, AES.MixColMatrix)

    # Encryption of initial counter
    initialCounter = computeInitialCounter(IV, H)  # Result in integer
    C_start_decimal = initialCounter
    C_start = counterEncryption(initialCounter)  # Used later but in decimal that's why we do not use this variable

    Ciphers = []
    CiphersDecimal = []     # Store decimals value for authentication
    P_blocks = matrixToblocks(AES.MessageToMatrix(P))
    for i in range(len(P_blocks)):
        if i == len(P_blocks)-1:    # Last case when the last block is not necessary of size 128-bits
            initialCounter += 1
            C = counterEncryption(initialCounter)
            size = len(P_blocks[-1])
            nbrBits = size*8
            pValue = blockToInt(P_blocks[i])
            cValue = significantBits(C,nbrBits)
            res = XOR(cValue,pValue)

            cipher = decimalToCipher(res)
            Ciphers.append(cipher)
            CiphersDecimal.append(res)
            break

        initialCounter += 1     # increment counter
        C = counterEncryption(initialCounter)
        pValue = blockToInt(P_blocks[i])    # Value in decimal of 128 bits block
        cValue = stringToInt(C)     # Value in decimal of encrypted cipher
        res = XOR(cValue,pValue)    # Xor operation
        cipher = decimalToCipher(res)
        Ciphers.append(cipher)
        CiphersDecimal.append(res)

    Tag = Authentication(A, H, CiphersDecimal,C_start_decimal)
    finalCipher = ''
    for element in Ciphers:
        finalCipher += element
    return finalCipher, Tag

# Decryption
def Decryption(C,T,K,A,IV):
    # Computation of Hash subkey
    nullMatrix = [[0 for i in range(4)] for j in range(4)]
    nullMessage = AES.MatrixToMessage(nullMatrix)
    H = AES.AES(nullMessage, K, AES.S_box, AES.MixColMatrix)
    initialCounter = computeInitialCounter(IV, H)

    # Obtain blocks of 16-integer for ciphertext and convert it to decimal
    C_blocks = matrixToblocks(AES.MessageToMatrix(C))
    C_decimals = [blockToInt(element) for element in C_blocks]

    # Compute tag value associated to the cipher
    Tag = Authentication(A, H, C_decimals,initialCounter)
    if Tag == T:
        Plains = []
        Plains_decimals = []

        for i in range(len(C_decimals)):
            if i == len(C_decimals) - 1:  # Last case when the last block is not necessary of size 128 bits
                initialCounter += 1
                C = counterEncryption(initialCounter)
                size = len('{0:08b}'.format(C_decimals[-1]))
                while size % 8 != 0:    # In case size is not a multiple of 8
                    size += 1
                nbrBits = size
                cipherValue = C_decimals[i]
                cValue = significantBits(C, nbrBits)
                res = XOR(cValue, cipherValue)

                plain = decimalToCipher(res)
                Plains.append(plain)
                Plains_decimals.append(res)
                break

            initialCounter += 1  # Increment counter
            C = counterEncryption(initialCounter)
            pValue = C_decimals[i]
            cValue = stringToInt(C)  # Value in decimal of encrypted cipher
            res = XOR(cValue, pValue)  # XOR operation
            plain = decimalToCipher(res)
            Plains.append(plain)
            Plains_decimals.append(res)
        final_plain = ''
        for element in Plains:
            final_plain += element
        return final_plain
    else:
        return "FAIL: Wrong tag, the message has been tampered with. Man-in-the-Middle attack detected."

def BitFlippingAttack(C):
    X = list(C)
    index = random.randrange(len(C))
    new_bit = chr(random.randrange(255))
    X[index] = new_bit
    C = "".join(X)
    return C


# Encryption
C, Tag = Encryption(P, IV, K, A)

# Bit-Flipping Attack
C = BitFlippingAttack(C)

# Decryption
decrypted_plaintext = Decryption(C, Tag, K, A, IV)

print("Original plaintext: ", P)
print("Decrypted plaintext: ", decrypted_plaintext)
