# Imports beyond the standard python library will not
# pass the autograder!

# you will likely need to write this helper routine
# but it will not be tested

#this is used to find the GCD of two numbers a and b as well as the coefficents 
# x and y of bezouts identity ( ax + by = gcd(a,b))


def extendedEuclid(a, b):
    
    #initializing the variables
    #here we choose because we want to start with 
    #the first value of x and y as 1 and 0
    
    x0, x1, y0, y1 = 0, 1, 1, 0 
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0  #updating the x values
        y0, y1 = y1 - q * y0, y0  #updating the y values
    return a , x1, y1 #gcd, x, y




# checks if a provided private key d is valid
#    given valid e, p, q
# To understand this check, consider (GCD CT)
def checkPrivateKey( d, e, p, q ):
    return (d * e) % ((p-1)*(q-1)) == 1






# assume p,q prime positive integers (p,q > 2)
# assume 2 < e < (p − 1)(q − 1)
# assume gcd(e, (p-1)(q-1)) = 1
# must return private key d > 0
# Hints: 
# - python has proper modulus support for negative numbers
#   ex: -1 % 5 = 4
# - You will want to use the extended Euclidean algoritm 
#   to compute the modular inverse
def genPrivateKey( e, p, q ):
    phi = (p-1)*(q-1)
    gcd, x, y = extendedEuclid(e, phi)
    #ensure d is positive
    d = x % phi
    return d






# e and n are the public key as described in the notes
# assume e and n constitute a valid public key
# message is an array of integers, of which each index
#     must be encrypted individually
# assume 0 <= message[i] < n
# you may modify message in place
# public keys are usually small so do not worry about
#       performance in this routine
# Hints: 
# - you may want to calculate an exponent iteratively
#   and apply a modulus with each iteration
def encryptRSA( message, e, n ):
    for i in range(len(message)):
        message[i] = pow(message[i], e, n)
    return message






# d, q, p is the private key as described in the notes
# assume n and d are valid
# ciphertext is an array of integers, of which each 
#     index must be decrypted individually
# you may modify ciphertext in place
# Hints:
# - naive exponentiation by d will be too slow!
# - use the extended euclidean algorithm to find the unique 
#   solution posed by the Chinese Remainder Theorem
# - watch https://www.youtube.com/watch?v=NcPdiPrY_g8
def decryptRSA( ciphertext, d, q, p):
    n = p * q
    for i in range(len(ciphertext)):
        ciphertext[i] = pow(ciphertext[i], d, n)
    return ciphertext






# Testing code provided in main():
def main():
    testDir = "C:\\Users\\clubb\\OneDrive\\Desktop\\2910\\W5Testcases\\" # update this path with the path to your tests directory!
    passed = True
    with open(f"{testDir}/testKeyGen.txt") as idFile:
        args = []
        for idx, line in enumerate(idFile.readlines()):
            if idx % 2 == 0:
                args = line.split(" ")
            else:
                computedKey = genPrivateKey(int(args[0]), int(args[1]), int(args[2]))
                correctKey = int(line.split()[0])
                if checkPrivateKey(computedKey, int(args[0]), int(args[1]), int(args[2])) != 1:
                    print(f"Failed testKeyGen test, Expected: {correctKey}, Got: {computedKey}")
                    passed = False
    if passed:
        print("Passed testKeyGen tests")
    passed = True
    with open(f"{testDir}/testEncrypt.txt") as idFile:
        args = []
        for idx, line in enumerate(idFile.readlines()):
            if idx % 2 == 0:
                args = line.split(" ")
            else:
                ciphertextOut = encryptRSA( [0,1,2,3,4,5,6,7,8,9,10], int(args[0]), int(args[1]) * int(args[2]) )
                correctText = [int(i) for i in line.split(" ")]
                if ciphertextOut != correctText:
                    print(f"Failed testEncrypt test:\nExpected: ")
                    print(correctText)
                    print("Got: ")
                    print(ciphertextOut)
                    passed = False
    if passed:
        print("Passed testEncrypt tests")
    passed = True
    with open(f"{testDir}/testDecrypt.txt") as idFile:
        expected = [0,1,2,3,4,5,6,7,8,9,10]
        args = []
        for idx, line in enumerate(idFile.readlines()):
            if idx % 2 == 0:
                args = line.split(" ")
            else:
                cipherIn = [int(i) for i in line.split(" ")]
                messageOut = decryptRSA( cipherIn, int(args[0]), int(args[1]), int(args[2]) )
                if messageOut != expected:
                    print(f"Failed testDecrypt test:\nExpected: ")
                    print(expected)
                    print("Got: ")
                    print(messageOut)
                    passed = False
    if passed:
        print("Passed testDecrypt tests")
    return 0

if __name__ == '__main__':
    main()
