import sympy
import string

check = [0x75,0x6a,0x70,0x3f,0x5f,0x6f,0x48,0x79,0x5f,0x6c,0x78,0x69,0x75,0x5f,0x7a,0x78,0x5f,0x75,0x76,0x65]

#check = [0x41,0x42,0x43]

ascii_lower = string.ascii_lowercase
ascii_upper = string.ascii_uppercase


for n in range(len(check)):
    bNum = n * 4
    while(True):
        if sympy.isprime(bNum):
            #print(bNum,end=",")
            break
        bNum += 1
    charToPrint = check[n]
    if(64 < check[n] < 91):
        charToPrint = ord(ascii_upper[((check[n] - 65) - bNum) % 26])
    if(96 < check[n] < 123):
        charToPrint = ord(ascii_lower[((check[n] - 97) - bNum) % 26])
    print(chr(charToPrint),end="")


#rotBases = 2,5,11,13,17,23,29,29,37,37,41,47,53,53,59,61,67,71,73,79