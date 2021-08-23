fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])
#These 3 lines creates the fibbonachi numbers up to the 11'th element, and stores them in the variable fib
#fib = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]


def c2f(c):
	n = ord(c) # Transforms the character to a number value using ascii/utf-8 and store it in the variable n
	b = ''
	for i in range(10, -1, -1): # Counts backwards from 10 to 0
		if n >= fib[i]: # Since i counts backwards, the first number checked in fib[i] will be the biggest  
			n -= fib[i]
			b += '1' # and since the first number checked in fib[i] was the biggest, we know that the first 1/0 symbol will be the "most significant bit"
		else:
			b += '0'
	return b


flag = open('flag.txt', 'r').read() # The program opens a flag.txt, so to make it work we have created a placeholder flag.txt
enc = ''
for c in flag:
	enc += c2f(c) + ' ' # This passes each character in the flag through the c2f() function before adding it to the array enc[] with a trailing space
with open('flag.enc', 'w') as f:
	f.write(enc.strip()) # Writes the flag to the file we were given