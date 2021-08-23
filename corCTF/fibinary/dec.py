fib = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]

def f2c(c):
	cDec = 0
	for i in range(0,10):
		if c[i] == '1':
			cDec += fib[10-i]
	return chr(cDec)


flagEnc = open('flag.enc','r').read().split()
flag = ''
for c in flagEnc:
	flag += f2c(c)
print(flag)