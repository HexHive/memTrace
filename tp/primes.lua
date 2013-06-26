
---Find primse smaller than this number:
LIMIT=100000

---Checks to see if a number is prime or not
function isPrime(n)
	primes={}
	if n<=0 then return false end
	if n<=2 then return true end
	if (n%2==0) then return false end
	for i=3,n/2,2 do
		if (n%i==0) then return false end
	end
	return true
end

---Print all the prime numbers within range
for i=1,LIMIT do
	if isPrime(i) then io.write(i..",") end
end

