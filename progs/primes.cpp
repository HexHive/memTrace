// Just a simple test program taken from the internetz

#include <iostream>
using namespace std;

void prime_num(int);

int main()
{
	int num = 100;
	prime_num(num);
}
 
void prime_num( int num)
{
		bool isPrime=true;
		for ( int i = 2; i <= num; i++)
		{
				for ( int j = 2; j <i; j++)
				{
						if ( i % j == 0 )
						{
						  isPrime=false;
						  break;
						}
				}
				if (isPrime)
				{
				  cout <<"Prime:"<< i << endl;
				}
				isPrime=true;
		}
}
