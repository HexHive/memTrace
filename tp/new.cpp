#include <iostream>

int main(){

  int* a = new int;

  for (int k=0; k<3; k++){
	  int r = 0;
	  int* b = new int[13];
	  for (int i=0; i<13; i++){
	    b[i]=i;
          }
	  for (int i=0; i<=13; i++){
	    std::cout<<"accessing element "<<i<<std::endl;
	    r += b[i];
	  }
	  delete[] b;
          std::cout<<"r="<<r<<std::endl;
  }

  return 0;
}
