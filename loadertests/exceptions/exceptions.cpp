#include <iostream>

using namespace std;


int main(int argc, char** argv)
{
  try {
    cout<<"starting exception test... (expected: graceful catching)"<<endl;  
    if (argc < 100){
//      asm("int3");
      throw 34;
    }
    cout<<"dudu"<<endl; 
  } catch (int ex) {
    cout<<"Test 'exceptions' successful (caught the exception) "<<ex<<endl; 
    return 0;
  }
  return 1;
}


