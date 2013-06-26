#include <iostream>

using namespace std;


int main(int argc, char** argv)
{
  try {
    cout<<"haha"<<endl;  
    if (argc < 100){
//      asm("int3");
      throw 34;
    }
    cout<<"dudu"<<endl; 
  } catch (int ex) {
 //   asm("hlt");
    cout<<"Caught "<<ex<<endl; 
    return 0;
  }
  return 1;
}


