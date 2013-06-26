int g(int n);
int f(int n){
if (n < 2) return 1;
return f(n-1) + g(n-2);
}
int g(int n){
if (n < 2) return 1;
return g(n-1) + f(n-2);
}
int main(){
  printf("%d\n", f(34));
  return 0;
}
