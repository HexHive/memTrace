int main(){
  char* a = malloc(10);
  int i;
  for (i=0; i<15; i++){
    printf("%d -> %d\n", i, (int)a[i]);
  }
  free(a);
  return 0;
}

