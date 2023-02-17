#include <arpa/inet.h>
#include <stdio.h>

int main(void)
{
  struct in_addr addr;
  if (inet_aton("10.11.1.1", &addr) == 0)
  {
    perror("inet_aton");
    return 1;
  }
  in_addr_t ip = addr.s_addr;
  printf("%u\n", ip);
  return 0;
}