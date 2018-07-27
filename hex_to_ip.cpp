#include "hex_to_ip.h"
#include <stdio.h>

int hex_to_ip(unsigned int hex, char* ip_str)
{
  sprintf(ip_str, "%3d", (hex) & 0xff);
  ip_str[3] = '.';
  sprintf(ip_str+4, "%3d", (hex >> 8) & 0xff);
  ip_str[7] = '.';
  sprintf(ip_str+8, "%3d", (hex >> 16) & 0xff);
  ip_str[11] = '.';
  sprintf(ip_str+12, "%d", (hex >> 24) & 0xff);
  ip_str[15] = 0;
}