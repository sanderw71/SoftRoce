#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include <linux/kernel.h>

unsigned char connect_request[] = {
  0x00, 0x15, 0x5d, 0x24, 0x01, 0x04, 0x00, 0x15,
  0x5d, 0x01, 0x02, 0x0d, 0x08, 0x00, 0x45, 0x00,
  0x01, 0x34, 0xb6, 0xaf, 0x40, 0x00, 0x40, 0x11,
  0xfe, 0xed, 0xc0, 0xa8, 0x01, 0x66, 0xc0, 0xa8,
  0x01, 0x65, 0xd8, 0x72, 0x12, 0xb7, 0x01, 0x20,
  0x00, 0x00, 0x64, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x00, 0x01, 0x80, 0x00, 0x00, 0x0c, 0x80, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x07,
  0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x02, 0xd5, 0x67, 0x2a, 0x51, 0x00, 0x10,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x2a,
  0x67, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x06, 0x1c, 0x06, 0x02, 0x15,
  0x5d, 0xff, 0xfe, 0x01, 0x02, 0x0d, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x11, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0xa0, 0xd6, 0x36, 0x75, 0xa7, 0xff, 0xff,
  0x37, 0xf0, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xc0, 0xa8, 0x01, 0x66, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xc0, 0xa8, 0x01, 0x65, 0x14, 0xa6,
  0x40, 0x00, 0x00, 0x40, 0x00, 0x98, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x40, 0x8d, 0xe2, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x66, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x65, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0a,
  0x9d, 0xe4
};

char rc_send_only[] = {
    0x00, 0x15, 0x5d, 0x24, 0x01, 0x04, 0x00, 0x15,
    0x5d, 0x01, 0x02, 0x0d, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3c, 0xb6, 0xb4, 0x40, 0x00, 0x40, 0x11, 
    0xff, 0xe0, 0xc0, 0xa8, 0x01, 0x66, 0xc0, 0xa8, 
    0x01, 0x65, 0xdf, 0x94, 0x12, 0xb7, 0x00, 0x28, 
    0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x00, 0x00, 
    0x00, 0x11, 0x80, 0xa5, 0x98, 0x0a, 0x00, 0x00, 
    0x56, 0x40, 0x02, 0x37, 0x0a, 0xb0, 0x00, 0x00, 
    0x10, 0x63, 0x00, 0x00, 0x00, 0x40, 0xa1, 0x85, 
    0x56, 0x85
};

//cm_t cm;
//p_cm_t p_cm = &cm;

uint32_t be32_to_le32(uint32_t value) 
{
    return (((value >> 24)  &0x000000ff) | // move byte 3 to byte 0
           ((value  << 8 )  &0x00ff0000) | // move byte 1 to byte 2
           ((value  >> 8 )  &0x0000ff00) | // move byte 2 to byte 1
           ((value  << 24)  &0xff000000)); // byte 0 to byte 3
}



int Crc_Checking(void)
{
  uint32_t icrc1,icrc2;

  icrc1 = calc_icrc32(connect_request, sizeof(connect_request)-4);
  icrc2 = calc_icrc32(connect_request, sizeof(connect_request)-4);
  if (icrc1 != icrc2) {
    printf("Crc checking error");
    exit(0);
  }
}

// void initCrc(void)
// {
//   memset(p_cm, 0, sizeof(cm));

//   p_cm->cm_width = 32;
//   p_cm->cm_poly = 0x04C11DB7;
//   p_cm->cm_init = 0xFFFFFFFF;
//   p_cm->cm_refin = 1;
//   p_cm->cm_refot = 1;
//   p_cm->cm_xorot = 0xFFFFFFFF;
//   cm_ini(p_cm);

//   Crc_Checking();
// }

