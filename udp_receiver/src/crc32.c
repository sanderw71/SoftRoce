
/* 
 * Based upon the work of Grant P. Maizels and Ross Williams.
 * Their original licence details are in the header file.
 * This amalgamation is the work of James Bensley Copyright (c) 2018.
 */ 


#include <stdio.h>     // EOF, FILE, fclose(), fprintf(), fscanf(), perror(), printf(), stderr, stdin
#include <stdlib.h>    // calloc(), exit()
#include <inttypes.h>  // intN_t, PRIxN, SCNxN, uintN_t
#include <string.h>    // memset()

#include "crc32.h"

cm_t cm;
p_cm_t p_cm = &cm;


static uint32_t reflect(uint32_t v, uint32_t b) {

  static int   i;
  static uint32_t t;

  t = v;

  for (i=0; i < b; i++) {

    if (t & 1L) {
       v|=  BITMASK((b - 1) - i);
    } else {
       v&= ~BITMASK((b - 1) - i);
    }

    t>>=1;

  }

  return v;

}


static uint32_t widmask(p_cm_t p_cm) {

  return (((1L << (p_cm->cm_width - 1)) - 1L) << 1) | 1L;

}


void cm_ini(p_cm_t p_cm) {

  p_cm->cm_reg = p_cm->cm_init;

}


void cm_nxt(p_cm_t p_cm, uint32_t ch) {

  static int   i;
  static uint32_t uch, topbit;

  uch    = ch;
  topbit = BITMASK(p_cm->cm_width - 1);

  if (p_cm->cm_refin) uch = reflect(uch, 8);

  p_cm->cm_reg ^= (uch << (p_cm->cm_width - 8));

  for (i=0; i < 8; i++) {

    if (p_cm->cm_reg & topbit) {
      p_cm->cm_reg = (p_cm->cm_reg << 1) ^ p_cm->cm_poly;
    } else {
       p_cm->cm_reg <<= 1;
    }

    p_cm->cm_reg &= widmask(p_cm);

  }

}


static void cm_blk(p_cm_t p_cm, uint8_t *blk_adr, uint32_t blk_len) {

  while (blk_len--) cm_nxt(p_cm, *blk_adr++);

}


uint32_t cm_crc(p_cm_t p_cm) {

  if (p_cm->cm_refot) {
    return p_cm->cm_xorot ^ reflect(p_cm->cm_reg, p_cm->cm_width);
  } else {
    return p_cm->cm_xorot ^ p_cm->cm_reg;
  }

}


static uint32_t cm_tab(p_cm_t p_cm, uint32_t index) {

  static uint8_t  i;
  static uint32_t r, topbit, inbyte;

  topbit = BITMASK(p_cm->cm_width - 1);
  inbyte = index;

  if (p_cm->cm_refin) inbyte = reflect(inbyte, 8);

  r = inbyte << (p_cm->cm_width - 8);

  for (i=0; i < 8; i++) {

    if (r & topbit) {
      r = (r << 1) ^ p_cm->cm_poly;
    } else {
       r <<= 1;
     }
  }

  if (p_cm->cm_refin) r = reflect(r, p_cm->cm_width);

  return r & widmask(p_cm);

}

uint32_t calc_icrc32(char *data, int len) 
{
  int brh_offset = 14;
  int checksum_length = 4;
  int l;
  char pseudo_lrh[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  cm_ini(p_cm);

  // Create an array that concatenates input array with pseaudo LRH header of 8x 0xFF

  char icrc_array[len + sizeof(pseudo_lrh) - brh_offset - checksum_length]; 
  memcpy(icrc_array, pseudo_lrh, sizeof(pseudo_lrh));
  memcpy(&icrc_array[sizeof(pseudo_lrh)], &data[brh_offset], len -checksum_length);

  icrc_array[9]  = 0xFF; // Differentiated Service Field (DSCP, ECN)
  icrc_array[16] = 0xFF; // Time to live
  icrc_array[18] = 0xFF; // IP Header checksum
  icrc_array[19] = 0xFF; // IP Header checksum
  icrc_array[34] = 0xFF; // UDP Header checksum
  icrc_array[35] = 0xFF; // UDP Header checksum
  icrc_array[40] = 0xFF; // BTH reserved field, resv8a

  // printf("Array for ICRC calculation: \n");
  // for (l = 0; l < sizeof(icrc_array); l++)
  // {
  //   if ((l % 8 == 0) & (l != 0))
  //   {
  //     printf("\n");
  //   }
  //   printf("0x%-10x ", (unsigned char)icrc_array[l]);
  // }
  // printf("\n");

  int16_t max = sizeof(icrc_array);

  for (uint16_t j = 0; j < max; j += 1)
  {
    cm_nxt(p_cm, icrc_array[j]); 
  }

  uint32_t icrc_be32 = (cm_crc(p_cm) & 0xffffffff);
  //uint32_t icrc = be32_to_le32(icrc_be32);

  return icrc_be32;
}

int InsertIcrc(unsigned char *buffer, int buflen)
{
	uint32_t icrc = calc_icrc32(buffer, buflen);
	uint32_t *ptr = (uint32_t *)&buffer[buflen - 4];
	*ptr = icrc;
	return 0;
}

// int Crc_Checking(void)
// {
//   uint32_t icrc1,icrc2;

//   icrc1 = calc_icrc32(connect_request, sizeof(connect_request)-4);
//   icrc2 = calc_icrc32(connect_request, sizeof(connect_request)-4);
//   if (icrc1 != icrc2) {
//     printf("Crc checking error");
//     exit(0);
//   }
// }

void initCrc(void)
{
  memset(p_cm, 0, sizeof(cm));

  p_cm->cm_width = 32;
  p_cm->cm_poly = 0x04C11DB7;
  p_cm->cm_init = 0xFFFFFFFF;
  p_cm->cm_refin = 1;
  p_cm->cm_refot = 1;
  p_cm->cm_xorot = 0xFFFFFFFF;
  cm_ini(p_cm);

  // Crc_Checking();
}