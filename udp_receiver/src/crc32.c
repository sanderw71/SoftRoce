
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

