/**********************************************************************************
Copyright Institut Telecom
Contributors: Renaud Pacalet (renaud.pacalet@telecom-paristech.fr)

This software is a computer program whose purpose is to experiment timing and
power attacks against crypto-processors.

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms. For more
information see the LICENCE-fr.txt or LICENSE-en.txt files.
**********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/times.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>
#include <utils.h>
#include <des.h>
#include <rdtsc_timer.h>

uint64_t
rand_uint64_t (void)
{
  uint64_t res;
  int i;

  res = UINT64_C (0x0);
  for (i = 0; i < 4; i++)
    {
      res <<= 16;
      res |= (uint64_t) (rand () & 0xffff);
    }
  return res;
}

extern uint64_t des_p_ta (uint64_t val);

uint64_t
des_f_ta (uint64_t rk, uint64_t val)
{
  if (val >> 32)
    {
      ERROR (-1, "illegal R input value for F function: %016" PRIx64, val);
    }
  if (rk >> 48)
    {
      ERROR (-1, "illegal RK input value for F function: %016" PRIx64, rk);
    }
  return des_p_ta (des_sboxes (des_e (val) ^ rk));
}

uint64_t
des_enc_ta (uint64_t * ks, uint64_t val)
{
  uint64_t lr, r, l, tmp;
  int i;

  lr = des_ip (val);
  r = des_right_half (lr);
  l = des_left_half (lr);
  for (i = 0; i < 16; i++)
    {
      tmp = r;
      r = l ^ des_f_ta (ks[i], r);
      l = tmp;
    }
  return des_fp ((r << 32) | l);
}

extern int
des_check_f (uint64_t (*f_enc) (uint64_t *, uint64_t),
       uint64_t (*f_dec) (uint64_t *, uint64_t));

int
des_check_ta (void)
{
  return des_check_f (des_enc_ta, des_dec);
}

int
measure (uint64_t * ks, uint64_t pt, double th, int average, double *time,
   uint64_t * ct)
{
  uint64_t a, b, t, min, *m;
  int i, n, cnt;

  if (average < 1)
    {
      ERROR (-1, "illegal average value: %d", average);
    }
  if (th < 1.0)
    {
      ERROR (-1, "illegal threshold value: %f", th);
    }
  m = XCALLOC (average, sizeof (uint64_t));
  min = UINT64_C (0);
  for (i = 0; i < average; i++)
    {
      a = get_rdtsc_timer ();
      *ct = des_enc_ta (ks, pt);
      b = get_rdtsc_timer ();
      t = b - a;
      m[i] = t;
      if (i == 0 || t < min)
  {
    min = t;
  }
    }
  n = 0;
  i = 0;
  cnt = average;
  while (n < average)
    {
      if (m[i] <= th * min)
  {
    n += 1;
    i = (i + 1) % average;
  }
      else
  {
    do
      {
        a = get_rdtsc_timer ();
        *ct = des_enc_ta (ks, pt);
        b = get_rdtsc_timer ();
        cnt += 1;
        t = b - a;
      }
    while (t > min * th);
    if (t < min)
      {
        n = 0;
        min = t;
      }
    m[i] = t;
    n += 1;
    i = (i + 1) % average;
  }
    }
  t = 0;
  for (i = 0; i < average; i++)
    {
      t += m[i];
    }
  *time = (double) (t) / (double) (average);
  return cnt;
}

#define TH 1.1
#define AVG 10

uint64_t str2key(char *);

int
main (int argc, char **argv)
{
  int n, i, j, k, l;
  uint64_t ks[16], pt, ct, key;
  double t;
#ifdef SRAND
  struct tms dummy;
#endif

  if (!des_check_ta ())
    {
      ERROR (-1, "%s: DES functional test failed", argv[0]);
    }
  if (argc != 3)
    {
      ERROR (-1, "usage: %s <n> <key>", argv[0]);
    }
  n = atoi (argv[1]);
  if (n < 1)
    {
      ERROR (-1,
       "%s: number of experiments (<n>) shall be greater than 1 (%d)",
       argv[0], n);
    }
  key = str2key(argv[2]);
  des_ks (ks, key);
#ifdef DEBUG
  for (i = 0; i < 8; i++)
    {
      fprintf (stderr, "%02" PRIx32 " ",
         (uint32_t) ((ks[15] >> ((7 - i) * 6)) & UINT64_C (0x3f)));
    }
  fprintf (stderr, "\n");
#endif
#ifdef SRAND
  srand (times (&dummy));
#else
  srand (0);
#endif
  j = n / 100;
  k = 0;
  l = 0;
  for (i = 0; i < n; i++)
    {
      pt = rand_uint64_t ();
      if (i == 0)
        {
          printf ("%016" PRIx64 "\n", pt);
        }
      measure (ks, pt, TH, AVG, &t, &ct);
      if (ct != des_enc_ta (ks, pt))
        {
          ERROR (-1, "data dependent DES functionally incorrect");
        }
      printf ("%016" PRIx64 " %f\n", ct, t);
      k += 1;
      if (k == j)
        {
          l += 1;
          fprintf (stderr, "%3d%%[4D", l);
          k = 0;
        }
    }
  fprintf (stderr, "\n");
  return 0;
}

uint64_t str2key(char * str) {
  uint64_t res;
  int i, v;

  v = 0;
  res = UINT64_C (0);
  for(i = 0; i < strlen(str); i++) {
    switch(str[i]) {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9': v = str[i] - '0';
                break;
      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f': v = str[i] - 'a' + 10;
                break;
      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F': v = str[i] - 'A' + 10;
                break;
      default: ERROR (-1, "unvalid key value: %s", str);
               break;
      }
    if((res >> 60) != UINT64_C (0)) {
      ERROR (-1, "key overflow: %s", str);
      }
    res = (res << 4) | (uint64_t)(v);
    }
  return res;
}
