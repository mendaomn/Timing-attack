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
#include <stdint.h>
#include <inttypes.h>

#include <utils.h>
#include <des.h>
#include <km.h>
#include <pcc.h>

uint64_t pt;    /* Plain text. */
uint64_t *ct;   /* Array of cipher texts. */
double *t;      /* Array of timing measurements. */
int n;              /* Required number of experiments. */

/* Allocate arrays <ct> and <t> to store <n> cipher texts and timing
 * measurements. Open datafile <name> and store its content in global variables
 * <pt>, <ct> and <t>. */
void read_datafile (char *name, int n);

/* Brute-force attack with a plain text - cipher text pair (<pt>, <ct>) and
 * partial knowledge of secret key (<km>). Print the found secret key (16 hex
 * digits) and return 1 if success, else return 0 and print nothing. */
int brute_force (des_key_manager km, uint64_t pt, uint64_t ct);

/* Tries key and returns the delta */
double try_key(unsigned long long key, int sbox);

int
main (int argc, char **argv)
{
  int i;              /* Loop index. */
  des_key_manager km; /* Key manager. */
  double delta = 0, new_delta;
  unsigned long long key, bestkey, finalkey, mask;
  int sbox;
  int k;

  /************************************************************************/
  /* Before doing anything else, check the correctness of the DES library */
  /************************************************************************/
  if (!des_check ())
    {
      ERROR (-1, "DES functional test failed");
    }

  /*************************************/
  /* Check arguments and read datafile */
  /*************************************/
  /* If invalid number of arguments (including program name), exit with error
   * message. */
  if (argc != 3)
    {
      ERROR (-1, "usage: ta <datafile> <nexp>\n");
    }
  /* Number of experiments to use is argument #2, convert it to integer and
   * store the result in variable n. */
  n = atoi (argv[2]);
  if (n < 1)      /* If invalid number of experiments. */
    {
      ERROR (-1,
       "number of experiments to use (<nexp>) shall be greater than 1 (%d)",
       n);
    }
  read_datafile (argv[1],  /* Name of data file is argument #1. */
     n    /* Number of experiments to use. */
    );

  /*****************************************************************************
   * Compute the Hamming weight of output of first (leftmost) SBox during last *
   * round, under the assumption that the last round key is all zeros.         *
   *****************************************************************************/
	/* per ogni cipher provo tutte le combinazioni dei primi 6 bit della key
    // medio i tempi dei cipher reali che dopo la sbox hanno hamming 0 e 4
    // delta tra le due medie
    // cambio key e riprovo, terro la key che ha delta maggiore
    // ripetero per le box successive */ 

	/* for every SBox */
	finalkey = 0ULL;
	for(k=0; k<1; k++){
	for (sbox = 7; sbox >= 0; sbox--){
	    mask = 63ULL << (42 - 6*sbox);
		finalkey &= ~mask; 
/*		printf("mask    :%012" PRIx64 "\n", ~mask); */
		for (i = 0; i < 64; i++){
			key = ((unsigned long long) i) << (42 - 6*sbox); 
			new_delta = try_key(finalkey | key, sbox);
			if (new_delta > delta) {
				delta = new_delta;
				bestkey = key;
			}
		}
		delta = 0;
		finalkey |= bestkey;
		/*printf("finalkey:%012" PRIx64 "\n", finalkey);*/
	}
	}

  /*******************************************************************************
   * Try all the 256 secret keys under the assumption that the last round key is *
   * all zeros.                                                                  *
   *******************************************************************************/
  /* If we are lucky, the secret key is one of the 256 possible with a all zeros
   * last round key. Let's try them all, using the known plain text - cipher text
   * pair as an oracle. */
  km = des_km_init ();    /* Initialize the key manager with no knowledge. */
  /* Tell the key manager that we 'know' the last round key (#16) is all zeros. */
  des_km_set_rk (km,    /* Key manager */
     16,    /* Round key number */
     1,    /* Force (we do not care about conflicts with pre-existing knowledge) */
     UINT64_C (0xffffffffffff),  /* We 'know' all the 48 bits of the round key */
     finalkey
    );
  /* Brute force attack with the knowledge we have and a known
   * plain text - cipher text pair as an oracle. */
  if (!brute_force (km, pt, ct[0]))
    {
     /* //printf ("Too bad, we lose: the last round key is not all zeros.\n"); */
    }
  free (ct);      /* Deallocate cipher texts */
  free (t);      /* Deallocate timings */
  des_km_free (km);    /* Deallocate the key manager */
  
 /* printf("\n****\nReal key was: e59dcd40dc51b56d\n */
  
  
  return 0;      /* Exits with "everything went fine" status. */
  
  
  
}

double try_key(unsigned long long key, int sbox){
	uint64_t r16l16;    /* Output of last round, before final permutation. */
	uint64_t l16;       /* Right half of r16l16. */
	uint64_t sbo;       /* Output of SBoxes during last round. */
	int i;              /* Loop index. */
	double delta;
	int hw;
	pcc_context ctx;
	ctx = pcc_init(1);
	for (i=0; i<n; i++){
		r16l16 = des_ip (ct[i]); /* undoes final permutation */
		l16 = des_right_half (r16l16); /* extracts right half */
		sbo = des_sboxes (des_e (l16) ^ key);  /* computes sboxes, R15 = L16, K16 = 0 */
		hw = hamming_weight (sbo); /* & (unsigned long long)mask); */
		pcc_insert_x(ctx, t[i]);
		pcc_insert_y(ctx, 0, hw);
	}
	pcc_consolidate(ctx);
	delta = pcc_get_pcc(ctx, 0);
	pcc_free(ctx);
	return delta;
}

void
read_datafile (char *name, int n)
{
  FILE *fp;      /* File descriptor for the data file. */
  int i;      /* Loop index */

  /* Open data file for reading, store file descriptor in variable fp. */
  fp = XFOPEN (name, "r");

  /* Read the first line and stores the value (plain text) in variable pt. If
   * read fails, exit with error message. */
  if (fscanf (fp, "%" PRIx64, &pt) != 1)
    {
      ERROR (-1, "cannot read plain text");
    }

  /* Allocates memory to store the cipher texts and timing measurements. Exit
   * with error message if memory allocation fails. */
  ct = XCALLOC (n, sizeof (uint64_t));
  t = XCALLOC (n, sizeof (double));

  /* Read the n experiments (cipher text and timing measurement). Store them in
   * the ct and t arrays. Exit with error message if read fails. */
  for (i = 0; i < n; i++)
    {
      if (fscanf (fp, "%" PRIx64 " %lf", &(ct[i]), &(t[i])) != 2)
        {
          ERROR (-1, "cannot read cipher text and/or timing measurement");
        }
    }
}

int
brute_force (des_key_manager km, uint64_t pt, uint64_t ct)
{
  uint64_t dummy, key, ks[16];

  des_km_init_for_unknown (km);  /* Initialize the iterator over unknown bits */
  do        /* Iterate over the possible keys */
    {
      key = des_km_get_key (km, &dummy);  /* Get current key, ignore the mask */
      des_ks (ks, key);    /* Compute key schedule with current key */
      if (des_enc (ks, pt) == ct)  /* If we are lucky... cheers. */
        {
          printf ("%016" PRIx64 "\n", key);
          return 1;    /* Stop iterating and return success indicator. */
        }
    }
  while (des_km_for_unknown (km));  /* Continue until we tried them all */
  return 0;      /* Return failure indicator. */
}
