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

/** \file rdtsc_timer.h
 *  A function that returns the current value of the internal timer.
 *  \author Renaud Pacalet, renaud.pacalet@telecom-paristech.fr
 *  \date 2009-07-08
 *  \attention
 *  Not portable, tested only on Pentium architecture under Linux.
 *
 *  Example of use to time a function 10 times and return the minimum time value
 *  as a floating point (double): \code
 *  uint64_t a, b;
 *  int i;
 *  double t, min;
 *  ...
 *  for(i = 0; i < 10; i++)
 *  {
 *    a = get_rdtsc_timer();
 *    function_to_time();
 *    b = get_rdtsc_timer();
 *    t = (double)(b - a);
 *    if(i == 0 || t < min)
 *    {
 *      min = t;
 *    }
 *  }
 *  return min;
 *  \endcode
 */

#ifndef RDTSC_TIMER_H
#define RDTSC_TIMER_H

#include <stdint.h>

/** A function that returns the current value of the internal timer. \return the
 * timer value as a 64 bits unsigned integer. */
uint64_t get_rdtsc_timer (void);

#endif /* not RDTSC_TIMER_H */
