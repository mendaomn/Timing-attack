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

#include <stdlib.h>
#include <utils.h>
#include <math.h>
#include <pcc.h>

pcc_context
pcc_init (int ny)
{
  pcc_context ctx;
  int i;

  if (ny < 1)
    {
      ERROR (-1, "invalid number of Y random variables: %d", ny);
    }
  ctx = XCALLOC (1, sizeof (struct pcc_context_s));
  ctx->ny = ny;
  ctx->nr = 0;
  ctx->x = 0.0;
  ctx->x2 = 0.0;
  ctx->y = XCALLOC (ny, sizeof (double));
  ctx->y2 = XCALLOC (ny, sizeof (double));
  ctx->xy = XCALLOC (ny, sizeof (double));
  ctx->pcc = XCALLOC (ny, sizeof (double));
  ctx->state = 0;
  ctx->cnt = ny;
  ctx->flags = XCALLOC (ny, sizeof (char));
  for (i = 0; i < ny; i++)
    {
      ctx->y[i] = 0.0;
      ctx->y2[i] = 0.0;
      ctx->xy[i] = 0.0;
      ctx->pcc[i] = 0.0;
      ctx->flags[i] = 0;
    }
  return ctx;
}

void
pcc_insert_x (pcc_context ctx, double x)
{
  if (ctx->cnt != ctx->ny)
    {
      ERROR (-1, "missing %d Y realizations", ctx->ny - ctx->cnt);
    }
  ctx->cnt = 0;
  ctx->state = 1 - ctx->state;
  ctx->rx = x;
  ctx->x += x;
  ctx->x2 += x * x;
  ctx->nr += 1;
}

void
pcc_insert_y (pcc_context ctx, int ny, double y)
{
  if (ny < 0 || ny >= ctx->ny)
    {
      ERROR (-1, "invalid Y index: %d", ny);
    }
  if (ctx->flags[ny] == ctx->state)
    {
      ERROR (-1, "Y realization #%d inserted twice", ny);
    }
  ctx->y[ny] += y;
  ctx->y2[ny] += y * y;
  ctx->xy[ny] += ctx->rx * y;
  ctx->cnt += 1;
  ctx->flags[ny] = ctx->state;
}

void
pcc_consolidate (pcc_context ctx)
{
  double n;
  double tmp;
  int i;

  if (ctx->cnt != ctx->ny)
    {
      ERROR (-1, "missing %d Y realizations", ctx->ny - ctx->cnt);
    }
  if (ctx->nr < 2)
    {
      ERROR (-1, "not enough realizations (%d, min 2)", ctx->nr);
    }
  n = (double) (ctx->nr);
  tmp = sqrt (n * ctx->x2 - ctx->x * ctx->x);
  for (i = 0; i < ctx->ny; i++)
    {
      ctx->pcc[i] = (n * ctx->xy[i] - ctx->x * ctx->y[i]) / tmp /
	sqrt (n * ctx->y2[i] - ctx->y[i] * ctx->y[i]);
    }
}

double
pcc_get_pcc (pcc_context ctx, int ny)
{
  if (ny < 0 || ny >= ctx->ny)
    {
      ERROR (-1, "invalid Y index: %d", ny);
    }
  return ctx->pcc[ny];
}

void
pcc_free (pcc_context ctx)
{
  free (ctx->y);
  free (ctx->y2);
  free (ctx->xy);
  free (ctx->pcc);
  free (ctx->flags);
  free (ctx);
}
