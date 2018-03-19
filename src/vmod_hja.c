#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* need vcl.h before vrt.h for vmod_evet_f typedef */
#include <cache/cache.h>
#include <vcl.h>

#ifndef VRT_H_INCLUDED
#include <vrt.h>
#endif

#ifndef VDEF_H_INCLUDED
#include <vdef.h>
#endif



#include "vcc_hja_if.h"
#include <vtim.h>
#include "vsb.h"

const size_t infosz = 64;
char *info;

/*
 * handle vmod internal state, vmod init/fini and/or varnish callback
 * (un)registration here.
 *
 * malloc'ing the info buffer is only indended as a demonstration, for any
 * real-world vmod, a fixed-sized buffer should be a global variable
 */

int v_matchproto_(vmod_event_f)
    event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
  char ts[VTIM_FORMAT_SIZE];
  const char *event = NULL;

  (void)ctx;
  (void)priv;

  switch (e) {
    case VCL_EVENT_LOAD:
      info = malloc(infosz);
      if (!info) return (-1);
      event = "loaded";
      break;
    case VCL_EVENT_WARM:
      event = "warmed";
      break;
    case VCL_EVENT_COLD:
      event = "cooled";
      break;
    case VCL_EVENT_DISCARD:
      free(info);
      return (0);
      break;
    default:
      return (0);
  }
  AN(event);
  VTIM_format(VTIM_real(), ts);
  snprintf(info, infosz, "vmod_hja %s at %s", event, ts);

  return (0);
}

VCL_STRING
vmod_info(VRT_CTX)
{
  (void)ctx;

  return (info);
}

static void first_path_to_lower(char *c)
{
  int track = 0;
  char *url = c;
  for (; *c; c++) {
    if (*c == '/' && track == 0) {
      track = 1;
      continue;
    }
    if (track == 1) {
      *c = tolower(*c);
    }
    if ((*c == '/' || *c == '?') && track == 1) {
      break;
    }
  }
  // Check if we have a / at the end and remove it

  if (url[strlen(url) - 1] == '/') {
    url[strlen(url) - 1] = '\0';
  }
}

VCL_STRING
vmod_first_folder_lower(VRT_CTX, VCL_STRING name)
{
  char *p;
  unsigned u, v;

  char *orig_string;
  orig_string = strdup(name);
  if(strlen(orig_string) > 1) {
    first_path_to_lower(orig_string);
  }

  u = WS_Reserve(ctx->ws, 0); /* Reserve some work space */
  p = ctx->ws->f;             /* Front of workspace area */
  v = snprintf(p, u, "%s", orig_string);
  free(orig_string);
  v++;
  if (v > u) {
    /* No space, reset and leave */
    WS_Release(ctx->ws, 0);
    return (NULL);
  }
  /* Update work space with what we've used */
  WS_Release(ctx->ws, v);
  return (p);
}
