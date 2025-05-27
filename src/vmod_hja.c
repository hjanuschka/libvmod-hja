#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

// JWT validation using proper SHA256 and HMAC-SHA256 implementation
// The standard JWT header already base64 encoded. Equates to {"alg": "HS256", "typ": "JWT"}
static const char* jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// SHA256 implementation
typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

#define SHA256_BLOCK_SIZE 32

// SHA256 constants
static const unsigned int k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const unsigned char data[])
{
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len)
{
    unsigned int i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, unsigned char hash[])
{
    unsigned int i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

// HMAC-SHA256 implementation
static void hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       unsigned char *out)
{
    unsigned char k_pad[64];
    unsigned char tk[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    int i;

    if (key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tk);
        key = tk;
        key_len = SHA256_BLOCK_SIZE;
    }

    memset(k_pad, 0, sizeof(k_pad));
    memcpy(k_pad, key, key_len);

    for (i = 0; i < 64; i++) {
        k_pad[i] ^= 0x36;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, out);

    memset(k_pad, 0, sizeof(k_pad));
    memcpy(k_pad, key, key_len);

    for (i = 0; i < 64; i++) {
        k_pad[i] ^= 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, out, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, out);
}

// Base64 URL encoding/decoding functions
static const char base64_url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int base64_url_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static size_t base64_url_decode(const char *input, unsigned char *output, size_t output_len) {
    size_t input_len = strlen(input);
    size_t output_pos = 0;
    size_t i;
    
    for (i = 0; i < input_len && output_pos < output_len - 1; i += 4) {
        int b1 = base64_url_decode_char(input[i]);
        int b2 = (i + 1 < input_len) ? base64_url_decode_char(input[i + 1]) : 0;
        int b3 = (i + 2 < input_len) ? base64_url_decode_char(input[i + 2]) : 0;
        int b4 = (i + 3 < input_len) ? base64_url_decode_char(input[i + 3]) : 0;
        
        if (b1 == -1 || b2 == -1) break;
        
        output[output_pos++] = (b1 << 2) | (b2 >> 4);
        
        if (i + 2 < input_len && output_pos < output_len - 1) {
            if (b3 == -1) break;
            output[output_pos++] = (b2 << 4) | (b3 >> 2);
        }
        
        if (i + 3 < input_len && output_pos < output_len - 1) {
            if (b4 == -1) break;
            output[output_pos++] = (b3 << 6) | b4;
        }
    }
    
    output[output_pos] = '\0';
    return output_pos;
}

static size_t base64_url_encode(const unsigned char *input, size_t input_len, char *output) {
    size_t output_pos = 0;
    size_t i;
    
    for (i = 0; i < input_len; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;
        
        output[output_pos++] = base64_url_chars[b1 >> 2];
        output[output_pos++] = base64_url_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        
        if (i + 1 < input_len) {
            output[output_pos++] = base64_url_chars[((b2 & 0x0f) << 2) | (b3 >> 6)];
        }
        
        if (i + 2 < input_len) {
            output[output_pos++] = base64_url_chars[b3 & 0x3f];
        }
    }
    
    output[output_pos] = '\0';
    return output_pos;
}

// Simple JSON value extraction
static long extract_json_number(const char *json, const char *key) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    
    char *pos = strstr(json, search_key);
    if (!pos) return 0;
    
    pos += strlen(search_key);
    while (*pos == ' ' || *pos == '\t') pos++; // skip whitespace
    
    return atol(pos);
}

static void synth(VRT_CTX, char *contents, unsigned long size);

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

void vmod_pixel(VRT_CTX)
{
  synth(
              ctx,
                      "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
                              43);
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

int
vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	return (event_function(ctx, priv, e));
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

  u = WS_ReserveSize(ctx->ws, strlen(orig_string)*2); /* Reserve some work space */
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

static void
synth(VRT_CTX, char *contents, unsigned long size)
{
    if ((ctx->method == VCL_MET_SYNTH) ||
                (ctx->method == VCL_MET_BACKEND_ERROR)) {
            struct vsb *vsb;
            CAST_OBJ_NOTNULL(vsb, ctx->specific, VSB_MAGIC);
            VSB_bcat(vsb, contents, size);
        }
}

VCL_STRING
vmod_validate_jwt(VRT_CTX, VCL_STRING token, VCL_STRING secret)
{
    if (!token || !secret) {
        return "false";
    }
    
    // Make a copy of the token since strtok modifies it
    size_t token_len = strlen(token);
    char *token_copy = malloc(token_len + 1);
    if (!token_copy) {
        return "false";
    }
    strcpy(token_copy, token);
    
    // Split the JWT into its three parts
    char *header_b64 = strtok(token_copy, ".");
    char *payload_b64 = strtok(NULL, ".");
    char *signature_b64 = strtok(NULL, ".");
    
    if (!header_b64 || !payload_b64 || !signature_b64) {
        free(token_copy);
        return "false";
    }
    
    // Verify the header matches our expected header
    if (strcmp(header_b64, jwtHeader) != 0) {
        free(token_copy);
        return "false";
    }
    
    // Decode the payload to check expiration
    unsigned char payload_decoded[512];
    size_t payload_len = base64_url_decode(payload_b64, payload_decoded, sizeof(payload_decoded));
    
    if (payload_len == 0) {
        free(token_copy);
        return "false";
    }
    
    // Check expiration if present
    long exp_time = extract_json_number((char*)payload_decoded, "exp");
    if (exp_time > 0) {
        time_t current_time = time(NULL);
        if (current_time >= exp_time) {
            free(token_copy);
            return "false";
        }
    }
    
    // Create the signing input (header.payload)
    size_t signing_input_len = strlen(header_b64) + 1 + strlen(payload_b64);
    char *signing_input = malloc(signing_input_len + 1);
    if (!signing_input) {
        free(token_copy);
        return "false";
    }
    
    snprintf(signing_input, signing_input_len + 1, "%s.%s", header_b64, payload_b64);
    
    // Calculate the expected signature using proper HMAC-SHA256
    unsigned char expected_signature[SHA256_BLOCK_SIZE];
    hmac_sha256((unsigned char*)secret, strlen(secret),
                (unsigned char*)signing_input, signing_input_len,
                expected_signature);
    
    // Encode the expected signature as base64 URL
    char expected_signature_b64[64];
    base64_url_encode(expected_signature, SHA256_BLOCK_SIZE, expected_signature_b64);
    
    // Remove padding from expected signature
    char *ptr = expected_signature_b64 + strlen(expected_signature_b64);
    while (ptr > expected_signature_b64 && *(ptr - 1) == '=') {
        ptr--;
    }
    *ptr = '\0';
    
    // Compare signatures
    int signatures_match = (strcmp(signature_b64, expected_signature_b64) == 0);
    
    // Clean up
    free(token_copy);
    free(signing_input);
    
    // Allocate result in Varnish workspace
    char *result;
    unsigned u, v;
    
    u = WS_ReserveSize(ctx->ws, 16);
    result = ctx->ws->f;
    
    if (signatures_match) {
        v = snprintf(result, u, "true");
    } else {
        v = snprintf(result, u, "false");
    }
    
    v++;
    if (v > u) {
        WS_Release(ctx->ws, 0);
        return signatures_match ? "true" : "false";
    }
    
    WS_Release(ctx->ws, v);
    return result;
}

