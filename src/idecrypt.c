#include "headers.h"
#include "extern.h"
#include <stdio.h>
#include <gcrypt.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

typedef uint8_t DESKEY[8];

struct pidentd_info
{
  uint32_t checksum;
  uint16_t random;
  uint16_t uid;
  uint32_t date;
  uint32_t ip_local;
  uint32_t ip_remote;
  uint16_t port_local;
  uint16_t port_remote;
};

typedef union
{
  struct pidentd_info info;
  uint32_t            longs[6];
  unsigned char       chars[24];
} PIDENTD_DATA;

#define PIDENTD_KEYSIZE 1024

static unsigned char
to_bin[] =
{
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x3e, 0x80, 0x80, 0x80, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80,
};

static const unsigned char odd_parity[256] =
  {
      1,   1,   2,   2,   4,   4,   7,  7,
      8,   8,  11,  11,  13,  13,  14, 14,
     16,  16,  19,  19,  21,  21,  22,  22,
     25,  25,  26,  26,  28,  28,  31,  31,
     32,  32,  35,  35,  37,  37,  38,  38,
     41,  41,  42,  42,  44,  44,  47,  47,
     49,  49,  50,  50,  52,  52,  55,  55,
     56,  56,  59,  59,  61,  61,  62,  62,
     64,  64,  67,  67,  69,  69,  70,  70,
     73,  73,  74,  74,  76,  76,  79,  79,
     81,  81,  82,  82,  84,  84,  87,  87,
     88,  88,  91,  91,  93,  93,  94,  94,
     97,  97,  98,  98, 100, 100, 103, 103,
    104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118,
    121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134,
    137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151,
    152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167,
    168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182,
    185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199,
    200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214,
    217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230,
    233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247,
    248, 248, 251, 251, 253, 253, 254, 254
};

static void
deskey_set_odd_parity (DESKEY *key)
{
  int i;
  for (i = 0; i < sizeof (*key); i++)
    {
      (*key)[i] = odd_parity[(*key)[i]];
    }
}

static int
string_to_key (unsigned char *keybuf, size_t keylen, DESKEY *key)
{
  int i;
  gcry_cipher_hd_t hd;
  gcry_error_t err;

  memset (key, 0, sizeof (*key));
  for (i = 0; i < keylen; i++)
    {
      unsigned char j = keybuf[i];

      if ((i % 16) < 8)
	(*key)[i % 8] ^= (j << 1);
      else
	{
	  j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f);
	  j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33);
	  j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55);
	  (*key)[7 - (i % 8)] ^= j;
	}
    }

  deskey_set_odd_parity (key);
  err = gcry_cipher_open (&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_open: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      return -1;
    }

  err = gcry_cipher_setkey (hd, key, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_setkey: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }

  err = gcry_cipher_setiv (hd, key, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_setiv: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }

  err = gcry_cipher_encrypt (hd, key, sizeof (key), keybuf, keylen);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_encrypt: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }
  deskey_set_odd_parity (key);

 end:
  gcry_cipher_close (hd);
  return err != GPG_ERR_NO_ERROR;
}

static int
decrypt_packet (unsigned char const *packet, size_t len,
		DESKEY *key, struct pidentd_info *pinfo)
{
  PIDENTD_DATA *data = (PIDENTD_DATA *) pinfo;
  gcry_cipher_hd_t hd;
  gcry_error_t err;
  int i, j;

  if (len != 32)
    {
      info (DEBUG, "%s:%d: bad packet length: %zu", __FILE__, __LINE__, len);
      return -1;
    }
  
  err = gcry_cipher_open (&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_open: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      return -1;
    }

  err = gcry_cipher_setkey (hd, key, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_setkey: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }

  for (i = 0, j = 0; i < 24; i += 3, j += 4)
    {
      data->chars[i] = (to_bin[packet[j]] << 2) + (to_bin[packet[j+1]] >> 4);
      data->chars[i+1] = (to_bin[packet[j+1]] << 4) + (to_bin[packet[j+2]] >> 2);
      data->chars[i+2] = (to_bin[packet[j+2]] << 6) + (to_bin[packet[j+3]]);
    }

  err = gcry_cipher_decrypt (hd, &data->longs[4], 8, NULL, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_decrypt: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }

  data->longs[4] ^= data->longs[2];
  data->longs[5] ^= data->longs[3];

  err = gcry_cipher_decrypt (hd, &data->longs[2], 8, NULL, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_decrypt: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
      goto end;
    }

  data->longs[2] ^= data->longs[0];
  data->longs[3] ^= data->longs[1];

  err = gcry_cipher_decrypt (hd, &data->longs[0], 8, NULL, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      info (DEBUG, "%s:%d: gcry_cipher_decrypt: %s",
	    __FILE__, __LINE__, gpg_strerror (err));
    }
 end:
  gcry_cipher_close (hd);

  if (err != GPG_ERR_NO_ERROR)
    return -1;

  for (i = 1; i < 6; i++)
    {
      data->longs[0] ^= data->longs[i];
    }

  if (data->info.checksum)
    return 1;

  data->info.date = ntohl (data->info.date);
  data->info.uid = ntohs (data->info.uid);

  return 0;
}

static int
idecrypt (unsigned char const *input, size_t len, struct pidentd_info *pinfo)
{
  FILE *fp;
  unsigned char keybuf[PIDENTD_KEYSIZE];
  int result = 1;

  if (!identd_keyfile_name)
    return -1;

  if ((fp = fopen (identd_keyfile_name, "r")) == NULL)
    {
      anubis_error (0, errno, "can't open inetd key file %s",
		    identd_keyfile_name);
      return -1;
    }

  while (fread (keybuf, sizeof (keybuf), 1, fp) == 1)
    {
      DESKEY key;
      if (string_to_key (keybuf, sizeof (keybuf), &key) == 0)
	{
	  if ((result = decrypt_packet (input, len, &key, pinfo)) == 0)
	    break;
	}
    }
  fclose (fp);
  return result;
}

static int inited;

char *
idecrypt_username (char const *text, size_t len)
{
  struct pidentd_info info;
  struct passwd *pwd;

  if (!inited)
    {
      gcry_check_version (NULL);
      inited = 1;
    }
  
  if (idecrypt ((unsigned char const *) text, len, &info))
    return NULL;
  if ((pwd = getpwuid (info.uid)) == NULL)
    return NULL;
  return xstrdup (pwd->pw_name);
}
