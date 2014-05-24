/*
 * Copyright (C) 2014 Attila Molnar
 * Copyright (C) 2014 Atheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Low-level SSL wrappers
 *
 */


#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#define ATHEME_USE_OPENSSL
#endif

E void ssl_init();
