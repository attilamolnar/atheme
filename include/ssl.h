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

#ifdef ATHEME_USE_OPENSSL
typedef SSL* ssl_session_t;
#else
typedef void* ssl_session_t;
#endif

E void ssl_init();
E ssl_session_t ssl_session_init_client(int fd);
E void ssl_session_deinit(ssl_session_t session);
