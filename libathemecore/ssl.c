/*
 * atheme-services: A collection of minimalist IRC services
 * ssl.c: Low-level SSL wrappers
 *
 * Copyright (c) 2014 Attila Molnar <attilamolnar@hush.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include "atheme.h"

#ifdef ATHEME_USE_OPENSSL
static SSL_CTX* context = NULL;
#endif

void ssl_init()
{
#ifdef ATHEME_USE_OPENSSL
	SSL_library_init();
	SSL_load_error_strings();

	context = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_mode(context, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);
#endif
}

ssl_session_t ssl_session_init_client(int fd)
{
	ssl_session_t session = NULL;

#ifdef ATHEME_USE_OPENSSL
	session = SSL_new(context);
	SSL_set_fd(session, fd);
#else
	soft_assert(0);
#endif

	return session;
}

void ssl_session_deinit(ssl_session_t session)
{
	return_if_fail(session != NULL);

#ifdef ATHEME_USE_OPENSSL
	SSL_shutdown(session);
	SSL_free(session);
#else
	soft_assert(0);
#endif
}
