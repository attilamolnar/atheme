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

int ssl_handshake(ssl_session_t session)
{
#ifdef ATHEME_USE_OPENSSL
	int ret;
	int sslerr;

	ret = SSL_connect(session);
	if (ret > 0)
	{
		/* Handshake was successfully completed, we may begin sending and receiving data
		 */
		return 1;
	}
	else if (ret < 0)
	{
		/* Handshake wasn't successful this time, see why.
		 * If the error is SSL_ERROR_WANT_READ/SSL_ERROR_WANT_WRITE then we need to
		 * retry the handshake again later, otherwise it's a fatal error.
		 */
		sslerr = SSL_get_error(session, ret);
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE)
			return 0;

		return -1;
	}
	else
	{
		/* Handshake wasn't successful because we got a closure alert
		 */
		return -1;
	}
#else
	soft_assert(0);
	return -1;
#endif
}

int ssl_send(ssl_session_t session, const void *buffer, size_t size)
{
#ifdef ATHEME_USE_OPENSSL
	return SSL_write(session, buffer, size);
#else
	soft_assert(0);
	return -1;
#endif
}

int ssl_recv(ssl_session_t session, void *buffer, size_t size)
{
#ifdef ATHEME_USE_OPENSSL
	return SSL_read(session, buffer, size);
#else
	soft_assert(0);
	return -1;
#endif
}

const char *ssl_get_ciphersuite(ssl_session_t session)
{
#ifdef ATHEME_USE_OPENSSL
	return SSL_get_cipher(session);
#else
	soft_assert(0);
	return "SSL unavailable";
#endif
}

const char *ssl_get_cert_fingerprint(ssl_session_t session, ssl_cert_fingerprint_hash_t hash)
{
#ifdef ATHEME_USE_OPENSSL
	static char fingerprintstr[EVP_MAX_MD_SIZE*2+1];
	const EVP_MD *mdalgo;
	X509 *cert;
	unsigned char raw[EVP_MAX_MD_SIZE];
	unsigned int numrawbytes;
	size_t i;

	if (hash == SSL_CERT_FINGERPRINT_SHA1)
		mdalgo = EVP_sha1();
	else
	{
		slog(LG_DEBUG, "ssl_get_cert_fingerprint(): unknown hash: %d", hash);
		return NULL;
	}

	cert = SSL_get_peer_certificate(session);
	if (!cert)
	{
		slog(LG_INFO, "ssl_get_cert_fingerprint(): peer did not send a certificate");
		return NULL;
	}

	if (!X509_digest(cert, mdalgo, raw, &numrawbytes))
	{
		slog(LG_DEBUG, "ssl_get_cert_fingerprint(): X509_digest() failed");
		X509_free(cert);
		return NULL;
	}

	for (i = 0; i < numrawbytes; i++)
		snprintf(fingerprintstr + i*2, sizeof(fingerprintstr) - i*2, "%02x", raw[i]);

	X509_free(cert);
	return fingerprintstr;
#else
	soft_assert(0);
	return NULL;
#endif
}
