/*
 * atheme-services: A collection of minimalist IRC services
 * base36uid.c: UID management.
 *
 * Copyright (c) 2005-2007 Atheme Project (http://www.atheme.org)
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

DECLARE_MODULE_V1("protocol/base36uid", true, _modinit, NULL, PACKAGE_STRING, "Atheme Development Group <http://www.atheme.org>");

static char new_uid[10];		/* allow for \0 */
static const char* formatstr = "%06d";

static void base36_uid_init(const char *sid)
{
	char buf[BUFSIZE];

	if (ircd->uses_p10)
	{
		me.numeric = sstrdup(uinttobase64(buf, (uint64_t) atoi(me.numeric), 2));
		formatstr = "%03d";
	}

	if (me.numeric != NULL)
		memcpy(new_uid, me.numeric, strlen(me.numeric));
}

static const char *base36_uid_get(void)
{
	static unsigned int current_id = 0;

	snprintf(new_uid + (ircd->uses_p10 ? 2 : 3), sizeof(new_uid) - 3, formatstr, current_id++);
	return (new_uid);
}

uid_provider_t base36_gen = {
	.uid_init = base36_uid_init,
	.uid_get = base36_uid_get,
};

void _modinit(module_t *m)
{
	uid_provider_impl = &base36_gen;
}

void _moddeinit(module_unload_intent_t intent)
{
	uid_provider_impl = NULL;
}
