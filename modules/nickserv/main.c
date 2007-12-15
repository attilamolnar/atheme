/*
 * Copyright (c) 2005 Atheme Development Group
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains the main() routine.
 *
 * $Id: main.c 7779 2007-03-03 13:55:42Z pippijn $
 */

#include "atheme.h"

DECLARE_MODULE_V1
(
	"nickserv/main", FALSE, _modinit, _moddeinit,
	"$Id: main.c 7779 2007-03-03 13:55:42Z pippijn $",
	"Atheme Development Group <http://www.atheme.org>"
);

list_t ns_cmdtree;
list_t ns_helptree;

/* main services client routine */
static void nickserv(sourceinfo_t *si, int parc, char *parv[])
{
	char *cmd;
        char *text;
	char orig[BUFSIZE];

	/* this should never happen */
	if (parv[0][0] == '&')
	{
		slog(LG_ERROR, "services(): got parv with local channel: %s", parv[0]);
		return;
	}

	/* make a copy of the original for debugging */
	strlcpy(orig, parv[parc - 1], BUFSIZE);

	/* lets go through this to get the command */
	cmd = strtok(parv[parc - 1], " ");
	text = strtok(NULL, "");

	if (!cmd)
		return;
	if (*cmd == '\001')
	{
		handle_ctcp_common(si, cmd, text);
		return;
	}

	/* take the command through the hash table */
	command_exec_split(si->service, si, cmd, text, &ns_cmdtree);
}

struct
{
	char *nickstring, *accountstring;
} nick_account_trans[] =
{
	/* command descriptions */
	{ "Reclaims use of a nickname.", "Disconnects an old session." },
	{ "Prevents a nickname from expiring.", "Prevents an account from expiring." },
	{ "Registers a nickname.", "Registers an account." },
	{ "Lists nicknames registered matching a given pattern.", "Lists accounts matching a given pattern." },
	{ "Lists nicknames registered to an e-mail address.", "Lists accounts registered to an e-mail address." },
	{ "Resets a nickname password.", "Resets an account password." },
	{ "Returns a nickname to its owner.", "Returns a account to its owner." },
	{ "Verifies a nickname registration.", "Verifies an account registration." },

	/* messages */
	{ "Usage: FREEZE <nickname> <ON|OFF> [reason]", "Usage: FREEZE <account> <ON|OFF> [reason]" },
	{ "\2%s\2 is not a registered nickname.", "\2%s\2 is not a registered account." },
	{ "Syntax: INFO <nickname>", "Syntax: INFO <account>" },
	{ "No nicknames matched pattern \2%s\2", "No accounts matched pattern \2%s\2" },
	{ "Nicknames matching e-mail address \2%s\2:", "Accounts matching e-mail address \2%s\2:" },
	{ "No nicknames matched e-mail address \2%s\2", "No accounts matched e-mail address \2%s\2" },
	{ "%s marked the nickname \2%s\2.", "%s marked the account \2%s\2." },
	{ "%s unmarked the nickname \2%s\2.", "%s unmarked the account \2%s\2." },
	{ "\2%s\2 has too many nicknames registered.", "\2%s\2 has too many accounts registered." },
	{ "An email containing nickname activation instructions has been sent to \2%s\2.", "An email containing account activation instructions has been sent to \2%s\2." },
	{ "If you do not complete registration within one day your nickname will expire.", "If you do not complete registration within one day your account will expire." },
	{ "%s registered the nick \2%s\2 and gained services operator privileges.", "%s registered the account \2%s\2 and gained services operator privileges." },
	{ "Syntax: RESETPASS <nickname>", "Syntax: RESETPASS <account>" },
	{ "Overriding MARK placed by %s on the nickname %s.", "Overriding MARK placed by %s on the account %s." },
	{ "The password for the nickname %s has been changed to %s.", "The password for the account %s has been changed to %s." },
	{ "This operation cannot be performed on %s, because the nickname has been marked by %s.", "This operation cannot be performed on %s, because the account has been marked by %s." },
	{ "The password for the nickname %s has been changed to %s.", "The password for the account %s has been changed to %s." },
	{ "%s reset the password for the nickname %s", "%s reset the password for the account %s" },
	{ "Usage: RETURN <nickname> <e-mail address>", "Usage: RETURN <account> <e-mail address>" },
	{ "%s returned the nickname \2%s\2 to \2%s\2", "%s returned the account \2%s\2 to \2%s\2" },
	{ "Syntax: SENDPASS <nickname>", "Syntax: SENDPASS <account>" },
	{ "Manipulates metadata entries associated with a nickname.", "Manipulates metadata entries associated with an account." },
	{ "You cannot use your nickname as a password.", "You cannot use your account name as a password." },
	{ "Changes the password associated with your nickname.", "Changes the password associated with your account." },
	{ "Syntax: TAXONOMY <nick>", "Syntax: TAXONOMY <account>" },
	{ "Syntax: VERIFY <operation> <nickname> <key>", "Syntax: VERIFY <operation> <account> <key>" },
	{ "Syntax: VHOST <nick> [vhost]", "Syntax: VHOST <account> [vhost]" },
	{ NULL, NULL }
};

static void nickserv_handle_nickchange(void *user_p)
{
	user_t *u;
	mynick_t *mn;
	hook_nick_enforce_t hdata;

	u = (user_t *) user_p;

	if (nicksvs.me == NULL || nicksvs.no_nick_ownership)
		return;

	/* They're logged in, don't send them spam -- jilles */
	if (u->myuser)
		u->flags |= UF_SEENINFO;

	/* Also don't send it if they came back from a split -- jilles */
	if (!(u->server->flags & SF_EOB))
		u->flags |= UF_SEENINFO;

	if (!(mn = mynick_find(u->nick)))
	{
		if (!nicksvs.spam)
			return;

		if (!(u->flags & UF_SEENINFO))
		{
			notice(nicksvs.nick, u->nick, "Welcome to %s, %s! Here on %s, we provide services to enable the "
			       "registration of nicknames and channels! For details, type \2/%s%s help\2 and \2/%s%s help\2.",
			       me.netname, u->nick, me.netname, (ircd->uses_rcommand == FALSE) ? "msg " : "", nicksvs.disp, (ircd->uses_rcommand == FALSE) ? "msg " : "", chansvs.disp);

			u->flags |= UF_SEENINFO;
		}

		return;
	}

	if (u->myuser == mn->owner)
	{
		mn->lastseen = CURRTIME;
		return;
	}

	/* OpenServices: is user on access list? -nenolod */
	if (myuser_access_verify(u, mn->owner))
	{
		mn->lastseen = CURRTIME;
		return;
	}

	notice(nicksvs.nick, u->nick, _("This nickname is registered. Please choose a different nickname, or identify via \2/%s%s identify <password>\2."),
		(ircd->uses_rcommand == FALSE) ? "msg " : "", nicksvs.disp);
	hdata.u = u;
	hdata.mn = mn;
	hook_call_event("nick_enforce", &hdata);
}

static void nickserv_config_ready(void *unused)
{
	int i;

        if (nicksvs.me)
                del_service(nicksvs.me);

        nicksvs.me = add_service(nicksvs.nick, nicksvs.user,
                                 nicksvs.host, nicksvs.real,
				 nickserv, &ns_cmdtree);
        nicksvs.disp = nicksvs.me->disp;

	if (nicksvs.no_nick_ownership)
		for (i = 0; nick_account_trans[i].nickstring != NULL; i++)
			itranslation_create(nick_account_trans[i].nickstring,
					nick_account_trans[i].accountstring);
	else
		for (i = 0; nick_account_trans[i].nickstring != NULL; i++)
			itranslation_destroy(nick_account_trans[i].nickstring);

        hook_del_hook("config_ready", nickserv_config_ready);
}

void _modinit(module_t *m)
{
        hook_add_event("config_ready");
        hook_add_hook("config_ready", nickserv_config_ready);

        hook_add_event("nick_check");
        hook_add_hook("nick_check", nickserv_handle_nickchange);

        if (!cold_start)
        {
                nicksvs.me = add_service(nicksvs.nick, nicksvs.user,
			nicksvs.host, nicksvs.real, nickserv, &ns_cmdtree);
                nicksvs.disp = nicksvs.me->disp;
        }
	authservice_loaded++;
}

void _moddeinit(void)
{
        if (nicksvs.me)
	{
                del_service(nicksvs.me);
		nicksvs.me = NULL;
	}
	authservice_loaded--;
}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
