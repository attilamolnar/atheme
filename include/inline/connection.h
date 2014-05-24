#ifndef INLINE_CONNECTION_H
#define INLINE_CONNECTION_H

/*
 * connection_count()
 *
 * inputs:
 *       none
 *
 * outputs:
 *       number of connections tracked
 *
 * side effects:
 *       none
 */
static inline int connection_count(void)
{
	return MOWGLI_LIST_LENGTH(&connection_list);
}

inline connection_t *connection_open_tcp(char *host, char *vhost, unsigned int port,
	void (*read_handler)(connection_t *),
	void (*write_handler)(connection_t *))
{
	return connection_open_tcp_ssl(host, vhost, port, read_handler, write_handler, NULL);
}

#endif
