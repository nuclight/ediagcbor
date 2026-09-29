/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Portable subset of FreeBSD sbuf(9) for non-FreeBSD builds.
 * See compat/sys/sbuf.h for copyright.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "compat/sys/sbuf.h"

#define	SBUF_HASROOM(s)		((s)->s_len < (s)->s_size - 1)
#define	SBUF_CANEXTEND(s)	((s)->s_flags & SBUF_AUTOEXTEND)
#define	SBUF_ISDYNAMIC(s)	((s)->s_flags & SBUF_DYNAMIC)
#define	SBUF_ISDYNSTRUCT(s)	((s)->s_flags & SBUF_DYNSTRUCT)
#define	SBUF_ISFINISHED(s)	((s)->s_flags & SBUF_FINISHED)

static int
sbuf_extend(struct sbuf *s, ssize_t add)
{
	char *newbuf;
	ssize_t newsize;

	if (!SBUF_CANEXTEND(s) || s->s_error != 0)
		return (-1);
	newsize = s->s_size + (add > s->s_size ? add : s->s_size);
	if (newsize < 64)
		newsize = 64;
	newbuf = realloc(s->s_buf, (size_t)newsize);
	if (newbuf == NULL) {
		s->s_error = ENOMEM;
		return (-1);
	}
	s->s_buf = newbuf;
	s->s_size = newsize;
	s->s_flags |= SBUF_DYNAMIC;
	return (0);
}

struct sbuf *
sbuf_new(struct sbuf *s, char *buf, int length, int flags)
{
	int dynstruct;

	dynstruct = 0;
	if (s == NULL) {
		s = calloc(1, sizeof(*s));
		if (s == NULL)
			return (NULL);
		dynstruct = 1;
	} else
		memset(s, 0, sizeof(*s));

	s->s_flags = flags & (SBUF_AUTOEXTEND);
	if (dynstruct)
		s->s_flags |= SBUF_DYNSTRUCT;

	if (buf != NULL) {
		s->s_buf = buf;
		s->s_size = length;
		s->s_len = 0;
	} else {
		s->s_size = length > 0 ? length : 64;
		s->s_buf = malloc((size_t)s->s_size);
		if (s->s_buf == NULL) {
			if (dynstruct)
				free(s);
			return (NULL);
		}
		s->s_flags |= SBUF_DYNAMIC;
		s->s_len = 0;
	}
	s->s_buf[0] = '\0';
	s->s_error = 0;
	return (s);
}

int
sbuf_bcat(struct sbuf *s, const void *data, size_t len)
{
	const char *p;

	if (s == NULL || SBUF_ISFINISHED(s) || s->s_error != 0)
		return (-1);
	p = data;
	while (len > 0) {
		if (!SBUF_HASROOM(s) && sbuf_extend(s, (ssize_t)len) != 0)
			return (-1);
		if (!SBUF_HASROOM(s)) {
			s->s_error = ENOMEM;
			return (-1);
		}
		s->s_buf[s->s_len++] = *p++;
		len--;
	}
	return (0);
}

int
sbuf_putc(struct sbuf *s, int c)
{
	unsigned char ch;

	ch = (unsigned char)c;
	return (sbuf_bcat(s, &ch, 1));
}

int
sbuf_finish(struct sbuf *s)
{

	if (s == NULL)
		return (-1);
	if (s->s_error != 0)
		return (-1);
	if (!SBUF_ISFINISHED(s)) {
		if (!SBUF_HASROOM(s) && sbuf_extend(s, 1) != 0)
			return (-1);
		s->s_buf[s->s_len] = '\0';
		s->s_flags |= SBUF_FINISHED;
	}
	return (0);
}

char *
sbuf_data(struct sbuf *s)
{

	return (s != NULL ? s->s_buf : NULL);
}

ssize_t
sbuf_len(struct sbuf *s)
{

	return (s != NULL ? s->s_len : -1);
}

int
sbuf_error(const struct sbuf *s)
{

	return (s != NULL ? s->s_error : EINVAL);
}

void
sbuf_delete(struct sbuf *s)
{

	if (s == NULL)
		return;
	if (SBUF_ISDYNAMIC(s))
		free(s->s_buf);
	if (SBUF_ISDYNSTRUCT(s))
		free(s);
}
