/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Portable subset of the FreeBSD sbuf(9) API for non-FreeBSD hosts
 * (e.g. Ubuntu).  Only the calls used by ediagcbor are implemented.
 *
 * Copyright (c) 2000-2008 Poul-Henning Kamp
 * Copyright (c) 2000-2008 Dag-Erling Coïdan Smørgrav
 * Copyright (c) 2026 ediagcbor contributors (portability trim)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_SBUF_H_
#define	_SYS_SBUF_H_

#include <sys/types.h>

struct sbuf {
	char	*s_buf;
	int	 s_error;
	ssize_t	 s_size;
	ssize_t	 s_len;
#define	SBUF_FIXEDLEN	0x00000000
#define	SBUF_AUTOEXTEND	0x00000001
#define	SBUF_DYNAMIC	0x00010000
#define	SBUF_FINISHED	0x00020000
#define	SBUF_DYNSTRUCT	0x00080000
	int	 s_flags;
};

struct sbuf	*sbuf_new(struct sbuf *, char *, int, int);
#define		 sbuf_new_auto() \
	sbuf_new(NULL, NULL, 0, SBUF_AUTOEXTEND)
int		 sbuf_bcat(struct sbuf *, const void *, size_t);
int		 sbuf_putc(struct sbuf *, int);
int		 sbuf_finish(struct sbuf *);
char		*sbuf_data(struct sbuf *);
ssize_t		 sbuf_len(struct sbuf *);
int		 sbuf_error(const struct sbuf *);
void		 sbuf_delete(struct sbuf *);

#endif /* !_SYS_SBUF_H_ */
