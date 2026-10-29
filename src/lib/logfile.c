/*
 * Log file helpers shared by apmond's log.c and the host tests:
 * repeated message suppression and trimming to max_log_entries.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apmon.h"

void apmon_dedupe_init(struct apmon_dedupe *d)
{
	memset(d, 0, sizeof(*d));
}

/*
 * As syslog: an identical consecutive message is counted, not written, for up to
 * APMON_DEDUPE_SECONDS. Returns 1 to write msg, 0 to drop it. When it returns 1 after
 * suppressed repeats, summary holds "previous message repeated N times" to write first.
 */
int apmon_dedupe_check(struct apmon_dedupe *d, const char *msg, int64_t now_s, char *summary, size_t len)
{
	summary[0] = '\0';

	if (d->have_last && strcmp(msg, d->last) == 0) {
		if (now_s - d->written_s < APMON_DEDUPE_SECONDS) {
			d->repeats++;
			return 0;
		}
	}

	if (d->repeats > 0) {
		snprintf(summary, len, "previous message repeated %u times", d->repeats);
	}
	snprintf(d->last, sizeof(d->last), "%s", msg);
	d->have_last = 1;
	d->repeats = 0;
	d->written_s = now_s;
	return 1;
}

int apmon_count_lines(const char *path)
{
	FILE *f = fopen(path, "r");
	int c;
	int prev = '\n';
	int n = 0;

	if (f == NULL) {
		return 0;
	}
	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			n++;
		}
		prev = c;
	}
	fclose(f);
	if (prev != '\n') {
		/* last line without a newline */
		n++;
	}
	return n;
}

/*
 * Keep the newest keep lines of path (rewritten in place, so the inode stays).
 * Returns the number of lines left, or -1 on error (the file is left as it was).
 */
int apmon_trim_log(const char *path, int keep)
{
	FILE *f;
	char *buf;
	long size;
	long pos;
	int seen = 0;

	if (keep < 1) {
		return -1;
	}
	f = fopen(path, "r");
	if (f == NULL) {
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	size = ftell(f);
	if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}

	buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(f);
		return -1;
	}
	size = (long)fread(buf, 1, (size_t)size, f);
	fclose(f);

	/* walk back from the end over keep line ends; pos ends at the start of the oldest kept line */
	pos = size;
	if (pos > 0 && buf[pos - 1] == '\n') {
		pos--;
	}
	while (pos > 0) {
		if (buf[pos - 1] == '\n') {
			seen++;
			if (seen == keep) {
				break;
			}
		}
		pos--;
	}

	f = fopen(path, "w");
	if (f == NULL) {
		free(buf);
		return -1;
	}
	fwrite(buf + pos, 1, (size_t)(size - pos), f);
	fclose(f);
	free(buf);

	return apmon_count_lines(path);
}
