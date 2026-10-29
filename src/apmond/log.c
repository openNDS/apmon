/*
 * apmond logging, as apmond 1.x / mesh11sd:
 * - messages above debuglevel are dropped; identical consecutive messages are dropped
 * - err and notice go to syslog AND the log file; info and debug go to the log file only
 * - log file <log_mountpoint>/apmond/apmond_log.log (/tmp/apmond/apmond_log.log by default),
 *   lines "<date> daemon.<level> apmond[<pid>]: [<n>] <message>", trimmed to max_log_entries
 * - a log_mountpoint that is not mounted disables the log file (it would fill flash)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include "apmond.h"

#define MIN_FREE_KB 10

static char log_file[192];
static int log_file_ok;
static int log_lines;
static unsigned long entry_num;
static char last_message[512];

static int is_mountpoint(const char *path)
{
	FILE *f = fopen("/proc/mounts", "r");
	char line[512];
	int found = 0;

	if (f == NULL) {
		return 0;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char dev[256];
		char dir[256];

		if (sscanf(line, "%255s %255s", dev, dir) != 2) {
			continue;
		}
		if (strcmp(dir, path) == 0) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

/*
 * Resolve the log file path from log_mountpoint, as 1.x.
 * Returns 0 and fills path, or -1 with a reason when file logging is disabled.
 * create = 1 also creates the directory (daemon); the CLI passes 0.
 */
int apmond_log_path(const struct apmond_config *cfg, char *path, size_t path_len, char *reason, size_t reason_len,
		    int create)
{
	char mp[128];
	char dir[160];
	size_t len;

	snprintf(mp, sizeof(mp), "%s", cfg->log_mountpoint);
	len = strlen(mp);
	while (len > 1 && mp[len - 1] == '/') {
		mp[len - 1] = '\0';
		len--;
	}
	if (len == 0) {
		snprintf(mp, sizeof(mp), "/tmp");
	}

	reason[0] = '\0';

	if (strcmp(mp, "/tmp") != 0) {
		if (!is_mountpoint(mp)) {
			snprintf(reason, reason_len,
				 "Log location [ %s ] is NOT a mountpoint - logs would fill storage space - logging disabled", mp);
			return -1;
		}
		snprintf(dir, sizeof(dir), "%s/apmond", mp);
		if (create && mkdir(dir, 0755) != 0 && errno != EEXIST) {
			snprintf(reason, reason_len, "log_mountpoint [ %s ] is not writable - falling back to /tmp", mp);
			snprintf(mp, sizeof(mp), "/tmp");
		}
	}

	snprintf(dir, sizeof(dir), "%s/apmond", mp);
	if (create) {
		mkdir(dir, 0755);
	}
	snprintf(path, path_len, "%s/apmond_log.log", dir);
	return 0;
}

static int count_lines(const char *path)
{
	FILE *f = fopen(path, "r");
	int c;
	int n = 0;

	if (f == NULL) {
		return 0;
	}
	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			n++;
		}
	}
	fclose(f);
	return n;
}

void apmond_log_init(void)
{
	char reason[256];

	if (apmond_log_path(&apmond.cfg, log_file, sizeof(log_file), reason, sizeof(reason), 1) == 0) {
		log_file_ok = 1;
		log_lines = count_lines(log_file);
		if (reason[0] != '\0') {
			LOG_NOTICE_("%s", reason);
		}
		LOG_INFO_("option log_mountpoint [ %s ], log file [ %s ]", apmond.cfg.log_mountpoint, log_file);
	} else {
		log_file_ok = 0;
		syslog(LOG_ERR, "%s", reason);
	}
}

/* Keep the last max_log_entries lines */
static void trim_log(void)
{
	FILE *f;
	char *buf;
	long size;
	long pos;
	int keep = apmond.cfg.max_log_entries;
	int seen = 0;

	f = fopen(log_file, "r");
	if (f == NULL) {
		return;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(f);
		return;
	}
	size = (long)fread(buf, 1, (size_t)size, f);
	fclose(f);

	/* walk back over keep lines */
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

	f = fopen(log_file, "w");
	if (f != NULL) {
		fwrite(buf + pos, 1, (size_t)(size - pos), f);
		fclose(f);
	}
	free(buf);
	log_lines = keep;
}

static void write_file(const char *level, const char *msg)
{
	struct statvfs vfs;
	char date[64];
	time_t now = time(NULL);
	FILE *f;
	int is_new;

	if (statvfs(log_file, &vfs) == 0 || statvfs("/tmp", &vfs) == 0) {
		unsigned long long free_kb = (unsigned long long)vfs.f_bavail * vfs.f_frsize / 1024;

		if (free_kb <= MIN_FREE_KB) {
			syslog(LOG_ERR, "Log file too big, please archive contents and reduce max_log_entries");
			return;
		}
	}

	is_new = access(log_file, F_OK) != 0;
	f = fopen(log_file, "a");
	if (f == NULL) {
		return;
	}

	/* busybox date format, as 1.x: "Thu Oct 29 14:45:00 GMT 2026" */
	strftime(date, sizeof(date), "%a %b %e %H:%M:%S %Z %Y", localtime(&now));

	if (is_new) {
		fprintf(f, "%s New log file created\n", date);
		log_lines = 1;
	}
	fprintf(f, "%s daemon.%s apmond[%d]: %s\n", date, level, (int)getpid(), msg);
	fclose(f);
	log_lines++;

	if (log_lines > apmond.cfg.max_log_entries) {
		trim_log();
	}
}

void apmond_log(int level, const char *fmt, ...)
{
	static const int prio[] = { LOG_ERR, LOG_NOTICE, LOG_INFO, LOG_DEBUG };
	static const char *names[] = { "err", "notice", "info", "debug" };
	char msg[512];
	char line[540];
	va_list ap;

	if (level < 0) {
		level = 0;
	}
	if (level > 3) {
		level = 3;
	}
	if (level > apmond.cfg.debuglevel && level > 0) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (strcmp(msg, last_message) == 0) {
		return;
	}
	snprintf(last_message, sizeof(last_message), "%s", msg);

	entry_num++;
	snprintf(line, sizeof(line), "[%lu] %s", entry_num, msg);

	if (!log_file_ok) {
		/* no log file: everything goes to syslog, as 1.x before the location is known */
		if (level <= 1 || log_file[0] == '\0') {
			syslog(prio[level], "%s", line);
		}
		return;
	}

	if (level <= 1) {
		syslog(prio[level], "%s", line);
	}
	write_file(names[level], line);
}

/* apmond read_log [-f]: print the log, then (follow) print new lines as they are written */
int apmond_read_log(int follow)
{
	char path[192];
	char reason[256];
	char buf[4096];
	struct stat st;
	FILE *f;
	long offset = 0;
	ino_t inode = 0;

	if (apmond_log_path(&apmond.cfg, path, sizeof(path), reason, sizeof(reason), 0) != 0) {
		fprintf(stderr, "%s\n", reason);
		return 1;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "no log file %s\n", path);
		return 1;
	}
	while (fgets(buf, sizeof(buf), f) != NULL) {
		fputs(buf, stdout);
	}
	offset = ftell(f);
	fclose(f);
	fflush(stdout);

	if (stat(path, &st) == 0) {
		inode = st.st_ino;
	}

	while (follow) {
		sleep(1);

		if (stat(path, &st) != 0) {
			continue;
		}
		if (st.st_ino != inode || st.st_size < offset) {
			/* trimmed or recreated: carry on from the last line of the new file */
			inode = st.st_ino;
			offset = st.st_size;
			f = fopen(path, "r");
			if (f != NULL) {
				long pos = st.st_size - 2;
				int c;

				while (pos > 0) {
					fseek(f, pos, SEEK_SET);
					c = fgetc(f);
					if (c == '\n') {
						break;
					}
					pos--;
				}
				if (pos > 0) {
					offset = pos + 1;
				} else {
					offset = 0;
				}
				fclose(f);
			}
		}
		if (st.st_size == offset) {
			continue;
		}

		f = fopen(path, "r");
		if (f == NULL) {
			continue;
		}
		fseek(f, offset, SEEK_SET);
		while (fgets(buf, sizeof(buf), f) != NULL) {
			fputs(buf, stdout);
		}
		offset = ftell(f);
		fclose(f);
		fflush(stdout);
	}
	return 0;
}
