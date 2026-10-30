/*
 * apmond logging, as apmond 1.x / mesh11sd:
 * - messages above debuglevel are dropped; an identical consecutive message is counted instead
 *   of written, and "previous message repeated N times" is logged before the next one or at the
 *   latest after 5 minutes (as syslog), so a quiet daemon still shows it is alive
 * - err and notice go to syslog AND the log file; info and debug go to the log file only
 * - log file <log_mountpoint>/apmond/apmond_log.log (/tmp/apmond/apmond_log.log by default),
 *   lines "<date> daemon.<level> apmond: [<n>] <message>", trimmed to max_log_entries
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
static struct apmon_dedupe dedupe;

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

void apmond_log_init(void)
{
	char reason[256];

	if (apmond_log_path(&apmond.cfg, log_file, sizeof(log_file), reason, sizeof(reason), 1) == 0) {
		log_file_ok = 1;
		log_lines = apmon_count_lines(log_file);
		if (reason[0] != '\0') {
			LOG_NOTICE_("%s", reason);
		}
		LOG_INFO_("option log_mountpoint [ %s ], log file [ %s ]", apmond.cfg.log_mountpoint, log_file);
	} else {
		log_file_ok = 0;
		syslog(LOG_ERR, "%s", reason);
	}
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
	fprintf(f, "%s daemon.%s apmond: %s\n", date, level, msg);
	fclose(f);
	log_lines++;

	if (log_lines > apmond.cfg.max_log_entries) {
		int left = apmon_trim_log(log_file, apmond.cfg.max_log_entries);

		if (left >= 0) {
			log_lines = left;
		} else {
			/* recount instead of trimming again on every line */
			log_lines = apmon_count_lines(log_file);
		}
	}
}

static void emit(int level, const char *msg)
{
	static const int prio[] = { LOG_ERR, LOG_NOTICE, LOG_INFO, LOG_DEBUG };
	static const char *names[] = { "err", "notice", "info", "debug" };
	char line[540];

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

void apmond_log(int level, const char *fmt, ...)
{
	char msg[512];
	char summary[64];
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

	if (!apmon_dedupe_check(&dedupe, msg, (int64_t)time(NULL), summary, sizeof(summary))) {
		return;
	}
	if (summary[0] != '\0') {
		emit(level, summary);
	}
	emit(level, msg);
}

/* apmond read_log [-f]: print the log, then (follow) print new lines as they are written */
int apmond_read_log(int follow)
{
	char path[192];
	char reason[256];
	char last[600] = "";
	struct stat st;
	ino_t inode = 0;
	off_t size = -1;
	time_t mtime = 0;

	if (apmond_log_path(&apmond.cfg, path, sizeof(path), reason, sizeof(reason), 0) != 0) {
		fprintf(stderr, "%s\n", reason);
		return 1;
	}

	if (apmon_log_follow(path, last, sizeof(last), stdout) < 0) {
		fprintf(stderr, "no log file %s\n", path);
		return 1;
	}

	while (follow) {
		sleep(1);

		if (stat(path, &st) != 0) {
			continue;
		}
		if (st.st_ino == inode && st.st_size == size && st.st_mtime == mtime) {
			/* a trim can keep the size; mtime has 1 s resolution, so look again while recent */
			if (st.st_mtime < time(NULL) - 1) {
				continue;
			}
		}
		inode = st.st_ino;
		size = st.st_size;
		mtime = st.st_mtime;

		/* trimmed in place or appended: carry on after the last line printed */
		apmon_log_follow(path, last, sizeof(last), stdout);
	}
	return 0;
}
