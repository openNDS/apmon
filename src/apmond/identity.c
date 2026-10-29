/*
 * apmond 2.x - which code is running, and is it the code installed?
 * As 1.x (apmond_checksum / installed_checksum): the sha256 of the running binary,
 * computed once at startup, and of the binary on disk, re-hashed only when its
 * mtime or size changes. They differ after an upgrade without a restart.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "apmond.h"

static time_t installed_mtime;
static off_t installed_size = -1;

void apmond_identity_init(void)
{
	if (apmon_sha256_file("/proc/self/exe", apmond.running_sha256) != 0) {
		apmond.running_sha256[0] = '\0';
		LOG_INFO_("cannot hash the running binary /proc/self/exe");
	}
	apmond_identity_refresh();
}

/* Cheap: one stat per report cycle, a hash only when the file changed */
void apmond_identity_refresh(void)
{
	struct stat st;

	if (stat(APMOND_INSTALL_PATH, &st) != 0) {
		apmond.installed_sha256[0] = '\0';
		installed_size = -1;
		return;
	}
	if (st.st_mtime == installed_mtime && st.st_size == installed_size && apmond.installed_sha256[0] != '\0') {
		return;
	}

	installed_mtime = st.st_mtime;
	installed_size = st.st_size;
	if (apmon_sha256_file(APMOND_INSTALL_PATH, apmond.installed_sha256) != 0) {
		apmond.installed_sha256[0] = '\0';
		return;
	}
	if (apmond_restart_needed() == 1) {
		LOG_NOTICE_("%s has changed since apmond started: restart apmond to run it", APMOND_INSTALL_PATH);
	}
}

int apmond_restart_needed(void)
{
	return apmon_restart_needed(apmond.running_sha256, apmond.installed_sha256);
}
