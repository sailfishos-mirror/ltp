// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 Viresh Kumar <viresh.kumar@linaro.org>
 */

/*\
 * Basic init_module() tests.
 *
 * [Algorithm]
 *
 * Inserts a simple module after opening and mmaping the module file.
 */

#include <stdlib.h>
#include <errno.h>
#include "lapi/init_module.h"
#include "tst_module.h"

#define MODULE_NAME	"init_module.ko"

static struct stat sb;
static void *buf;
static int sig_enforce;

static void setup(void)
{
	int fd;

	if (tst_module_signature_enforced())
		sig_enforce = 1;

	tst_module_exists(MODULE_NAME, NULL);

	fd = SAFE_OPEN(MODULE_NAME, O_RDONLY|O_CLOEXEC);
	SAFE_FSTAT(fd, &sb);
	buf = SAFE_MMAP(0, sb.st_size, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
	SAFE_CLOSE(fd);
}

static void run(void)
{
	if (sig_enforce == 1) {
		TST_EXP_FAIL(init_module(buf, sb.st_size, "status=valid"), EKEYREJECTED);
		return;
	}

	TST_EXP_PASS(init_module(buf, sb.st_size, "status=valid"));
	if (!TST_PASS)
		return;

	tst_module_unload(MODULE_NAME);
}

static void cleanup(void)
{
	munmap(buf, sb.st_size);
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	/* lockdown and SecureBoot requires signed modules */
	.skip_in_lockdown = 1,
	.skip_in_secureboot = 1,
};
