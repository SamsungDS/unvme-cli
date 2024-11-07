// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

static void *__handle __attribute__((__unused__));

extern char **environ;

extern char *unvme_get_filepath(char *pwd, const char *filename);
extern void *fio_libunvmed(void);

int unvmed_run_fio(int argc, char *argv[], const char *libfio, const char *pwd)
{
	int (*main)(int, char *[], char *[]);
	void (*register_ioengine)(void *);
	void (*unregister_ioengine)(void *);
	char **__argv;
	int ret = 0;

	/*
	 * If the previous app handle has not been closed yet, close here
	 * rather than closing it from the pthread context.  It should be the
	 * same context where dlopen() actually happened.
	 */
	if (__handle)
		dlclose(__handle);

	/*
	* Load fio binary built as a shared obejct every time `unvme fio`
	* command is invoked.  By freshly reloading the fio code and data to
	* the memory makes fio run as a standalone application.
	*/
	__handle = dlopen(libfio, RTLD_LAZY);
	if (!__handle) {
		fprintf(stderr, "failed to load shared object '%s'.  "
				"Give proper path to 'unvme start --with-fio=<path/to/fio/so>'\n", libfio);
		return -1;
	}

	main = dlsym(__handle, "main");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'main' symbol in fio. "
				"Maybe forgot to give 'unvme start --with-fio=<path/to/fio/so>'\n");
		return errno;
	}

	register_ioengine = dlsym(__handle, "register_ioengine");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'register_ioengine' symbol in fio\n");
		return errno;
	}

	unregister_ioengine = dlsym(__handle, "unregister_ioengine");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'unregister_ioengine' symbol in fio\n");
		return errno;
	}

	/*
	 * Put a default argument '--eta=always' to print output in stdio
	 * successfully.
	 */
	__argv = malloc(sizeof(char *) * (argc + 2));
	for (int i = 0; i < argc; i++) {
		/* job file path */
		if (argv[i][0] != '-')
			__argv[i] = unvme_get_filepath((char *)pwd, argv[i]);
		else
			__argv[i] = argv[i];
	}
	__argv[argc] = "--eta=always";
	__argv[argc + 1] = NULL;

	register_ioengine(fio_libunvmed());
	ret = main(argc + 1, __argv, environ);
	unregister_ioengine(fio_libunvmed());

	free(__argv);

	dlclose(__handle);
	__handle = NULL;

	return ret;
}
