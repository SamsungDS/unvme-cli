// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

extern char **environ;

extern void *fio_libunvmed(void);
int unvmed_run_fio(int argc, char *argv[], const char *libfio)
{
	int (*main)(int, char *[], char *[]);
	void (*register_ioengine)(void *);
	void (*unregister_ioengine)(void *);
	void *__fio_handle;
	char **__argv;
	int ret = 0;

	/*
	* Load fio binary built as a shared obejct every time `unvme fio`
	* command is invoked.  By freshly reloading the fio code and data to
	* the memory makes fio run as a standalone application.
	*/
	__fio_handle = dlopen(libfio, RTLD_LAZY);
	if (!__fio_handle)
		return -1;

	main = dlsym(__fio_handle, "main");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'main' symbol in fio");
		return errno;
	}

	register_ioengine = dlsym(__fio_handle, "register_ioengine");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'register_ioengine' symbol in fio");
		return errno;
	}

	unregister_ioengine = dlsym(__fio_handle, "unregister_ioengine");
	if (dlerror()) {
		fprintf(stderr, "failed to load 'unregister_ioengine' symbol in fio");
		return errno;
	}

	/*
	 * Put a default argument '--eta=always' to print output in stdio
	 * successfully.
	 */
	__argv = malloc(sizeof(char *) * (argc + 2));
	for (int i = 0; i < argc; i++)
		__argv[i] = argv[i];
	__argv[argc] = "--eta=always";
	__argv[argc + 1] = NULL;

	register_ioengine(fio_libunvmed());
	ret = main(argc + 1, __argv, environ);
	unregister_ioengine(fio_libunvmed());

	free(__argv);

	dlclose(__fio_handle);
	return ret;
}
