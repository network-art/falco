Falco is a collection of modules that help engineers quickly develop embedded and network-based applications in C. Falco helps build high-performance applications. Applications that run on embedded devices, IoT gateways, desktops and servers.

[![Build Status](https://travis-ci.org/network-art/falco.svg?branch=master)](https://travis-ci.org/network-art/falco)

#### Contents
------

1. [About Falco Library](README.md#about-falco-library)
2. [Modules in Falco](README.md#modules-in-falco)
3. [Coding style and conventions](README.md#style-and-code-conventions)
4. [Building](README.md#building)
5. [Usage](README.md#usage)
6. [Roadmap](README.md#roadmap)

# About Falco Library

Falco is the reincarnation of the erstwhile SVUtils ([**S**upport**V**antage](https://networkart.com) Utils) library that we built for our [product SupportVantage](https://networkart.com/products/supportvantage). The bird family "Falco Peregrinus" is the inspiration for the name "Falco". [Peregrine Falcon](https://en.wikipedia.org/wiki/Peregrine_falcon), the fastest bird, belongs to this family.

SVAgent (**S**upport**V**antage **Agent**), a component of our product, has many modules. Each module runs as a process/daemon. All modules have the same infrastructural requirements. Some of them are listed below.

- Provide simple API for logging via Syslog (with controls for setting log level/priority).
- Signal handling management. E.g. apps must be able to register a signal handler to terminate itself when it receives SIGTERM.
- Timer management. The ability to create and manage timers with timeout intervals and timeout handlers.
- Socket management. The ability to create and manage sockets (INET, INET6) with support for different types (raw, datagram and stream). Support for blocking and non-blocking send and receive.
- Manage read, write and except bits for select() and epoll().
- Task management, along with task scheduling based on priority.

Falco addresses these and many other infrastructural requirements. It reduces boilerplate code in applications.

Falco is inspired by and is similar in style to the excellent task management infrastructure of GateD. GateD was an open-source routing daemon project developed by the Merit Consortium, Inc at the University of Michigan at Ann Arbor, in the 90s and early 2000. However, Falco differs from GateD's task infrastructure in many ways. Task is the primary infrastructure object in GateD. Other objects (such as sockets, timers) are associated with the task object. In Falco, the task object is not mandatory for managing objects such as sockets, timers. This notable difference changes the nature of the application programming interfaces (APIs).

# Modules in Falco

## [Process](https://github.com/network-art/falco/blob/master/src/fl_process.c)

A small component that provides the following functionalities:

- Convenience function to initialize all Falco modules.
- Record (when process runs as a daemon) and close/delete PID files (upon termination).
- Convenience function to dump state and statistics of all Falco modules.

## [Task](https://github.com/network-art/falco/blob/master/src/fl_task.c)

A simple task management module.

- An app can create and manage tasks. Tasks have priorities. Three levels of priorities are currently supported.
- Apps can schedule tasks in their main loop.

## [Socket](https://github.com/network-art/falco/blob/master/src/fl_socket.c)

A comprehensive sockets management framework. Apps can quickly realize features for network-based applications.

The socket module APIs provide argument parity with the standard BSD/Linux socket APIs. For example,

```c
int socket(int domain, int type, int protocol)
```

The Falco API is:

```c
fl_socket_t *fl_socket_socket(struct fl_task_t_ *task, const char *name, int domain, int type, int protocol)
```

The task argument is optional, while the name argument is mandatory.

Some features are listed below.

- Ability to bind, listen and accept connections.
- Support for one transmit buffer and one receive buffer. We intend to add support for more than one transmit buffers.
- Support for blocking and non-blocking transmit and receive across socket types (raw, datagram and stream).
- Apps can register call back functions for non-blocking transmit and receive.
- Falco provides ready-made non-blocking transmission and receive functions. Apps can focus on the actual functionality and reduce boilerplate code.

## [Timer](https://github.com/network-art/falco/blob/master/src/fl_timer.c)

The timer module uses the timerfd infrastructure in Linux. Apps can handle timer fires in `select()` or `epoll()`.

Functionality includes: creating, starting (arming), stopping (disarming) and deleting timers. Apps can register timeout handlers with contextual data.

## [Signal](https://github.com/network-art/falco/blob/master/src/fl_signal.c)

The signal module is a small module that allows apps to register signal handlers to signals. For example, `app_terminate()` method for signal `SIGTERM`.

Apps can control the timer dispatches (i.e. timeout handlers) from their main loop.

## [File Descriptors (FD)](https://github.com/network-art/falco/blob/master/src/fl_fds.c)

The Falco socket and timer modules use the FD module internally. Apps can also use the FD module to get the current read, write and except bits.

## [Logging](https://github.com/network-art/falco/blob/master/src/fl_logr.c) and [Tracing](https://github.com/network-art/falco/blob/master/src/fl_tracevalue.c)

The logr module provides a simple API set for logging via [Syslog](https://en.wikipedia.org/wiki/Syslog). The tracevalue module provides mechanisms to trace/print integer and bit values.

# Style and Code Conventions

File names reflect the name of the module. For example, fl_fds.c provides the File Descriptors management functionality. File names, constants, function names, global variables and other entities contain the Falco library (`fl_`) prefix.

Falco does not provide definitions for basic data types (such as character, 16-bit, 32-bit, 64-bit integers). Instead, `sys/types.h` is used to get the definitions. Header file `sys/param.h` provides constants for maximum path length, line length and other such constants.

Falco employs `assert()` (via `FL_ASSERT`) extensively to help engineers catch bugs and mistakes at the earliest. Apps can also use `FL_ASSERT()`.

# Building

Falco supports native and cross-platform builds. GNU Autotools, and cmake based build methods are supported.

## Build using cmake

For example,

```bash
% mkdir build/${TOOLCHAIN}
% cd build/${TOOLCHAIN}
% cmake -DCMAKE_INSTALL_PREFIX=/usr ../..
% make
% make install
# You can also specify a destination directory for installation. For example, make DESTDIR=<destination-directory> install.
```



## Build using GNU Autotools method

For example,

```bash
% ./autogen.sh
% mkdir -p build/${TOOLCHAIN}
% cd build/${TOOLCHAIN}
% ../../configure
% make
% make install
# You can also specify a destination directory for installation. For example, make DESTDIR=<destination-directory> install.
```

A static library archive (`${DESTDIR}/usr/lib/libfalco.a`) is available for the applications to link with. Header files are installed in `${DESTDIR}/usr/include`.

# Usage

The following code snippet shows how apps can initialize with Falco library.

```c
do {
	fl_logr_openlog("YOUR_APP_NAME");

	if (getuid()) {
        FL_LOGR_CRIT("%s must be run as root or with sudo privileges, exiting.\n",
                     progname);
		break;
	}

	if (getppid() == 1) {
		daemonize = FALSE;
		FL_LOGR_INFO("%s was started either via /etc/inittab or "
                     "systemctl, will not daemonize", progname);
	}

	if (daemonize) {
		fl_process_daemonize();
	}

	pid_fd = fl_process_open_pid_file(progname);
	if (pid_fd < 0) {
		FL_LOGR_CRIT("Could not open PID file or store PID, exiting.\n");
		break;
	}

	if (fl_signal_register_handlers(sighandlers) < 0) {
		FL_LOGR_CRIT("Signal handlers registrations failed, exiting.");
		break;
	}

	if (fl_init() < 0) {
		FL_LOGR_CRIT("Falco library initialization failed, exiting.");
		break;
	}

    app_main_loop();
} while(0);

app_shutdown(1);
```



 The following code shows how apps can use Falco in their main loop.

```c
static void app_main_loop()
{
	int nfds_fired;
	fd_set *rfds, *wfds, *efds;

	while (TRUE) {
		/* Sample set of signals to be blocked */
		int block_signals[] = { SIGUSR1, SIGUSR2, 0 };
		int signals_blocked = 0;
        sigset_t signals_blockset;

		/* select() comes here */
		nfds_fired = fl_socket_select(&rfds, &wfds, &efds);
		if (nfds_fired < 0) {
            FL_LOGR_EMERG("Sockets select() fired with error, exiting.");
            app_shutdown();
        }

		/* Block signals here */
        signals_blocked = fl_signals_block(block_signals, &signals_blockset);

		/* Process timer expirations */
		fl_timers_dispatch(&nfds_fired, rfds);

		/* Process sockets ready for read */
		if (nfds_fired) {
            fl_socket_process_reads(&nfds_fired, rfds);
        }

        /* Process sockets ready for write */
        if (nfds_fired) {
            fl_socket_process_writes(&nfds_fired, wfds);
        }

        /* Process sockets ready for accept */
        if (nfds_fired) {
            fl_socket_process_connections(&nfds_fired, rfds);
        }

		/* Unblock signals that were previously blocked */
        if (signals_blocked) {
            (void) fl_signals_unblock(&signals_blockset);
        }
    }
}
```

Code snippets that exemplify cleanup and shutdown procedures.
```c
static void app_shutdown(int exit_code)
{
	app_cleanup();
	exit(exit_code);
}

static void app_cleanup()
{
    /* Stop and close logging */
    if (logging_started) {
		fl_logr_closelog(progname);
    }

    /* Close and remove the PID file */
	if (pid_fd >= 0) {
		fl_process_close_pid_file(progname, pid_fd);
		pid_fd = -1;
	}
}
```



# Roadmap

- (Re)Introduce the unit testing code.
- (Re)Introduce comments for all APIs from the erstwhile SVUtils library. API documentation to be made available via manual (BSD/Linux man) pages.
- Support for more than one transmit buffer.
- Support for Bazel builds.
- Testing on BSD based systems.

Please submit feature requests on GitHub as issues. We prioritize (and reprioritize) feature requests on the last Friday of every month.
