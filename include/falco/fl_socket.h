/*******************************************************************************
BSD 3-Clause License

Copyright (c) 2014 - 2020, NetworkArt Systems Private Limited (www.networkart.com).
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

/**
 * @file
 * @brief Sockets and communications.
 *
 * At the heart of the falco socket module is the notion or concept of a "Falco
 * Socket" (#fl_socket_t). The falco socket is a structure that contains the
 * socket file descriptor (sockfd). It also contains many other
 * properties/attributes that help applications (and the falco library itself)
 * perform various operations on the sockfd. The commentary on the source code
 * often refer to this concept of falco socket. This is not to be confused with
 * the socket file descriptor (sockfd) containined within the falco socket.
 *
 * Throughout the code, falco sockets are represented by <em><b>flsk</b></em>.
 * Throughout the code and commentary, the socket file descriptor (contained
 * within a falco socket) is represented by <em><b>sockfd</b></em>. Functions,
 * structure definitions, and enumerations are prefixed with
 * <em>fl_socket_</em>.
 *
 * This module provides APIs for the following functionalities.
 * - Create, close/delete sockets.
 * - Accept connections (server) and connect method (client).
 * - Send and Receive data (TCP, UDP, and RAW IP).
 * Blocking and Non-Blocking operations are supported.
 *
 * The following socket domains (address families) are supported.
 * - AF_INET (IPv4 Internet Protocols)
 * - AF_INET6 (IPv6 Internet Protocols)
 * - AF_UNIX (Local Communication)
 *
 * The following socket types, which spcecify the communication semantics, are
 * supported.
 * - SOCK_DGRAM
 * - SOCK_RAW
 * - SOCK_STREAM
 *
 * All APIs that accept parameter of type sockaddr or sockaddr_storage check
 * the above socket domains (or address families) and socket types.
 *
 * <em><b>sockaddr_storage</b></em> is used instead of @c sockaddr in APIs such
 * fl_socket_bind(). This is so that applications can allocate for the maximum
 * size of a socket address instead of running into size/cast issues.
 *
 */

#ifndef _FL_SOCKET_H_
#define _FL_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_bits.h"
#include "falco/fl_tracevalue.h"

/**
 * @brief Maximum length of a socket name (including the trailing delimiter).
 */
#define FL_SOCKET_NAME_MAX_LEN   128

/* Flags for socket state and options */
/**
 * @brief Flag to indicate the state that the socket is bound to an
 * IPv4 address.
 */
#define FL_SOCKF_BOUND_IN           BITVAL(0x00000001)
/**
 * @brief Flag to indicate the state that the socket is bound to an
 * IPv6 address.
 */
#define FL_SOCKF_BOUND_IN6          BITVAL(0x00000002)
/**
 * @brief Flag to indicate the state that the socket is bound to a Unix path.
 */
#define FL_SOCKF_BOUND_UNIX         BITVAL(0x00000004)
/**
 * @brief Flag to indicate the state that the socket is connected.
 */
#define FL_SOCKF_CONNECTED          BITVAL(0x00000008)
/**
 * @brief Flag to indicate the state that the socket is listening for connections.
 */
#define FL_SOCKF_LISTEN             BITVAL(0x00000010)
/**
 * @brief Flag to indicate that non-blocking option has been set for the
 * socket operations.
 */
#define FL_SOCKF_NONBLOCKING        BITVAL(0x00000020)
/**
 * @brief Flag to indicate that recevie wait option has been set on the socket.
 */
#define FL_SOCKF_RCVWAIT            BITVAL(0x00000040)

struct fl_socket_t_;

/**
 * @brief Type definition for methods that implement connection accept method.
 */
typedef void (*fl_socket_accept_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods that implement connect method.
 */
typedef void (*fl_socket_connect_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods to handle errors returned from connect.
 */
typedef void (*fl_socket_connect_error_method_t)(struct fl_socket_t_ *, int);
/**
 * @brief Type definition for methods to handle the completion of a connection.
 */
typedef void (*fl_socket_connect_complete_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods that handle reception of packets or
 * datagrams.
 */
typedef void (*fl_socket_recv_method_t)(struct fl_socket_t_ *, void *buf, size_t len, struct sockaddr *src_addr, socklen_t *addrlen);
/**
 * @brief Type definition for methods that implement non-blocking receive
 * operation.
 */
typedef void (*fl_socket_nb_recv_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods that check if a message has been received
 * completely.
 */
typedef int (*fl_socket_recv_is_msg_complete_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods that handle reception of packets or
 * datagrams.
 */
typedef void (*fl_socket_recv_complete_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods to handle errors encountered during
 * receive operation.
 */
typedef void (*fl_socket_recv_error_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods that implement tranmission of packets or
 * datagrams.
 */
typedef ssize_t (*fl_socket_send_method_t)(struct fl_socket_t_ *, void *buf, size_t len, const struct sockaddr *dest_addr, socklen_t addrlen);
/**
 * @brief Type definition for methods that implement non-blocking tranmission
 * of packets or datagrams.
 */
typedef void (*fl_socket_nb_send_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods to handle the completion of a transmit
 * operation.
 */
typedef void (*fl_socket_send_complete_method_t)(struct fl_socket_t_ *);
/**
 * @brief Type definition for methods to handle errors encountered during
 * transmit/send operation.
 */
typedef void (*fl_socket_send_error_method_t)(struct fl_socket_t_ *);

/**
 * @brief Falco Socket.
 */
typedef struct fl_socket_t_ {
  /**
   * @brief List connector for all sockets.
   */
  LIST_ENTRY(fl_socket_t_) socket_lc;
  /**
   * @brief List connector for all sockets associated with a task.
   */
  LIST_ENTRY(fl_socket_t_) task_socket_lc;

  char name[FL_SOCKET_NAME_MAX_LEN]; ///< Socket name specified by the application during #fl_socket_socket().
  int domain; ///< Socket domain. One of AF_INET or AF_INET6 or AF_UNIX
  int type; ///< Socket type. One of SOCK_DGRAM or SOCK_RAW or SOCK_STREAM
  int protocol; ///< Protocol to use, refer to the man page for socket

  fl_socket_accept_method_t accept_method;
  fl_socket_connect_method_t connect_method;
  fl_socket_connect_complete_method_t connect_complete_method;
  fl_socket_recv_method_t recv_method;
  fl_socket_nb_recv_method_t nb_recv_method;
  fl_socket_recv_is_msg_complete_method_t recv_is_msg_complete_method;
  fl_socket_recv_complete_method_t recv_complete_method;
  fl_socket_recv_error_method_t recv_error_method;
  fl_socket_send_method_t send_method;
  fl_socket_nb_send_method_t nb_send_method;
  fl_socket_send_complete_method_t send_complete_method;
  fl_socket_send_error_method_t send_error_method;

  int sockfd; ///< Socket file descriptor
  flag_t flags; ///< Socket state flags. See flags starting from #FL_SOCKF_BOUND_IN
  struct sockaddr_storage sa_local; ///< Local address of the socket
  /**
   * @brief Maximum length of the string (including the trailing delimiter)
   * that represents a socket address in a printable (presentation) format.
   */
  /* From sys/un.h sun_path length is 108. This value should be more than
   * sufficient across platforms.
   */
#define FL_SOCKADDR_STR_MAX_LEN 130
  char local_addr[FL_SOCKADDR_STR_MAX_LEN]; ///< Local address of the socket in presentation format

  struct sockaddr_storage sa_remote; ///< Remote address of the socket
  char remote_addr[FL_SOCKADDR_STR_MAX_LEN]; ///< Remote address of the socket in presentation format

  /* Data Buffers */
  void *rbuf;        ///< Read data buffer supplied by the application
  size_t trbuf_len;  ///< Total read data buffer length supplied by the application
  size_t crdata_len; ///< Current read data buffer updated by the recv method
  struct sockaddr_storage rbuf_src_addr; ///< Source address of the buffer (i.e. address of the sender)

  void *wbuf;        ///< Write data buffer supplied by the application
  size_t twbuf_len;  ///< Total write data buffer length supplied by the application
  size_t cwdata_len; ///< Current write data buffer updated by the write method
  struct sockaddr_storage wbuf_dest_addr; ///< Destination address (to where this buffer needs to be sent/transmitted)

  struct fl_task_t_ *task; ///< The falco task to which this socket is associated
} fl_socket_t;

/**
 * @brief Falco Socket Options.
 */
typedef enum fl_sockoption_e_ {
  FL_SOCKOPT_MIN = 1,
  /**
   * @brief Non-Blocking option for the socket.
   */
  FL_SOCKOPT_NONBLOCKING = FL_SOCKOPT_MIN,
  /**
   * @brief Recv-Wait option for the socket.
   */
  FL_SOCKOPT_RCVWAIT,
  /**
   * @brief Maps to SO_RCVTIMEO (Receive TimeOut) for the socket.
   */
  FL_SOCKOPT_RCVTIMEO,
  /**
   * @brief Maps to SO_SNDTIMEO (Send TimeOut) for the socket.
   */
  FL_SOCKOPT_SNDTIMEO,
  FL_SOCKOPT_MAX = FL_SOCKOPT_SNDTIMEO,
} fl_sockoption_e;

/**
 * @brief Initialize socket and communications module.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_socket_module_init(void);

/**
 * @brief Dump the status and state of the module.
 *
 * @param[in] fd Stream to which the status and state of all modules needs to
 *               be written. If this parameter is NULL, then the output is
 *               written to syslog.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_socket_module_dump(FILE *fd);

/**
 * @brief Duplicate a socket address (representation of @c sockaddr_storage).
 *
 * @param[in] dst Destination socket address
 * @param[in] src Source socket address
 * @param[in] srclen Length of @p src. Must be atleast @c sizeof(sockaddr_in),
 *                   and cannot exceed @c sizeof(sockaddr_storage)
 *
 * @return On success, @p dst is returned. On error, @c NULL is returned.
 */
extern struct sockaddr_storage *fl_sockaddr_dup(struct sockaddr_storage *dst,
                                                const struct sockaddr_storage *src,
                                                socklen_t srclen);
/**
 * @brief Compare two socket addresses.
 *
 * @return Returns -1, 0, or 1 if @c sa1 is found to be less than, to match,
 * or be greater than @c sa2.
 */
extern int fl_sockaddr_cmp(const struct sockaddr *sa1,
                           const struct sockaddr *sa2);

/**
 * @brief Compare the network portion of two socket addresses.
 *
 * @return Returns -1, 0, or 1 if @c sa1 is found to be less than, to match,
 * or be greater than @c sa2.
 */
extern int fl_sockaddr_nw_cmp(const struct sockaddr *sa1,
                              const struct sockaddr *sa2,
                              const struct sockaddr *netmask);

/**
 * @brief Get the length of a socket address (represented as @c sockaddr).
 *
 * @return Returns the length of the address if the socket address family/domain
 * is supported. Otherwise, 0 is returned.
 */
extern socklen_t fl_sockaddr_len(struct sockaddr *sa);

/**
 * @brief Convert a socket address from binary to text form.
 *
 * This function converts the network address structure @p ss (in the address
 * family @c ss->ss_family) into a character string.
 * For socket addresses belonging to family AF_INET or AF_INET6, the resulting
 * string is copied to the buffer pointed to by dst, which must be a non-null
 * pointer.
 *
 * For socket addresses belonging to the AF_UNIX family, the buffer pointed to
 * by dst is unchanged. The unix path of the socket is returned.
 *
 * @return Returns a non-null pointer to @p dst if the address family is
 * supported. Otherwise, NULL is returned.
 */
extern const char *fl_sockaddr_ntop(const struct sockaddr_storage *ss,
                                    char *dst, socklen_t size);

/**
 * @brief Convert the port in a socket address to host byte order.
 *
 * This function converts the port in a socket address from network byte order
 * to host byte order.
 *
 * @return For socket addresses belonging to AF_INET or AF_INET6 family,
 * an unsigned short integer in host byte order is returned.
 * For socket addresses belonging to AF_UNIX family, 0 is returned.
 */
extern u_int16_t fl_sockaddr_port_hbo(const struct sockaddr_storage *ss);

/**
 * @brief Create an endpoint for communication
 *
 * Create an endpoint for communication and return a falco socket.
 *
 * @param[in] task (Optional) Task to which this socket needs to be associated
 * @param[in] name String of length not exceeding #FL_SOCKET_NAME_MAX_LEN
 *
 * Parameters domain, type, and protocol have the same semantics and definition
 * as in @c socket(2).
 *
 * @return On success, a pointer to a structure that represents a falco socket
 * is returned. Otherwise, NULL is returned.
 *
 * The pointer to the falco socket structure needs to be freed by the
 * application when it is no longer required.
 *
 * @see socket(2)
 */
extern fl_socket_t *fl_socket_socket(struct fl_task_t_ *task, const char *name,
                                     int domain, int type, int protocol);

/**
 * @brief Set options on falco sockets
 *
 * Manipulate options for the sockfd (contained within a falco socket).
 * This function uses @c ioctl() to set Non-Blocking option, and
 * @c setsockopt() to set receive and send timeout options.
 *
 * @param[in] flsk Falco socket
 * @param[in] option Enumerated value from #fl_sockoption_e
 * @param[in] args For send and receive timeout options, caller must pass a
 *                 timeout value (in milliseconds) as the third argument.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c socket(2), @c setsockopt(2)
 */
extern int fl_socket_setsockopt(fl_socket_t *flsk, fl_sockoption_e option, ...);

/**
 * @brief Bind a name to a falco socket
 *
 * This function assigns the address specified by @p addr to the sockfd
 * (contained within the falco socket).
 *
 * @param[in] flsk Falco socket
 * @param[in] addr Local address to bind to
 * @param[in] addrlen The size, in bytes, of the address structure pointed to by
 *                    @p addr
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c bind(2)
 */
extern int fl_socket_bind(fl_socket_t *flsk,
                          const struct sockaddr_storage *addr,
                          socklen_t addrlen);

/**
 * @brief Listen for connections on a falco socket
 *
 * Marks the sockfd (contained within the falco socket) as a passive socket,
 * that is, as a socket that will be used to accept incoming connection requests
 * using @c accept(2).
 *
 * @param[in] flsk Falco socket
 * @param[in] backlog Defines the maximum length to which the queue or pending
 *                    socket fd may grow.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c listen(2)
 */
extern int fl_socket_listen(fl_socket_t *flsk, int backlog);

/**
 * @brief Synchronous I/O multiplexing
 *
 * Allows an application to monitor multiple file descriptors, waiting until one
 * or more of the file descriptors become ready for some class of I/O operation.
 * For example, read or write operation.
 *
 * The falco File Descriptors (FDs) management module keeps track or maintains
 * (socket) file descriptors that were created by calling fl_socket_socket().
 * In addition, the application can also directly access #FL_FD_SET macro to
 * tell the FDs management module to track an FD for a certain operation.
 * @p rfds, @p wfds and @p efds are independent sets of FDs and are watched.
 *
 * @param[in,out] rfds Set of file descriptors to be watched for write
 * @param[in,out] wfds Set of file descriptors to be watched for read
 * @param[in,out] efds Set of file descriptors to be watched for exceptions
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c select(2), #FL_FD_SET, #FL_FD_CLR, #FL_FD_ZERO, fl_fd_isset()
 */
extern int fl_socket_select(fd_set **rfds, fd_set **wfds, fd_set **efds);

/**
 * @brief Accept a connection on a socket
 *
 * This function is used with connection-based socket types (SOCK_STREAM). It
 * uses the @c accept(2) system call to process pending connections.
 *
 * On successful connection to a client, a new falco socket is created. Its
 * fd is set to the fd returned from @c accept(2). The local address is set.
 * For AF_INET and AF_INET6 families, the remote address is set from the remote
 * address returned from @c accept(2). The application is then notified of the
 * new connection by invoking the @c connect_complete_method() which implements
 * #fl_socket_connect_complete_method_t.
 *
 * @param[in] flsk Falco socket
 *
 * @see @c accept(2)
 */
extern void fl_socket_generic_accept(fl_socket_t *flsk);

/**
 * @brief Initiate a connection on a socket
 *
 * A generic implementation of @c connect(2) that applications can use readily.
 * This function uses the @c connect(2) system call to connect the socket
 * referred to by sockfd (contained within the falco socket) to the address by
 * @p addr.
 *
 * On successful connection, a new falco socket is created. The local address
 * and remote address is set.
 *
 * @param[in] flsk Falco socket
 * @param[in] addr Remote address
 * @param[in] addrlen Specifies the size of @p addr
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c connect(2)
 */
extern int fl_socket_generic_connect(fl_socket_t *flsk,
                                     const struct sockaddr_storage *addr,
                                     socklen_t addrlen);

/**
 * @brief Receive a message from a socket
 *
 * A generic implementation of @c recv(2) that applications can use readily.
 * This function employs @c recvfrom(2) for SOCK_DGRAM, @c recvmsg(2) for
 * SOCK_RAW and @c recv(2) for SOCK_STREAM.
 *
 * If src_addr is not NULL, and the underlying protocol provides the source
 * address of the message, that source address is placed in the buffer pointed
 * to by src_addr. @p addrlen is updated to contain the actual size of the
 * source address.
 *
 * @param[in] flsk Falco socket
 * @param[in,out] buf Buffer to store the received data
 * @param[in] len Length of the buffer @p buf
 * @param[in,out] src_addr Source address of the message
 * @param[in,out] addrlen Specifies the size of @p src_addr
 *
 * @return On success, the number of bytes received is returned. On error, -1 is
 * returned.
 *
 * @see @c recv(2), recvfrom(2), recvmsg(2)
 */
extern ssize_t fl_socket_generic_recv(fl_socket_t *flsk, void *buf, size_t len,
                                      struct sockaddr_storage *src_addr,
                                      socklen_t *addrlen);

/**
 * @brief Send a message on a socket
 *
 * A generic implementation of @c send(2) that applications can use readily.
 * This function employs @c sendto(2) for SOCK_DGRAM, @c sendmsg(2) for
 * SOCK_RAW and @c send(2) for SOCK_STREAM.
 *
 * @param[in] flsk Falco socket
 * @param[in] buf Send data buffer
 * @param[in] len Length of the buffer @p buf
 * @param[in] dest_addr Destination address of the message
 * @param[in] addrlen Specifies the size of @p dest_addr
 *
 * @return On success, the number of bytes sent is returned. On error, -1 is
 * returned.
 *
 * @see @c send(2), sendto(2), sendmsg(2)
 */
extern ssize_t fl_socket_generic_send(fl_socket_t *flsk, void *buf, size_t len,
                                      const struct sockaddr_storage *dest_addr,
                                      socklen_t addrlen);

/**
 * @brief Set socket connection complete handler method
 *
 * @param[in] flsk Falco socket
 * @param[in] connect_complete_method Method that is invoked by falco when a
 *            socket connection is complete
 *
 * @see fl_socket_accept()
 */
extern void fl_socket_set_connect_complete_method(fl_socket_t *flsk, fl_socket_connect_complete_method_t connect_complete_method);

/**
 * @brief Set receive handler method
 *
 * @param[in] flsk Falco socket
 * @param[in] recv_method Method that is invoked by falco when a message is
 *                        received on a socket
 *
 * @see fl_socket_accept()
 */
extern void fl_socket_set_recv_method(fl_socket_t *flsk,
                                      fl_socket_recv_method_t recv_method);

/**
 * @brief Set non-blocking receive handler method
 *
 * @param[in] flsk Falco socket
 * @param[in] nb_recv_method Method that is invoked by falco when a message is
 *                           received (in a non-blocking fashion) on a socket
 *
 * @see fl_socket_socket(), fl_socket_accept()
 */
extern void fl_socket_set_nb_recv_method(fl_socket_t *flsk,
                                         fl_socket_nb_recv_method_t nb_recv_method);

/**
 * @brief Set method that checks if a received message is complete
 *
 * When sockets are set to operate in a non-blocking mode, falco calls the
 * method to check with if a message received on a socket is complete.
 *
 * @param[in] flsk Falco socket
 * @param[in] recv_is_msg_complete_method Pointer to a function
 *
 * @see fl_socket_socket(), fl_socket_recv()
 */
extern void fl_socket_set_recv_is_msg_complete_method(fl_socket_t *flsk, fl_socket_recv_is_msg_complete_method_t recv_is_msg_complete_method);

/**
 * @brief Set method to notify the application that a complete message has been
 * received
 *
 * When sockets are set to operate in a non-blocking mode, falco calls the
 * method to notify the application of a message that has been received.
 *
 * @param[in] flsk Falco socket
 * @param[in] recv_complete_method Pointer to a function
 *
 * @see fl_socket_socket(), fl_socket_recv()
 */
extern void fl_socket_set_recv_complete_method(fl_socket_t *flsk, fl_socket_recv_complete_method_t recv_complete_method);

/**
 * @brief Set method to notify the application that a message has been sent
 *
 * When sockets are set to operate in a non-blocking mode, falco calls the
 * method to notify the application of a message that has been sent/transmitted.
 *
 * @param[in] flsk Falco socket
 * @param[in] send_complete_method Pointer to a function
 *
 * @see fl_socket_socket(), fl_socket_send()
 */
extern void fl_socket_set_send_complete_method(fl_socket_t *flsk, fl_socket_send_complete_method_t send_complete_method);

/**
 * @brief Perform read operation on sockets
 *
 * This function performs read operations on socket file descriptors which have
 * become ready for read. It calls the non-blocking receive method that has
 * been previously registered for the socket.
 *
 * @param[in,out] Number of FDs that are ready for I/O operations.
 *                It is decremented by the number of FDs on which read operation
 *                has been performed.
 * @param[in,out] fds Read FD set. FDs on which the read operation has been
 *                                 performed are cleared.
 *
 * @see fl_socket_select()
 */
extern void fl_socket_process_reads(int *nfds, fd_set *fds);

/**
 * @brief Perform write operation on sockets
 *
 * This function performs write operations on socket file descriptors which have
 * become ready for write. It calls the non-blocking send method that has
 * been previously registered for the socket.
 *
 * @param[in,out] Number of FDs that are ready for I/O operations.
 *                It is decremented by the number of FDs on which write
 *                operation has been performed.
 * @param[in,out] fds Read FD set. FDs on which the write operation has been
 *                    performed are cleared.
 *
 * @see fl_socket_select()
 */
extern void fl_socket_process_writes(int *nfds, fd_set *fds);

/**
 * @brief Process new connections on sockets that are in listen mode
 *
 * This function performs read operations on socket file descriptors which have
 * become ready to accept new connections. It calls the accept method that has
 * been previously registered for the socket.
 *
 * @param[in,out] Number of FDs that are ready for I/O operations.
 *                It is decremented by the number of FDs on which new
 *                connections have been processed.
 * @param[in,out] fds Read FD set. FDs on which the new connections have been
 *                processed are cleared.
 *
 * @see fl_socket_select(), fl_socket_listen()
 */
extern void fl_socket_process_connections(int *nfds, fd_set *fds);

#endif /* _FL_SOCKET_H_ */
