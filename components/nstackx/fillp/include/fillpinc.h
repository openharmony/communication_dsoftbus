/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FILLP_INC_H
#define FILLP_INC_H
#include "fillptypes.h"
#include "fillpcallbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 8)

/**
 * @ingroup FillPTraceInterfaces
 * @brief  This callback function is used to call the application trace function.
 *
 * @param[in] traceObjType   Indicates a trace object of type FillpTraceTypeEnum.
 * @param[in] traceHandle     Indicates the handle passed by application.
 * @param[in] msgLength      Indicates the length of the message.
 * @param[in] traceObj      Indicates the socket identifier for which the trace is currently provided.
 * @param[in] traceDescript Indicates the structure FillpTraceDescriptSt.
 * @param[in] traceMsg      Indicates the actual trace message. For commands from user, only the arguments are part
 * of the indication. For network messages, the FillP header along with the IP header (port and IP) are given as part
 * of indication.
 * @return void.
 * @par Related Topics
 * stTraceInfo
 * FtRegTraceCallbackFn
 */
typedef void (*FillpTraceSend)(IN FILLP_UINT32 traceObjType, IN void *traceHandle,
    IN FILLP_UINT32 msgLength, IN FILLP_UINT32 traceObj, IN FILLP_UINT8 *traceDescript,
    IN FILLP_CHAR *traceMsg, ...);

/**
 * This structure provides the trace information.
 */
struct TraceInfo {
    FillpTraceSend fillpTraceSend; /* Specifies a pointer to the FillpTraceSend function. */
    FILLP_BOOL  cmdTraceFlag;
    FILLP_UINT8 padd[3];
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd1[4];
#endif
};

extern struct TraceInfo g_traceInfo;


/**
 * @ingroup FillPSocketInterfaces
 * @brief Sends a message on a socket. This function is the same as the send function of the TCP socket.
 * If the socket is set as NON-Block, and if the non-block error happens, the the API returns -1 and the
 * error number is set as ERR_EAGAIN. You can retrieve the last error number of the socket by calling the
 * FtGetErrno() API.
 *
 * @param[in] fd        Indicates the socket created by FtSocket.
 * @param[in] data      Indicates a data pointer.
 * @param[in] size      Indicates the size of the message.
 * @param[in] flag      Indicates the status.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 */
extern FILLP_INT DLL_API FtSend(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag);

/**
 * @ingroup FillPSocketInterfaces
 * @brief Sends a video frame on a socket. This function is same with FtSend except the argument 'frame'
 * If the socket is set as NON-Block, and if the non-block error happens, the the API returns -1 and the
 * error number is set as ERR_EAGAIN. You can retrieve the last error number of the socket by calling the
 * FtGetErrno() API.
 *
 * @param[in] fd        Indicates the socket created by FtSocket.
 * @param[in] data      Indicates a data pointer.
 * @param[in] size      Indicates the size of the message.
 * @param[in] flag      Indicates the status.
 * @param[in] frame     Indicates frame information (including the frame type I or P, etc.) of the video frame.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 */
extern FILLP_INT DLL_API FtSendFrame(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag,
    FILLP_CONST struct FrameInfo *frame);

/**
 * @ingroup FillPSocketInterfaces
 * @brief This interface is used to bind to a socket created by the FtSocket() API. The usage is the same as
 * the bind function of the TCP socket.
 *
 * @param[in] fd        Specifies a descriptor identifying an unbound socket created by the FtSocket.
 * @param[in] name      Specifies a pointer to a SockAddr structure of the local address to assign to the bound socket.
 * @param[in] nameLen   Specifies the length, in bytes, of the value pointed to by the name parameter.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note
 * If the FtBind API returns failure, the user must call the FtClose API for same socket index and recreate the socket
 * using the FtSocket() API.
 * @par Limitations
 * The FtBind API does not support  bind to INADDR_ANY address.
 */
extern FILLP_INT DLL_API FtBind(FILLP_INT fd, FILLP_CONST struct sockaddr *name, FILLP_UINT32 nameLen);


/**
 * @ingroup FillPSocketInterfaces
 * @brief Creates an endpoint for communication and returns a descriptor. The usage is the same as
 * the socket function of the TCP socket.
 *
 * @param[in] domain     Indicates the domain to communicate.
 * @param[in] type       Indicates the type of connection.
 * @param[in] protocol   Indicates the type of protocol used.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 */
extern FILLP_INT DLL_API FtSocket(IN FILLP_INT domain, IN FILLP_INT type, IN FILLP_INT protocol);


/**
 * @ingroup FillPSocketInterfaces
 * @brief Initiates a connection on a socket. This is same as the TCP connect function.
 * If the socket is a non-block and there is a non-block error on the socket during FtConnect function,
 * the API returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno API.
 *
 * @param[in] fd        Indicates a socket created by the FtSocket API.  This is of protocol family and this must be
 * passed as PF_INET/AF_INET/AF_INET6 /PF_INET6.
 * @param[in] name      Indicates the socket type, which must be of type SOCK_STREAM.
 * @param[in] nameLen   This must be passed as IPPROTO_FILLP.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 */
extern FILLP_INT DLL_API FtConnect(FILLP_INT fd, FILLP_CONST FILLP_SOCKADDR *name, socklen_t nameLen);


/**
 * @ingroup FillPSocketInterfaces
 * @brief This is an interface for the user to receive messages from a socket. This is same as the TCP receive
 * function. If the socket is a non-block and there is non-block error on the socket during FtConnect(), then the
 * API will return -1. You can retrieve the last error number of the socket by calling the FtGetErrno API.
 *
 * @param[in] fd   Indicates a socket created by FtSocket().
 * @param[in] mem  Indicates a pointer to the buffer where the message is stored.
 * @param[in] len  Indicates the length, in bytes, of the buffer pointed by the buffer argument.
 * @param[in] flag   Indicates the flag.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.

 * @note
 * If the  product uses FILLP EPOLL (FILLP EPOLL is edge triggered), then the FtRecv function must be called to
 * receive the complete data upon reception of SPUNGE_EPOLLIN.
 * In case of edge triggered epoll event notification method, the FtRecv API will behave same as
 * the tcp recv() function.
 */
extern FILLP_INT DLL_API FtRecv(FILLP_INT fd, void *mem, size_t len, FILLP_INT flag);

#if defined(FILLP_LINUX) && defined(FILLP_MMSG_SUPPORT)
/**
 * @ingroup FillPSocketInterfaces
 * @brief This is an interface for the user to send a message on a socket.
 * If the socket is set as NON-Block and if the non-block error happens then the API returns -1.
 * The Last error number of the socket can be retrieved by calling the API FtGetErrno.
 *
 * @param[in] fd   A socket created by FtSocket.
 * @param[in] iov  A pointer which points to an array of iovec structures.
 * @param[in] iovCount  buffer count of data described by iov.
 * @return On success, returns 0
 */
extern FILLP_INT DLL_API FtWritev(FILLP_INT fd, const struct iovec *iov, FILLP_INT iovCount);

/**
 * @ingroup FillPSocketInterfaces
 * @brief This is an interface for the user to recv a message on a socket.
 * If the socket is set as NON-Block and if the non-block error happens then the API returns -1.
 * The Last error number of the socket can be retrieved by calling the API FtGetErrno.
 *
 * @param[in] fd   A socket created by FtSocket.
 * @param[in] iov  A pointer which points to an array of iovec structures.
 * @param[in] iovCount  buffers of data described by iov.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 */
extern FILLP_INT DLL_API FtReadv(FILLP_INT fd, const struct iovec *iov, FILLP_INT iovCount);

#endif

/**
 * @ingroup FillPSocketInterfaces
 * @brief Closes the socket connection and releases all associated resources. This API is same as
 * the close function of TCP socket.
 *
 * @param[in]    fd      This indicates a socket created by the FtSocket function.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note Once FtClose is called for a socket, the application must not invoke any API to perform any operation
 * on the closed socket.
 * FillP recv_buff has data, say 2 KB.
 * Adapter calls the FtRecv() API with the buffer length as 1 KB. The application checks the input buffer length
 * and the return length of the FtRecv API. If both lengths are identical, the application must call the FtRecv
 * API again. During that time, FillP copies the remaining 1 KB to the adapter.
 * When there is no data in the FillP buffer, but the application calls the FtRecv() API, the API will
 * return EAGAIN.
 */
extern FILLP_INT DLL_API FtClose(FILLP_INT fd);


/**
 * @ingroup FillPSocketInterfaces
 * @brief Indicates graceful closure of socket.
 * Initiates a graceful closure of the socket connection from initiating side (uni-directional).
 *
 * @param[in] fd   Indicates a socket created by FtSocket function.
 * @param[in] how  If how is SHUT_RD, further receptions will be disallowed.  If how is SHUT_WR,
 * further transmissions will be disallowed. If how is SHUT_RDWR, further receptions and
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note The socket resources will not be cleared just by calling the FtShutDown() API. To clear the
 * socket resources, call the FtClose API.
 * If the product uses fillp_epoll, after calling FtShutDown the product has to wait till it receives
 * the SPUNGE_EPOLLERR event in FtEpollWait call, and then call the FtClose() API.
 * If the product does not use fillp_epoll (for example, product which use blocking socket),
 * then after calling FtShutDown, product can call FtClose(), say after 3 seconds.
 */
extern FILLP_INT DLL_API FtShutDown(FILLP_INT fd, FILLP_INT how);


/**
 * @ingroup FillPSocketInterfaces
 * @brief fd a connection on a socket. This is same as the accept function of the TCP socket.
 * @param[in] fd      Indicates a socket which is created by the FtSocket function.
 * @param[in] addr        Indicates a pointer to a SockAddr structure that contains the address of the peer socket.
 * @param[in] addrLen     Indicates the length of the SockAddr structure.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note - The addr and addrLen pointers are optional in the FtAccept API. If the user passes a valid pointer in
 * this API, the stack fills the peer address in this pointer after accepting the connection stack. If user is passing
 * FILLP_NULL_PTR for these 2 pointers, the stack can accept peer connection but will not provide peer address.
 * The addr and addrLen pointers should be address structures of IPv4 and IPv6 as per socket created in FtSocket().
 * Else, the FtAccept() API may fail.
 */
extern FILLP_INT DLL_API FtAccept(FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen);


/**
 * @ingroup FillPSocketInterfaces
 * @brief Listens for connections on a socket. This function is the as same as the listen function of the TCP socket.
 *
 * @param[in] fd        Indicates a socket created by the FtSocket API.
 * @param[in] backLog   Defines the maximum length to which the queue of pending connections for fd can grow.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note The backLog value provided in the FtListen() API must be between 0 and MAX CONNECTION configured during
 * init. Else, stack will take default value, MAX CONNECTION number as the backLog.
 */
extern FILLP_INT DLL_API FtListen(FILLP_INT fd, FILLP_INT backLog);


/**
 * @ingroup FillPEpollInterfaces
 * @brief This API is used to open an epoll file descriptor.
 *
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * The following table provides information about the errors set by this API.
 * <table>

   <tr><th>Errors                     <th>Error Message String
   <tr><td>FILLP_EINVAL  <td>Invalid argument epNum passed.
   <tr><td>FILLP_ENOMEM  <td>There was insufficient memory to create epoll object.
   <tr><td>FILLP_EFAULT  <td>Error occurred due to semaphore or atomic operation.

   </table>
 */
extern FILLP_INT DLL_API FtEpollCreate(void);

/**
 * @ingroup FillPEpollInterfaces
 * @brief  This API is used to open an epoll file descriptor.
 *
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 *
 */
extern FILLP_INT DLL_API FtEpollCreateLinux(FILLP_INT epNum);


/**
 * @ingroup FillPEpollInterfaces
 * @brief This API indicates the control interface for epoll file descriptor.
 *
 * @param[in]            epFd   Indicates a file descriptor on which the operation is performed.
 * @param[in]            op     Indicates an operation which needs to be performed.
 * @param[in]            fd     Indicates a file descriptor.
 * @param[in]            event  Indicates an object linked to the file descriptor.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * The following table provides information about the errors set by this API.
 */
extern FILLP_INT DLL_API FtEpollCtl(FILLP_INT epFd, FILLP_INT op, FILLP_INT fd,
    FILLP_CONST struct SpungeEpollEvent *event);


/**
 * @ingroup FillPEpollInterfaces
 * @brief This function indicates wait for an I/O event on an epoll file descriptor.
 *
 * @param[in]  epFd      Indicates an epoll file descriptor.
 * @param[in]  events    Indicates the memory area pointed to the events, containing the events that will be
 * available for the caller.
 * @param[in]  maxEvents Indicates the maximum number of events.
 * @param[in]  timeout   Indicates the maximum timeout value, in milliseconds.
 * @return On success, returns 0
 * On failure, returns -1. You can retrieve the last error number of the socket by calling the FtGetErrno() API.
 * @note
 * If timeout value is -1, the FillP/VTP stack will wait in blocking mode, till it does not get any event
 * for the epoll list.
 * If timeout value is 0, the FillP stack will wait in nonblocking mode. It will check for only current events
 * available to inform.
 * If timeout value is some other positive number, the stack will wait for the time indicated by the timeout
 * parameter.
 * Do not pass negative numbers other than -1 to this API.
 */
extern FILLP_INT DLL_API FtEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events,
    FILLP_INT maxEvents, FILLP_INT timeout);


/**
 * @ingroup FillP_Control_Interfaces
 * @brief This function is used to manipulate the file descriptor.
 *
 * @param[in] fd    Indicates a socket created by the FtSocket API.
 * @param[in] cmd   Indicates the command to perform on the socket s.
 * @param[in] val   Indicates the flag value used to set the blocking and non blocking socket.
 * @return
 * Upon success, returns the value which depends on command(cmd), or returns error codes on failure.
 * @note
 * This API must be used only in the Linux platform.
 */
extern FILLP_INT DLL_API FtFcntl(FILLP_INT fd, FILLP_INT cmd, FILLP_INT val);


/**
 * @ingroup FillP_Control_Interfaces
 * @brief This function controls the I/O mode of a socket.
 *
 * @param[in] fd    Indicates a socket created by the FtSocket API.
 * @param[in] cmd   Indicates the command to perform on the socket s.
 * @param[in] val   Indicates the flag value used to set the blocking and non blocking socket.
 * @return
 * On success: FILLP_OK.
 * On failure: error code on failure.
 * @note
 * This API must be used only in the Linux platform.
 */
extern FILLP_INT DLL_API FtIoctl(FILLP_INT fd, FILLP_ULONG cmd, FILLP_CONST FILLP_INT *val);


/**
 * @ingroup FillP_Control_Interfaces
 * @brief This function controls the I/O mode of a socket.
 *
 * @param[in] fd    Indicates a socket created by the FtSocket API.
 * @param[in] cmd   Indicates the command to perform on the socket s.
 * @param[in] val   Indicates the flag value used to set the blocking and non blocking socket.
 * @return
 * On success: FILLP_OK.
 * On failure: error code on failure.
 * @note
 * This API must be used only in Windows Platform.
 */
extern FILLP_INT DLL_API FtIoctlSocket(FILLP_INT fd, FILLP_SLONG cmd, FILLP_CONST FILLP_INT *val);

#define FILLP_CONFIG_ALL_SOCKET ((FILLP_UINT16)FILLP_MAX_UNSHORT_VAL)

/**
 * TRCE/ INTERFACE DEFINITION This structure represents the trace direction.
 */
typedef struct FillpTraceDescriptStruct {
    FILLP_UINT8 traceDirection; /* This is of type TYPE FillpTraceDirectEn. */
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 res[7];
#else
    FILLP_UINT8 res[3];
#endif
} FillpTraceDescriptSt;

#define FILLP_TRACE_DESC_INIT(dir) \
    { \
        (dir), \
        {0}, \
    }

/**
 * TRCE/ INTERFACE DEFINITION This enum represents the trace direction.
 */
typedef enum FillpTraceDirectEnum {
    FILLP_TRACE_DIRECT_RECV = 0, /* Indicates FillP trace receive. */
    FILLP_TRACE_DIRECT_SEND,     /* Indicates FillP trace send. */
    FILLP_TRACE_DIRECT_NONE,     /* Indicates FillP trace none. */
    FILLP_TRACE_DIRECT_END       /* Indicates FillP trace end. */
} FillpTraceDirectEn;


/**
 * TRCE/ INTERFACE DEFINITION This enum represents type of FillP trace.
 */
typedef enum FillpTraceTypeEnum {
    FILLP_TRACE_DIRECT_DISABLE = 0,         /* Indicates that FillP/VTP trace is disabled. */
    FILLP_TRACE_DIRECT_USER,                /* Indicates that FillP will trace all the user commands (socket API). */
    FILLP_TRACE_DIRECT_NETWORK,             /* Indicates whether FillP packets are sent or received. */
    FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE, /* Enables FillP to send or receive packets. */
    FILLP_TRACE_END                         /* Indicates the FillP/VTP trace type enum end.  */
} FillpTraceTypeEn;


/**
 * @ingroup FillPTraceInterfaces
 * @brief This function is called by the FillP adapter to start the trace of user APIs and
 * network messages for a particular socket.
 *
 * @param[in] traceObjType   Indicates a trace object defined in FILLP_TRACE_OBJ_TYPE_ENUM and indicates
 * the type of trace which must be done.
 * @param[in] traceObj      A user must pass the FtSocket identification to set the trace for that particular
 * socket (0xFFFFFFFF - means for all the sockets).
 * @param[in] traceHandle    Provides a trace handle which is transparently passed to the user while giving trace.
 * 0xFFFFFFFF is an invalid handle.
 * @return
 * On success: FILLP_OK.
 * On failure: error code on failure. The error reason is returned by the error value.
 */
extern FILLP_INT32 DLL_API FtStartTrace(IN FILLP_UINT8 traceObjType, IN FILLP_INT traceObj,
    IN FILLP_CONST void *traceHandle);


/**
 * @ingroup FillPTraceInterfaces
 * @brief  This function is called by the FillP adapter to stop the trace for a particular socket.
 *
 * @param[in]  traceObjType      Indicates a trace object as defined in FILLP_TRACE_OBJ_TYPE_ENUM  and tells
 * what kind of trace should be done.
 * @param[in] traceObj          This is for a particular socket or for all the associations (0xFFFFFFFF).
 * @return
 * On success : FILLP_OK
 * On failure : Error codes. The error reason is returned by the error value.
 */
extern FILLP_INT32 DLL_API FtStopTrace(IN FILLP_UINT8 traceObjType, IN FILLP_INT traceObj);


/**
 * @ingroup FillPTraceInterfaces
 * @brief Registers the callback function for FillP message trace and FillP command trace.
 *
 * @param[in]    traceFuncCallback      Indicates a trace callback.
 * @return
 * On success :FILLP_OK
 * On failure :Error codes
 */
extern FILLP_INT32 DLL_API FtRegTraceCallbackFn(IN FILLP_CONST FillpTraceSend traceFuncCallback);


/**
 * Indicates the enumeration for the debug commands.
 */
typedef enum FillpDebugCmdEnum {
    /* Provides the output information  about all other debug commands that you can use. */
    FILLP_DBGCMD_HELP,
    /* Sets the level of debug information which stack provides in the callback. Refer FillpDebugLevel for
     * different levels. If level is set as FILLP_DBG_LVL_ERROR only error info is provided to user, if level is set as
     * FILLP_DBG_LVL_WARNING both warning and error info are provided to the user. */
    FILLP_DBGCMD_SET_PRINT_LEVEL,
    /* Shows the current dynamically configured configuration parameters at application level. */
    FILLP_DBGCMD_SHOW_PRINT_LEVEL,
    /* Shows all the information about the FillP socket/connection. */
    FILLP_DBGCMD_SHOW_SOCKET_INFO,
    /* Shows  all the INIT configuration of the stack. */
    FILLP_DBGCMD_SHOW_INIT_RESOURCE,
    /* Shows all the global configuration parameters of the stack. */
    FILLP_DBGCMD_SHOW_GLOBAL_CONFIG_RESOURCE,
    /* Shows all the socket level configuration parameters of the stack. */
    FILLP_DBGCMD_SHOW_SOCKET_CONFIG_RESOURCE,
    FILLP_DBGCMD_BUTT
} FillpDebugCmdEn;


/**
 * @ingroup FillP_Debug
 * @brief FillP uses this function to control the debug command options. You can call this API and set the debug level.
 *
 * @param[in]    command       Indicates the debug command type of any value from @ref FillpDebugCmdEn
 * @param[in]    content        Indicates debug control parameter.
 * @return
 * void. No errors are set.
 */
extern void DLL_API FillpDebugControl(IN FILLP_UINT8 command, IN FILLP_CONST void *content);


/**
 * @ingroup fillp_stack_api
 * @brief  This function is called by the FillP adapter to register the adapter's callback function for
 * LM functionality. If A function pointer is passed as NULL, then it is omitted  for copying. So, the user/adapter
 * can call this function to register the function pointers separately.
 *
 * @param[in]    lmFuncCallback     Indicates the pointer to LM callback function struct.
 * @return
 * Success:   ERR_OK
 * Failure: error code
 */
extern FILLP_INT32 DLL_API FillpRegLMCallbackFn(IN FILLP_CONST FillpLmCallbackFunc *lmFuncCallback);


/**
 * @ingroup fillp_stack_api
 * @brief This function is called by the FillP adapter to get the address with which the requested socket is bound.
 *
 * @param[in]      fd                 Indicates the socket created.
 * @param[out]     name               Indicates the socket address that needs to be connected.
 * @param[in]      nameLen            Indicates the length of the address.
 * @return
 * On success : ERR_OK
 * On failure : error code
 */
extern FILLP_INT DLL_API FtGetSockName(FILLP_INT fd, FILLP_SOCKADDR *name, socklen_t *nameLen);

/**
 * @ingroup fillp_stack_api
 * @brief This function is called by the Fillp adapter to get the peer address to which the
 * requested socket is connected.
 *
 * @param[in]      fd                 Indicates the socket created.
 * @param[out]     name               Indicates the socket address that needs to be connected.
 * @param[in,out]  nameLen            Indicates the length of the address.
 * @return
 * On success : ERR_OK
 * On failure : error code
 */
extern FILLP_INT DLL_API FtGetPeerName(FILLP_INT fd, FILLP_SOCKADDR *name, socklen_t *nameLen);

/**
 * @ingroup fillp_stack_api
 * @brief    This function is called by the Fillp Adapter to get system socket options. \n
 * Note: All parameters are passed uninterpreted to the system interface.
 * This function always returns failure for RAW socket.
 *
 * @param[in]      fd                 Indicates a socket created by FtSocket.
 * @param[in]      level              Indicates the level at which the option resides and the name of the option must
 * be specified, when manipulating socket options.
 * @param[in]      optName            Indicates the Optname options which are passed uninterpreted to system interface.
 * @param[out]     optValue             Indicates the option value obtained by invoking the FtGetSockOpt API.
 * @param[out]     optLen             Indicates the option length obtained by invoking the FtGetSockOpt API.
 * @return
 * On success : ERR_OK
 * On failure : error code
 */
extern FILLP_INT DLL_API FtGetSockOpt(FILLP_INT fd, FILLP_INT level, FILLP_INT optName,
    void *optValue, FILLP_INT *optLen);

/**
 * @ingroup fillp_stack_api
 * @brief    This function is called by the Fillp Adapter to set system socket options. \n
 * Note: All parameters are passed uninterpreted to the system interface. This function always returns failure
 * for RAW socket.
 *
 * @param[in]      fd                 Indicates a socket created by FtSocket.
 * @param[in]      level              Indicates the level at which the option resides and the name of the option must
 * be specified, when manipulating socket options.
 * @param[in]      optName            Indicates the Optname options which are passed uninterpreted to system interface.
 * @param[in]      optValue             Indicates the option value obtained by invoking the FtGetSockOpt API.
 * @param[in]      optLen             Indicates the option length obtained by invoking the FtGetSockOpt API.
 * @return
 * On success : ERR_OK
 * On failure : error code
 */
extern FILLP_INT DLL_API FtSetSockOpt(FILLP_INT fd, FILLP_INT level, FILLP_INT optName,
    FILLP_CONST void *optValue, socklen_t optLen);


/* Indicates configuration of the enumerator members. */
#define FT_CONFIG_BASE_ENUM    1

/**
 * STATIC/Pure Init Configurations
 *
 * 1) Maximum Socket Number
 *
 * DYNAMIC/POST Init Configurations
 *
 * 1)     TX Burst
 * 2)     RX Burst
 * 3)     Send Cache
 * 4)     Recv Cache
 * 5)     Connection Timeout
 * 6)     Keep Alive Time
 * 7)     Full CPU
 * 8)     Default Rate
 * 9)     Packet Size
 * 10)     NACK Repeat Times
 * 11)     Packet Loss Allowed
 * 12)    Pack Interval
 * 13)     Self Adaption
 * 14)     USE Redundancy
 * 15)     Default rtt value
 * 15)     Calculate rtt Dynamically
 *
 * List Of Stack Level Configurations
 *
 * 1)     Stack Maximum Socket Number
 * 2)     Stack Maximum Connection Number
 * 3)     Socket TX Burst
 * 4)     Socket RX Burst
 * 5)     Stack Send Cache
 * 6)     Stack Recv Cache
 * 7)    Socket Full CPU
 * 8)     Stack Default Rate
 * 9)     Stack Packet Size
 * 10)    Stack NACK Repeat Times
 * 11)    Stack Packet Loss Allowed
 * 12)    Stack PACK Interval
 * 13)     Socket Self Adaption
 * 14)     Socket USE Redundancy
 * 15)     Default rtt value
 * 16)     STACK calculate rtt Dynamically
 *
 * List Of Socket Level Configurations
 *
 * 1)     Socket Send Cache
 * 2)     Socket Recv Cache
 * 3)    Socket OS Send Compensate
 * 4) Socket NACK Repeat Times
 * 5) Socket Packet Loss Allowed
 *
 * List of Timer Configuration (stack level and Dynamic)
 * 1) Connect timer
 * 2) disconnect timer
 * 3) keep alive timer
 * 4) pack timer
 * 5) close pending
 */
typedef enum FillpFecRedundancyLevelStrcut {
    FILLP_FEC_REDUNDANCY_LEVEL_INVLAID = 0,
    FILLP_FEC_REDUNDANCY_LEVEL_LOW,
    FILLP_FEC_REDUNDANCY_LEVEL_MID,
    FILLP_FEC_REDUNDANCY_LEVEL_HIGH,
    FILLP_FEC_REDUNDANCY_LEVEL_REAL,
    FILLP_FEC_REDUNDANCY_LEVEL_AUTO,
    FILLP_FEC_REDUNDANCY_LEVEL_BUTT
} FillpFecRedundancyLevel;

/**
 * Provides the enum for FillP app list configuration.
 */
/* Enum Declarations */
typedef enum FillpConfigAppListEnum {
    FT_CONF_INIT_APP = FT_CONFIG_BASE_ENUM,
    FT_CONF_INIT_STACK,

    FT_CONF_TX_BURST, /* Indicates the TX burst for UDP. */
    FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE, /* Indicates the maximum server allowed send cache. */
    FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE, /* Indicates the maximum server allowed receive cache. */
    FT_CONF_SEND_CACHE, /* Indicates the FillP send cache. */
    FT_CONF_RECV_CACHE, /* Indicates the FillP receive cache. */
    FT_CONF_SEND_BUFFER_SIZE, /* Indicates the size of the send buffer. */
    FT_CONF_RECV_BUFFER_SIZE, /* Indicates the size of the receive buffer. */
    FT_CONF_OPPOSITE_SET_RATE, /* Indicates the FillP stack set rate. */
    FT_CONF_PACKET_SIZE, /* Indicates the FillP stack packet size. */
    FT_CONF_SLOW_START, /* Indicates the slow start. */
    FT_CONF_MAX_RATE, /* Indicates the FillP stack maximum rate. */
    FT_CONF_MAX_RECV_RATE, /* Indicates the maximum packet receive rate. */
    FT_CONF_ENABLE_NACK_DELAY, /* Indicates the FillP NACK delay feature. */
    FT_CONF_NACK_DELAY_TIMEOUT, /* Indicates the FillP NACK delay timeout. */
    FT_CONF_ENLARGE_PACK_INTERVAL, /* Indicates about the enlarging pack duration when there is no much data send */
    FT_CONF_TIMER_CONNECT, /* Indicates about the connection timeout duration */
    FT_CONF_TIMER_CONNECTION_RETRY, /* Indicates about the connection retry duration */
    FT_CONF_TIMER_DISCONNECT_RETRY_TIMEOUT, /* Indicates about the connection disconnect fin duration */
    FT_CONF_TIMER_KEEP_ALIVE, /* Indicates about the keep alive time duration */
    FT_CONF_FEC_REDUNDANCY_LEVEL, /* Indicates about the data loss packet retry redundancy level */
    FT_CONF_RECV_JITTER, /* Indicates about the jitter  */
    FT_CONF_APP_FC_RECV_RATE, /* Indicates about the periodRecvRate  */
    FT_CONF_APP_FC_RECV_PKT_LOSS, /* Indicates about the periodRecvPktLoss  */
    FT_CONF_CONST_RATE, /* Indicates about the constant send rate  */
    FT_CONF_APP_FC_RECV_RATE_BPS, /* Indicates about the periodRecvRateBps  */
    FT_CONF_APP_FC_STATISTICS, /* Indicates about the FILLP_APP_FC_STASTICS  */
    FT_CONF_APP_FC_STASTICS_INTERVAL, /* Indicates about the app flow statics intterval  */
    FT_CONF_APP_DIFFER_TRANSMIT, /* indicates the app flow using differentiated transmission,
                                  * which means no flow control for I frame and BDP for P frame */
    FT_CONF_APP_PACK_INTERVAL, /* Indicate the FillP default pack interval */

    FT_CONF_APP_CONFIG_BOUNDARY = 0x7f,

    FT_CONF_MAX_SOCK_NUM, /* Indicates about max socket number */
    FT_CONF_MAX_CONNECTION_NUM, /* Indicates about max connection number */
    FT_CONF_RECV_CACHE_PKT_NUM_BUFF_SIZE, /* Indicates about reac cache packet number buffer size */
    FT_CONF_RX_BURST, /* Indicates about receiver burst count */
    FT_CONF_FULL_CPU, /* Indicates about occupying the full core CPU */
    FT_CONF_OUT_OF_ORDER_CATCHE_FEATURE, /* Indicates about enabling the out of order packet buffer feature */
    FT_CONF_CPU_CORE_USE, /* Indicates about the CPU core to be used */
    FT_CONF_OPPOSITE_SET_PERCENTAGE, /* Indicates about the opposite set rate percentage */
    FT_CONF_MAX_RATE_PERCENTAGE, /* Indicates about the maximum set rate percentage */
    FT_CONF_NACK_REPEAT_TIMES, /* Indicates about the nack control packet repeat count */
    FT_CONF_PACKET_LOSS_ALLOWED, /* Indicates about the allowed packet loss */
    FT_CONF_USE_FEC, /* Indicates about the flow control enable */
    FT_CONF_SUPPORT_FAIRNESS, /* Indicates about the support for fairness */
    FT_CONF_INITIAL_RATE, /* Indicates about the initial rate */
    FT_CONF_CORE_MAX_RATE, /* Indicates about the overall rate on the sending channel */
    FT_CONF_CORE_MAX_RECV_RATE, /* Indicates about the overall rate on the receiving channel */
    FT_CONF_TIMER_RECV_CACHE_PKT_NUMBUFF, /* Indicates about the receive packet cache buffer number */
    FT_CONF_ALG, /* Indicates about the flow control algorithm to be selected */
    FT_CONF_INIT_STACK_EXT, /* Indicates about the configs which needs to be set for achieveing 3.2Gbps */
    FT_CONF_BFULL_CPU_USE_THRESHOLD_RATE, /* Indicates about the full cpu rate(Kbps) */
    FT_CONF_STACK_CORE_LIMIT_RATE, /* Indicates about the overall rate limit on the sending channel */
    FT_CONF_STACK_CORE_SEND_CACHE, /* Indicates the FillP stack send cache. */
    FT_CONF_STACK_CORE_RECV_CACHE, /* Indicates the FillP stack receive cache. */
    FT_CONF_MAX_ASSIST_MSG_ITEM_NUM, /* Indicates the max assist msg item number. */
    ENUM_FILLP_CONFIG_LIST_BUTT = 0xFF /* Indicates the maximum value for the enumeration. */
} FtConfigItemList;

typedef struct FillpAppFcStasticsStruct {
    /* Indicates the period trans delay, uint:ms */
    FILLP_UINT32 periodRtt;
    /* Indicates the period pkt loss rate on recv side, precision xx% lost rate is 1%, then 1 will returned */
    FILLP_UINT32 periodRecvPktLoss;
    /* Indicates the period recv rate, uint:kbps */
    FILLP_UINT32 periodRecvRate;
    /* Indicates the period pkt loss rate on recv side, precision xx.xx%, lost rate is 1.10%, then 110 will returned */
    FILLP_UINT32 periodRecvPktLossHighPrecision;
    /* Indicates the period pkt loss rate on send side, precision xx.xx%, lost rate is 1.10%, then 110 will returned */
    FILLP_UINT32 periodSendPktLossHighPrecision;
    /* Indicates the period recv rate, uint:bps */
    FILLP_ULLONG periodRecvRateBps;
    /* Indicates the period send rate, uint:bps */
    FILLP_ULLONG periodSendRateBps;
    /* Indicates the period send rate, uint:ms */
    FILLP_LLONG jitter;
} FillpAppFcStasticsSt;

/**
 * Here provide one common lib to eBackup for both 200Mbps and 3.2Gbps requirement.
 * Application can use this lib for both the requirements by following below method:
 * 1) For eBackup (200Mbps) case, no change in Application code
 * 2) For eBackup_perf (3.2Gbps) case, in Application code, before FtInit(), need to set below
 * configuration using FtConfigSet with name as FT_CONF_INIT_STACK_EXT
 *
 * enableDefault10GConfigsForEbackupPdt:   Enable: Non Zero value; Disable: FILLP_FALSE
 * pktLossThresHoldMax:
 * timingWheelAccuracy;
 * maximalAckNumLimit : 2000
 * sendOneAckNum : 100
 * cpuPauseTime : 0
 * retransmitCmpTime : 0
 * minRate : 350
 * minPackInterval : 20000
 * unsendBoxLoopCheckBurst : 1024
 * instUnsendBoxSize: 819200
 * nackRetryLen:600
 * para :Reserved for future extension purpose
 */
typedef struct FillpGlobalPreinitExtConfigsStruct {
    FILLP_UINT8 enableDefault10GConfigsForEbackupPdt; /* Enable: Non Zero value; Disable: FILLP_FALSE */
    FILLP_UINT8 pktLossThresHoldMax;
    FILLP_UINT16 timingWheelAccuracy;
    FILLP_UINT32 maximalAckNumLimit;
    FILLP_UINT32 sendOneAckNum;
    FILLP_UINT16 cpuPauseTime;
    FILLP_UINT8 retransmitCmpTime;
    FILLP_UINT8 reserve;
    FILLP_UINT16 minRate;
    FILLP_UINT16 minPackInterval;
    FILLP_UINT16 unsendBoxLoopCheckBurst;
    FILLP_UINT16 reserv;
    FILLP_UINT32 instUnsendBoxSize;
    FILLP_UINT16 nackRetryLen;
    FILLP_UINT16 reserved;
    void *para; /* For future extension purpose */
} FillpGlobalPreinitExtConfigsSt;


/**
 * Represents the UDP resource data structure.
 */
/* Structure Declarations */
typedef struct FillpUdpResourceStruct {
    /* Indicates the  number of packets received at each send cycle. This value must be tuned properly for getting
     * high end performance. The default value is 128. Range: 1 -- 0xFFFF */
    FILLP_UINT16 rxBurst;
    FILLP_UINT8 padd[2];
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
} FillpUdpResourceSt;

/**
 * Provides the values for the FillpCommonStruct data structure.
 */
typedef struct FillpCommonStruct {
    /* Indicates the receive cache packet number buffer size. The default value is 100.
     * Valid values are 1 to 10000. */
    FILLP_UINT32 recvCachePktNumBufferSize;
    /* Indicates the socket numbers supported for the FillP Server.  For 32 value, the server creates the same number
     * of ring queues. The default value is 64. Valid values are 1 to 64. */
    FILLP_UINT16 maxSockNum;
    /* Indicates the maximum connection numbers supported by each socket. This value cannot be greater than
     * "maxSockNum" otherwise set as equal to "maxSockNum". The default value is 32. Valid values are 1 to 32. */
    FILLP_UINT16 maxConnectionNum;
    /* Indicates the CPU option.  If set to TRUE, the FillP main thread will not sleep. Instead of just sending,
     * receiving data, and doing other processing, this will lead to better transfer rate control. It can have impact
     * on CPU rate. If set to FALSE, the FillP main thread will sleep for certain interval based on the packet transfer
     * rate. In this case, the CPU utilization is less but can have adverse impact on packet rate. You must select the
     * option based on this trade-off and configure this flag properly. Example:  If we set the rate to 100 Mbps,
     * we should send one packet per 100 us, and do sleep for 100 us. But, while sleep is done more time may be passed
     * (more than 10 us). So when FillP awakes next, FillP has to send more packets at one time.
     * The default value is FALSE. */
    FILLP_BOOL fullCpu;
    /* Indicates whether to support out of order cache feature. The default value is TRUE. */
    FILLP_BOOL outOfOrderCacheFeature;
    /* Indicates the end of the enum. */
    FILLP_UINT8 padd[2]; /* add 2 bytes for byte alignment */
    FILLP_UINT32 maxAssistMsgItemNum;
} FillpCommonSt;


/**
 * Provides the values for flow control.
 */
typedef struct FillpFlowControlStruct {
    /* Indicates the maximum sending rate of the network. The default value is 950 Mbps. Range: non-zero to any */
    FILLP_UINT32 maxRate;
    /* Indicates the maximum receiving rate of the network. The default value is 950 Mbps. Range: non-zero to any */
    FILLP_UINT32 maxRecvRate;
    /* Indicates the rate with which FillP needs to start the data during the slow start. The default value is 2 Mbps.
     * Range: non-zero to maxRate - 1 */
    FILLP_UINT32 initialRate;
    /* Indicates the opposite set percentage. */
    FILLP_UINT16 oppositeSetPercentage;
    /* Indicates the maximum rate percentage. */
    FILLP_UINT16 maxRatePercentage;
    /* Indicates the number of NACK packets to send from the system to avoid congestion and NACK Failure rate. If it
     * set as 10, then NACK packets will be sent 10 times to remote end. The default value is 10. Range: 1 to 0xFF */
    FILLP_UINT16 nackRepeatTimes;
    /* Indicates the maximum allowed packet loss in the system. For High "pktLossAllow" value, the sending rate
     * should be decreased. This value should be minimum in order to get a 2 Mbps sending rate.
     * The default value is 10. */
    FILLP_UINT16 pktLossAllow;
    /* Enables or disables the redundant data retransmit feature. For data packet which is retransmitted multiple
     * times due to multiple send failures, FillP can send redundant data packet at same time to further avoid the
     * further packet loss. The default value is FALSE. */
    FILLP_BOOL fecEnable;
    /* Algorithm choice */
    FILLP_UINT8 fcAlg;
    /* Indicates whether fair sharing of bandwidth among the connections is required. If enabled, fairness would be
     * provided. The default value is NO FAIRNESS. Range   = { FillpStackFairnessTypeEn } */
    FILLP_UINT8 supportFairness;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
} FillpFlowControlSt;


/**
 * Provides the data structure for the FillP timer.
 */
typedef struct FillpTimerStruct {
    /* Indicates the receive packet time out. The default value is 20. Valid values are 10 to 300. */
    FILLP_UINT16 recvCachePktNumBufferTimeout;
    FILLP_UINT8 padd[2];
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
} FillpTimer;


/**
 * Provides the global configurations.
 */
typedef struct FillpGlobalConfigsStruct {
    FillpUdpResourceSt udp; /* Indicates the UDP resource list. */
    FillpCommonSt common; /* Indicates the common resource list. */
    FillpFlowControlSt flowControl; /* Indicates the flow control resource list. */
    FillpTimer timers; /* Indicates the set timers. */
} FillpGlobalConfigsSt;

/**
 * Provides UDP resource values.
 */
typedef struct FillpAppUdpResourceStruct {
    /* Indicates the number of packets sent at each send cycle. The TX burst value must be tuned properly for getting
     * high end performance. \n Minimum Value: greater than 0 \n Maximum Value:  0x7fff \n Default Value: \n
     * 4096 (Miracast PDT)  */
    FILLP_UINT16 txBurst;
    /* This padding is not required, but since this structure is member of another structure, padding to 4 bytes. */
    FILLP_UINT8 padd[2];
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
} FillpAppUdpResourceSt;


/**
 * Provides the values for the FillpAppCommonStruct data structure.
 */
typedef struct FillpAppCommonStruct {
    /* Indicates the maximum cache allowed by the server to send. Minimum Value: greater than 0 Maximum Value:
     * No upper limit Default Value: 1638400   */
    FILLP_UINT32 maxServerAllowSendCache;
    /* Indicates the maximum cache allowed by the server to receive. Minimum Value: greater than 0
     * Maximum Value:  No upper limit Default Value: 1638400 */
    FILLP_UINT32 maxServerAllowRecvCache;
    /* Indicates the cache pool size reserved to send data for each connection. Minimum Value: greater than 0
     * Maximum Value: Less than or equal to 0x15D860 Default Value: 8192 (Miracast PDT)   */
    FILLP_UINT32 sendCache;
    /* Indicates the cache pool size reserved for received data for each connection. Minimum Value: greater than 0
     * Maximum Value: Less than or equal to 0x15D860 Default Value: 8192 (Miracast PDT)   */
    FILLP_UINT32 recvCache;
    /* Indicates the size of the send buffer. Minimum Value: greater than or equal to 1500 Maximum Value:
     * No maximum value Default Value: (16 * 1024 * 1024) */
    FILLP_UINT32 udpSendBufSize;
    /* Indicates the size of the receive buffer. Minimum Value: greater than or equal to 1500 Maximum Value:
     * No maximum value Default Value: (16 * 1024 * 1024) */
    FILLP_UINT32 recvBufSize;
    /* Indicates the retry count for the  keep alive signal. Values: FILLP_TRUE or FILLP_FALSE Default Value:
     * FILLP_FALSE (Miracast PDT) */
    FILLP_BOOL enableNackDelay;
    /* Indicates the the increase the pack interval when there is no data transmission. Values: Any value. Greater
     * than 0 means that the feature is enabled Default Value: FILLP_TRUE (Miracast PDT) */
    FILLP_BOOL enlargePackIntervalFlag;
    FILLP_UINT16 paddShort;
    FILLP_UINT32 paddUint32;
    /* Indicates the duration for delaying nack packet. Minimum Value: greater than or equal to (10000 << 3)
     * Maximum Value:  Less than or equal to 0x7fffffff  20000 Default Value: 20000 */
    FILLP_LLONG nackDelayTimeout;
} FillpAppCommonSt;


/**
 * Provides the values for flow control.
 */
typedef struct FillpAppFlowControlStruct {
    /* Indicates the  maximum send rate, in Mbps, the connection in this stack can reach. If set on a particular
     * socket ID, then it is applicable for that socket ID, otherwise it will be set as default value for all the
     * sockets which will be created later. Minimum Value: greater than 0 Maximum Value: Less than
     * (10 * 1000 * 1000) Default Value: (20 * 1000) (Miracast PDT) */
    FILLP_UINT32 maxRate;
    /* Maximum rate to be used for receiving the traffic If set on a particular socket ID, then it is applicable for
     * that socket ID, otherwise it will be set as default value for all the sockets which will be created later
     * Minimum Value: greater than 0 Maximum Value: Less than (10 * 1000 * 1000) Default Value:
     * (20 * 1000) (Miracast PDT) */
    FILLP_UINT32 maxRecvRate;
    /* Indicates the opposite set rate. Minimum Value: less than (10 * 1000 * 1000) Maximum Value: Less than
     * maxRate Default Value: 0 */
    FILLP_UINT32 oppositeSetRate;
    /* Indicates the maximum size of packet supported for send and receive on FillP socket. If you change this value
     * sendPktNum and send interval value are also changed. Minimum Value: 0 Maximum Value: Less than or equal
     * to (FILLP_FRAME_MTU - FILLP_HLEN) Default Value: 1300  */
    FILLP_UINT16 pktSize;
    /* Indicates the slow start. Values: FILLP_TRUE and FILLP_FALSE Default Value: FILLP_FALSE (Miracast PDT) */
    FILLP_BOOL slowStart;
    /* Enables constant rate. Values: FILLP_TRUE and FILLP_FALSE Default Value: FILLP_FALSE */
    FILLP_BOOL constRateEnbale;
    /* enable differentiated transmission */
    FILLP_BOOL differTransmit;
} FillpAppFlowControlSt;


/**
 * Provides the app timer values.
 */
typedef struct FillpAppTimerStruct {
    /* Indicates the keep alive time, after which the connection will be disconnected if no messages are exchanged.
     * Minimum Value: Greater than or equal to 100 ms Maximum Value: Less than or equal to (3600 * 1000) ms
     * Default Value: (10*1000) */
    FILLP_UINT32 keepAliveTime;
    /* Indicates the disconnect retry timeout. Minimum Value: Greater than 0 Maximum Value: Less than or
     * equal to (10 * 1000) ms Default Value: 200 */
    FILLP_UINT32 disconnectRetrytimeout;
    /* Indicates the maximum time for any connection to remain in connecting state. The connection is set to IDLE
     * state after this timer expires. Minimum Value: Greater than 0 Maximum Value: Less than or equal to
     * (300 * 1000) ms \n Default Value: (10 * 1000) */
    FILLP_UINT32 connectTimeout;
    FILLP_UINT16 reserve;  /* reserve */
    /* Indicates the connection retry timeout. Minimum Value: Greater than 0  Maximum Value: Less than or
     * equal to (10 * 1000) ms Default Value: 200 */
    FILLP_UINT16 connRetrytimeout;
    FILLP_UINT16 reserveExt;
    FILLP_UINT8 padd[2];
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserved;
#endif
} FillpAppTimerSt;

/**
 * Provides the global configurations.
 */
typedef struct FillpAppGlobalConfigStruct {
    FillpAppUdpResourceSt udp; /* Indicates the UDP resource list. */
    FillpAppCommonSt common; /* Indicates the common resource list.  */
    FillpAppFlowControlSt flowControl; /* Indicates the flow control resource list. */
    FillpAppTimerSt timers; /* Indicates the timer list. */
} FillpAppGlobalConfigsSt;

/**
 * Provides the FillP stack fairness type.
 */
typedef enum FillpStackFairnessTypeEnum {
    FILLP_FAIRNESS_TYPE_NONE = 0,         /* Indicates the fairness type none. */
    FILLP_FAIRNESS_TYPE_EQUAL_WEIGHT = 1, /* Indicates the equal weight fairness type. */
    FILLP_FAIRNESS_TYPE_CONN_SET_VAL = 2, /* Indicates the setting value. */
    FILLP_FAIRNESS_TYPE_END,              /* Indicates FillP fairness end. */
    FILLP_FAIRNESS_TYPE_BUTT = 0xFF       /* Indicates the FillP fairness type. */
} FillpStackFairnessTypeEn;

/**
 * @ingroup fillp_stack_api
 * @brief  Registers the system interface functions to be used by the FillP stack. The function pointers of all
 * system functions defined by this API are passed FillpSysLibCallbackFuncSt to FILLP stack to be registered
 * and used during the run time of the stack. Users must pass "FillpCryptoRandFunc cryptoRand" which is to register
 * cryptographically strong random number generator function. Others callback pointers are optional, if users pass
 * them as NULL, then default functions will be registered by FillP/VTP. This function should be called before
 * initializing the stack.
 *
 * @param[in] libSysFunc    Pointer to system interface callback function structure FillpSysLibCallbackFuncSt.
 * @param[in] para           This is a reserve parameter for future extension. User can pass it as FILLP_NULL_PTR.
 * @return
 * FILLP_SUCCESS : Upon successful
 * ERR_NULLPTR : Upon failure
 */
extern FILLP_INT32 DLL_API FillpApiRegLibSysFunc(IN FILLP_CONST FillpSysLibCallbackFuncSt *libSysFunc,
    IN FILLP_CONST void *para);

/**
 * @ingroup fillp_stack_api
 * @brief  Registers the APP functions to be used by the FillP stack. The function pointers of all APP functions
 * defined by this API are passed FillpAppCallbackFunc to FILLP stack to be registered and used during
 * the run time of the stack. This api can only invoked after FillpApiRegLibSysFunc.
 * fillpSockCloseCbkFunc callback pointers are optional and default value is NULL.
 *
 * @param[in] appCbkFunc       Pointer to APP callback function structure FillpAppCallbackFunc.
 * @return
 * 0 : Upon successful
 * -1 : Upon failure
 * The following table provides information about the errors set by this API.
 */
extern FILLP_INT32 DLL_API FillpApiRegAppCallbackFunc(IN FILLP_CONST FillpAppCallbackFunc *appCbkFunc);

/**
 * @ingroup fillp_stack_api
 * @brief  This API is used to initialize the VTP/FillP stack.
 * @note Two threads cannot call FtInit() simultaneously. Also FtInit() cannot be called multiple time once it is
 * successful. It is suggested that products use this API only once by a single thread to initialize VTP/FIllP stack.
 *
 * @return The error reason is returned by the return value.
 */
extern FILLP_INT DLL_API FtInit(void);

/**
 * @ingroup fillp_stack_api
 * @brief   This API is used to deinitialize the FillP stack.
 * @note
 * - User must close all the sockets created by FtSocket() / FtEpollCreate() before calling the FtDestroy() API.
 * Otherwise the  FtDestroy() API will block.  There is another API FtDestroyNonblock() which does not block,
 * so user can choose to use this API.
 * - Two threads cannot call FtDestroy() simultaneously. Also FtDestroy() cannot be called multiple time after it is
 * successful. It is suggested that products use this API only once by a single thread.
 *
 * @return  This API does not set any error.
 */
extern void DLL_API FtDestroy(void);

/**
 * @ingroup fillp_stack_api
 * @brief  This API is use  to deinit the fillp stack but not block.
 *
 * @return  This API does not set any error.
 */
extern void DLL_API FtDestroyNonblock(void);

/**
 * Provides the statistics types.
 */
typedef enum FillpStatsTypeEnum {
    FILLP_STATS_DIRECT_PACK = 0,   /* Indicates the packet statistics. */
    FILLP_STATS_DIRECT_KEEP_ALIVE, /* Indicates the packet keep alive statistics. */
    FILLP_STATS_DIRECT_DEBUG,      /* Indicates the direct debug statistics. */
    FILLP_STATS_DIRECT_TRAFFIC,    /* Indicates the traffic statistics. */
    FILLP_STATS_DIRECT_ALL         /* Indicates the statistics for all packets. */
} FillpStatsTypeEn;

/**
 * Provides the FillP packet statistics.
 */
struct FillpPackStastics {
    FILLP_LLONG packTimePassed; /* Indicates the packet time passed. */
    FILLP_LLONG packSendTime; /* Indicates the packet send time. */
    FILLP_LLONG packRttDetectTime; /* Indicates the packet rtt detect time. */
    FILLP_ULLONG periodRecvBits; /* Indicates the packet receive bits. */
    FILLP_UINT32 packInterval; /* Indicates the packet time interval. */
    FILLP_UINT32 lastPackRecvRate; /* Indicates the packet receive rate. */
    FILLP_UINT32 periodRecvRate; /* Indicates the packet receive rate. */
    FILLP_UINT32 maxRecvRate; /* Indicates the maximum packet receive rate. */
    FILLP_UINT32 packLostSeq; /* Indicates the packet lost sequence. */
    FILLP_UINT32 packPktNum; /* Indicates the packet number. */

    FILLP_UINT32 periodRecvedOnes; /* Indicates the received packets. */
    FILLP_UINT32 periodDroped; /* Indicates the dropped packets. */

    FILLP_UINT32 periodSendRate; /* Indicates the packet send rate. */
    FILLP_UINT32 periodAckByPackRate; /* Indicates the ack by packet rate. */

    FILLP_UINT32 packIntervalBackup; /* Records the packInterval as a backup. */
    FILLP_UINT16 periodRecvPktLoss; /* Indicates the packet receive loss. */
    FILLP_BOOL peerRtt; /* Indicates the peer value. */
    FILLP_UINT8 padd[5];
};

/* Provides the FillP NACK statistics. */
struct FillpNackStastics {
    FILLP_LLONG nackDelayTimeout; /* Indicates the NACK delay timeout. */
    FILLP_UINT32 nackInterval; /* Indicates the NACK interval. */
    FILLP_UINT16 nackHistorySendQueueNum; /* Indicates the NACK history send queue number. */
    FILLP_UINT16 currentHistoryNackNum; /* Indicates the Ncurrent history NACK number. */
    FILLP_LLONG nackSendTime; /* Indicates the NACK send time. */
    FILLP_UINT32 historyNackQueueLen; /* Indicates the history NACK queue length. */
    FILLP_UINT8 fnsPadd[4];
};

/**
 * Provides the keep alive statistics.
 */
struct FillpKeepAliveStastics {
    FILLP_LLONG lastRecvTime; /* Indicates the last receive time. */
    FILLP_LLONG lastDataRecvTime; /* Indicates the last data receive time. */
    FILLP_LLONG lastSendTime; /* Indicates the last send time. */
};

/**
 * Provides the debug pcb statistics.
 */
struct FillpStatatisticsDebugPcb {
    FILLP_LLONG packRecvedTimeInterval; /* Indicates the packet received time interval. */
    FILLP_LLONG curPackDeltaUs;
    FILLP_INT multiRetry; /* Indicates multiple retries. */
    FILLP_INT retryOne; /* Indicates one time retry. */
    FILLP_INT retryThreeTimes; /* Indicates three times retry. */
    FILLP_INT retryFourthTimes; /* Indicates four times retry. */
    FILLP_INT retryMore; /* Indicates more retry. */
    FILLP_INT maxRetry; /* Indicates the maximum retry. */
    FILLP_UINT32 connReqSend; /* Indicates the connection request send. */
    FILLP_UINT32 connReqFailed; /* Indicates the connection request failed. */
    FILLP_UINT32 connReqAckSend; /* Indicates the connection request ACK send. */
    FILLP_UINT32 connReqAckFailed; /* Indicates the connection request ACK failed. */
    FILLP_UINT32 connConfirmSend; /* Indicates the connection confirm request send. */
    FILLP_UINT32 connConfirmFailed; /* Indicates the connection confirm request failed. */
    FILLP_UINT32 connConfirmAckSend; /* Indicates the connection confirm request ACK send. */
    FILLP_UINT32 connConfirmAckFailed; /* Indicates the connection confirm request ACK failed. */
    FILLP_UINT32 disconnReqSend; /* Indicates the disconnection request send. */
    FILLP_UINT32 disconnReqFailed; /* Indicates the disconnection request failed. */
    FILLP_UINT32 disconnRspSend; /* Indicates the disconnection response send. */
    FILLP_UINT32 disconnRspFailed; /* Indicates the disconnection response failed. */
    FILLP_UINT32 keepAliveProbeReqSend; /* Indicates the keep alive probe request send. */
    FILLP_UINT32 keepAliveProbeReqFailed; /* Indicates the keep alive probe request failed. */
    FILLP_UINT32 keepAliveProbeRspSend; /* Indicates the keep alive probe response send. */
    FILLP_UINT32 keepAliveProbeRspFailed; /* Indicates the keep alive probe response failed. */
    FILLP_UINT32 nackSend; /* Indicates the NACK send. */
    FILLP_UINT32 nackFailed; /* Indicates the NACK failed. */
    FILLP_UINT32 nackRcv; /* Indicates the NACK received. */
    FILLP_UINT32 packSend; /* Indicates the packet send. */
    FILLP_UINT32 packFailed; /* Indicates the packet failed. */
    FILLP_UINT32 packRcv; /* Indicates the packet received. */
    FILLP_UINT32 nackPktNum; /* Indicates the NACK packet number. */
    FILLP_UINT32 packIntervalPktNum; /* Indicates the packet number of the packet interval. */
    FILLP_UINT32 packIntervalSendBytes; /* Indicates the send bytes of the packet interval. */
    FILLP_UINT32 packIntervalSendPkt; /* Indicates the send packets of the packet interval. */
    FILLP_UINT8 onePktMaxSendCount; /* Indicates the maximum send count for one packet. */
    FILLP_UINT8 fsdpPadd[3];
};

/**
 * Provides the traffic statistics.
 */
struct FillpStatisticsTraffic {
    FILLP_UINT32 totalRecved; /* Indicates the total packet received. */
    FILLP_UINT32 totalRecvedBytes; /* Indicates the total received bytes. */
    FILLP_UINT32 totalDroped; /* Indicates the total packets dropped. */
    FILLP_UINT32 totalRetryed; /* Indicates the total packets retried. */
    FILLP_UINT32 totalSendFailed; /* Indicates the total packet send failed. */
    FILLP_UINT32 totalSend; /* Indicates the total packets sent. */
    FILLP_UINT32 totalSendBytes; /* Indicates the total sent bytes. */
    FILLP_UINT32 totalOutOfOrder; /* Indicates the total packets out of order. */
    FILLP_UINT32 totalRecvLost; /* Indicates the total packet receive lost. */
    FILLP_UINT32 packSendBytes; /* Indicates the total sent bytes. */
    FILLP_UINT32 packExpSendBytes; /* Indicates the total sent bytes. */
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd1[4];
#endif
};

#define FILLP_NACK_HISTORY_NUM 10
#define FILLP_NACK_HISTORY_ARR_NUM 2
struct FillpNackHistory {
    FILLP_UINT32 lostPktGap;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
    FILLP_LLONG timestamp;
};

struct FillpNackHistoryStastics {
    struct FillpNackHistory nackHistoryArr[FILLP_NACK_HISTORY_NUM];
    FILLP_UINT32 nackHistoryNum;
    FILLP_UINT16 pktLoss;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd64[2];
#endif
    FILLP_UINT32 historyMinLostPktGap[FILLP_NACK_HISTORY_ARR_NUM]; /* 0: by time, 1: by all the member */
    FILLP_UINT32 historyAvgLostPktGap[FILLP_NACK_HISTORY_ARR_NUM];
    FILLP_UINT32 historyMaxLostPktGap[FILLP_NACK_HISTORY_ARR_NUM];
};

struct FillAppFcStastics {
    FILLP_LLONG periodTimePassed;
    FILLP_LLONG periodRecvBits;
    FILLP_UINT32 pktNum;
    FILLP_UINT32 periodRecvPkts;
    FILLP_UINT32 periodRecvPktLoss;
    FILLP_UINT32 periodRecvRate; /* kbps */
    FILLP_ULLONG periodRecvRateBps; /* bps */
    FILLP_UINT32 periodRtt; /* ms */
    FILLP_UINT32 periodRecvPktLossHighPrecision; /* for example when lost rate is 1.10%, then 110 will returned */
    FILLP_UINT32 periodSendLostPkts;
    FILLP_UINT32 periodSendPkts;
    FILLP_UINT32 periodSendPktLossHighPrecision; /* for example when lost rate is 1.10%, then 110 will returned */
    FILLP_ULLONG periodSendBits;
    FILLP_ULLONG periodSendRateBps; /* bps */
};

/**
 * Provides the pcb statistics.
 */
struct FillpStatisticsPcb {
    struct FillpPackStastics pack; /* Indicates the packet statistics. */
    struct FillpKeepAliveStastics keepAlive; /* Indicates the keep alive statistics. */
    struct FillpStatatisticsDebugPcb debugPcb; /* Indicates the debug pcb statistics. */
    struct FillpStatisticsTraffic traffic; /* Indicates the traffic statistics. */
    struct FillpNackStastics nack; /* Indicates the NACK statistics. */
    struct FillpNackHistoryStastics nackHistory; /* Indicates the NACK history. */
    struct FillAppFcStastics appFcStastics; /* Indicates the app fc statistics. */
};

/**
 * @ingroup fillp_stastics_api
 * @brief   This function is called by the fillp Adapter to get the statistics information for a each type.
 *
 * @param[in]  fd       Indicates the socket index for which stats need to be provided.
 * @param[out] outStats Indicates fillp_statistics_pc, to which statistics are copied.
 * @return  Success: ERR_OK
 * Fail: Error code
 * The following table provides information about the errors set by this API.
 */
extern FILLP_INT DLL_API FtFillpStatsGet(IN FILLP_INT fd, OUT struct FillpStatisticsPcb *outStats);


/**
 * @ingroup fillp_stastics_api
 * @brief    This function is called by the FillP adapter to  to show the statistics information.
 *
 * @param[in] fillpStatsType   Indicates the statistics type.
 * @param[in] fd           Indicates the socket index.
 * @return  On Success : ERR_OK
 * On Failure : Error code
 * The following table provides information about the errors set by this API.
 */
extern FILLP_INT DLL_API FtFillpStatShow(IN FILLP_UINT32 fillpStatsType, IN FILLP_INT fd);


/**
 * @ingroup FillPSocketInterfaces
 * @brief
 * This function gives the error values. If any FillP API fails, then there will be errno set by FillP/VTP.
 * User can retrieve the errno by calling FtGetErrno()
 *
 * @param None
 * @par Error Numbers
 * The following table provides information about the errno set by FillP/VTP.

 * @return  This API does not set any errors.
 */
extern FILLP_INT DLL_API FtGetErrno(void);

/**
 * @ingroup FillP/VTP Stack Interfaces
 * @brief
 * Returns rtt in microseconds which was calculated while setting up the connection
 * for the sockFd socket.
 *
 * @param[in] fd  Indicates the socket index.
 * @return
 * On Success : calculated rtt value as a unsigned long long value
 * On Failure : FILLP_NULL
 * The following table provides information about the errors set by this API.
 */
extern FILLP_ULLONG DLL_API FtGetRtt(FILLP_INT fd);


/**
 * @ingroup fillp_stack_api
 * @brief
 * This function is called to get the current stack time in FillP/VTP.
 *
 * @param[in] instInx  Indicates the instance index to check.
 * @return
 * FILLP_ULLONG - Last time updated of stack.  This API does not set any errors.
 */
extern FILLP_ULLONG DLL_API FtGetStackTime(FILLP_INT instInx);

typedef char *FILLP_CHAR_PTR;
/**
 * @ingroup fillp_stack_api
 * @brief   Gets the FillP version string.
 *
 * @return  FILLP_CHAR* - Version string. User must not free this pointer. This API does not set any errors.
 */
extern FILLP_CHAR_PTR DLL_API FtGetVersion(void);
/**
 * @ingroup fillpconfig
 * @brief  Gets individual FillP stack configuration items.
 *
 * @param[in]   name   Specifies the name of the configuration item to configure (FILLP_CONFIG_LIST enum).
 * @param[out]  value  Contains the value for the configuration item.
 * @param[in]   param  Contains the value for the configuration item, which requires additional information to config.
 * @par The following table provides configuration information:
 * @return
 * ERR_OK on success
 * Error codes on failure.
 * Error reason is returned by the return value.
 */
extern FILLP_INT32 DLL_API FtConfigGet(IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param);
/**
 * @ingroup fillpconfig
 * @brief  Sets individual FillP stack configuration items.
 *
 * @param[in]  name   Indicates the name of the configuration item to configure.
 * @param[in]  value  Contains the value for the configuration item.
 * @param[in]  param  Contains the value for the configuration item, which requires additional information to configure.
 * @par The following table provides configuration information:
 * @return
 * ERR_OK on success
 * Error codes on failure.
 * Error reason is returned by the return value.
 */
extern FILLP_INT32 DLL_API FtConfigSet(IN FILLP_UINT32 name, IN FILLP_CONST void *value,
    IN FILLP_CONST void *param);


struct FillpCurrentSendCacheInf {
    FILLP_UINT32 currentSendCacheSize; /* Indicates the total allocated size of send cache. */
    FILLP_UINT32 currentDataSizeInCache; /* Indicates the size of the pending data to be sent. */
};

/**
 * @ingroup fillpevt
 * @brief  Register the event callback function on the socket.
 *
 * @param[in] fd          Indicates a socket created by the FtSocket API.
 * @param[in] evtCbkFunc  Pointer to event callback function FillpEvtCbkFunc.
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
FILLP_INT DLL_API FtApiRegEventCallbackFunc(IN FILLP_INT fd, IN FillpEvtCbkFunc evtCbkFunc);

/**
 * @ingroup fillpevt
 * @brief  unregister the event callback function on the socket.
 *
 * @param[in] fd          Indicates a socket created by the FtSocket API.
 * @param[in] evtCbkFunc  Pointer to event callback function FillpEvtCbkFunc.
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
FILLP_INT DLL_API FtApiUnregEventCallbackFunc(IN FILLP_INT fd, IN FillpEvtCbkFunc evtCbkFunc);

/**
 * @ingroup fillpevt
 * @brief  Get the event info on the socket.
 *
 * @param[in]     fd    Indicates a socket created by the FtSocket API.
 * @param[in/out] info  Pointer to event callback information FtEventCbkInfo.
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
FILLP_INT DLL_API FtApiEventInfoGet(IN FILLP_INT fd, IO FtEventCbkInfo *info);

/**
 * @ingroup fillpevt
 * @brief  register dfx event callback function
 *
 * @param[in] softObj   any useful message to evtCb
 * @param[in]    func   event callback function
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
extern FILLP_INT DLL_API FtSetDfxEventCb(void *softObj, FillpDfxEventCb evtCb);

/**
 * @ingroup fillpevt
 * @brief   deal with HiDumper cmd
 *
 * @param[in]    argc   arg number
 * @param[in]    argv   arg value
 * @param[in] softObj   any useful message to dump
 * @param[in]    dump   function to printf data
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
extern FILLP_INT DLL_API FtDfxHiDumper(FILLP_UINT32 argc, const FILLP_CHAR **argv,
    void *softObj, FillpDfxDumpFunc dump);

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* _FILLP_API_INC_H_ */

