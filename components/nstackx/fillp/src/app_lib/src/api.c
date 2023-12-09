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

#include "fillpinc.h"
#include "socket_app.h"
#include "socket_opt.h"
#include "spunge.h"
#include "res.h"
#include "callbacks.h"
#include "epoll_app.h"
#include "fillp_dfx.h"
#ifdef __cplusplus
extern "C" {
#endif

/*
Description: Trce callback and trce flag info
Value Range: None
Access: Used to maintain trce callback and trce flag
Remarks:
*/
struct TraceInfo g_traceInfo = {
    FILLP_NULL_PTR,
    FILLP_FALSE,
    {
        /* For padd[3] */
        FILLP_FALSE,
        FILLP_FALSE,
        FILLP_FALSE
    },
#ifdef FILLP_64BIT_ALIGN
    {
        /* For padd1[4] */
        FILLP_FALSE,
        FILLP_FALSE,
        FILLP_FALSE,
        FILLP_FALSE
    }
#endif
};

/**
* @Description: bind to a socket, which is create by FtSocket,
*               the usage is the same with bind function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          name: the SockAddr that need to bind
*          nameLen: length of the SockAddr structure
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtBind(
    FILLP_INT fd,
    FILLP_CONST struct sockaddr *name,
    FILLP_UINT32 nameLen)
{
    return SockBind(fd, name, nameLen);
}

/**
* @Description : creates an endpoint for communication and returns a descriptor,
*                is the same with socket function of linux socket
* @param : NA
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT  DLL_API  FtSocket(
    IN FILLP_INT domain,
    IN FILLP_INT type,
    IN FILLP_INT protocol)
{
    return SockSocket(domain, type, protocol);
}

/**
* @Description : initiate a connection on a socket, is the same with connect function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          name: the SockAddr that need to connect
*          nameLen: length of the SockAddr structure
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API  FtConnect(
    FILLP_INT fd,
    FILLP_CONST FILLP_SOCKADDR *name,
    socklen_t nameLen)
{
#ifdef FILLP_SUPPORT_SERVER_ONLY
    FILLP_LOGERR("FILLP_SUPPORT_SERVER_ONLY Macro is enabled. i.e. Client Functionality "
                 "not supported. but still invoking FtConnect!!! Index: %d", fd);

    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(name);
    FILLP_UNUSED_PARA(nameLen);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
#else
    return SockConnect(fd, name, nameLen);

#endif
}

FILLP_ULLONG DLL_API FtGetRtt(FILLP_INT fd)
{
    return SockGetRtt(fd);
}

/**
* @Description : receive messages from a socket, is the same with recv function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          mem: Points to the buffer where the message should be stored
*          len: Specifies the length in bytes of the buffer pointed to by the mem argument
*          flag: Indicates the status
* @return : success: Number of bytes received  fail: error code
*/
FILLP_INT DLL_API FtRecv(FILLP_INT fd, void *mem, size_t len, FILLP_INT flag)
{
    return SockRecv(fd, mem, len, flag);
}

/**
* @Description : send a message on a socket, is the same with send function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          data: Points to the buffer where the message should be stored
*          size: Specifies the length in bytes of the buffer pointed to by the data argument
*          flag: Indicates the status
* @return : success: Number of bytes sent fail: error code
*/
FILLP_INT DLL_API FtSend(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag)
{
    return SockSend(fd, data, size, flag);
}

/**
* @Description : send a video/audio frame on a socket. All the arguments is same with FtSend except
*                the argument 'frame'
* @param : fd: a socket, which is create by FtSocket
*          data: Points to the buffer where the message should be stored
*          size: Specifies the length in bytes of the buffer pointed to by the data argument
*          flag: Indicates the status
*          frame: Specifies the frame information of the frame
* @return : success: Number of bytes sent, fail: error code
*/
FILLP_INT DLL_API FtSendFrame(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag,
    FILLP_CONST struct FrameInfo *frame)
{
    if (frame != FILLP_NULL_PTR) {
        FILLP_LOGDTL("get frame, type: %d, size: %u, seq: %d, sub seq: %d, level: %d, bitmap: 0x%x",
            frame->frameType, (FILLP_UINT32)size, frame->seqNum, frame->subSeqNum, frame->level, frame->bitMap);
    }

    return SockSendFrame(fd, data, size, flag, frame);
}

#if defined(FILLP_LINUX) && defined(FILLP_MMSG_SUPPORT)
/**
* @Description : send messages on a socket
* @param : fd: a socket, which is create by FtSocket
*          iov: A pointer which points to an array of iovec structures.
*          iovCount: buffer count of data described by iov.
* @return : These calls return the number of bytes written, or -1 if an error occurred.
*           In the event of an error, errno is set to indicate the error
*/
FILLP_INT DLL_API FtWritev(FILLP_INT fd, const struct iovec *iov, FILLP_INT iovCount)
{
    return SockWritev(fd, iov, iovCount);
}

/**
* @Description : receive messages on a socket
* @param : fd: a socket, which is create by FtSocket
*          iov: A pointer which points to an array of iovec structures.
*          iovCount: buffer count of data described by iov.
* @return : These calls return the number of bytes read, or -1 if an error occurred.
*           In the event of an error, errno is set to indicate the error
*/
FILLP_INT DLL_API FtReadv(FILLP_INT fd, const struct iovec *iov, FILLP_INT iovCount)
{
    return SockReadv(fd, iov, iovCount);
}

#endif
/**
* @Description : Closes the Socket connection and releases all associated resources,
*                is the same with close function of linux socket

* @param : fd: a socket, which is create by FtSocket
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtClose(FILLP_INT fd)
{
    return SockClose(fd);
}

/**
* @Description : initiates the graceful Closure of the Socket connection from initiating side (uni-directional).
*                the local user can still recv data from peer.
* @param : fd: a socket, which is create by FtSocket
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtShutDown(FILLP_INT fd, FILLP_INT how)
{
    return SockShutdown(fd, how);
}

/**
* @Description : accept a connection on a socket, is the same with accept function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          addr: pointer to a SockAddr structure that filled in with the address of the peer socket
*          addrlen: length of the SockAddr structure
* @return : success: a descriptor for the accepted socket  fail: -1
*/
FILLP_INT DLL_API FtAccept(FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen)
{
#ifdef FILLP_SERVER_SUPPORT
    return SockAccept(fd, addr, addrLen);
#else
    FILLP_LOGERR("FILLP_SERVER_SUPPORT Macro is not enabled. i.e. Server Functionality "
                 "not supported. but still invoking FtAccept!!! Index: %d", fd);

    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(addr);
    FILLP_UNUSED_PARA(addrLen);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;

#endif
}

/**
* @Description : listen for connections on a socket, is the same with listen function of linux socket
* @param : fd: a socket, which is create by FtSocket
*          backLog: defines the maximum length to which the queue of pending connections for fd, may grow
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtListen(FILLP_INT fd, FILLP_INT backLog)
{
#ifdef FILLP_SERVER_SUPPORT
    return SockListen(fd, backLog);
#else
    FILLP_LOGERR("FILLP_SERVER_SUPPORT Macro is not enabled. i.e. Server Functionality "
                 "not supported. but still invoking FtListen!!! Index: %d", s);

    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(backLog);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
#endif
}

/*******************************************************************
  Function      : FtEpollCreate
  Description   : This API is used to open an epoll file descriptor.

  Return        : Index to the list of FtSocket : On success.
                      Error code : On failure.
********************************************************************/
FILLP_INT DLL_API FtEpollCreate(void)
{
    return SpungeEpollCreate();
}

/*******************************************************************
  Function      : FtEpollCreate
  Description   : This API is used to open an epoll file descriptor.
  Return        : Index to the list of FtSocket : On success.
                      Error code : On failure.
********************************************************************/
FILLP_INT DLL_API FtEpollCreateLinux(FILLP_INT epNum)
{
    if (epNum <= 0) {
        FILLP_LOGERR("Error number");
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    return FtEpollCreate();
}

/*******************************************************************
  Function      : FtEpollCtl
  Description   : This API indicates control interface for epoll file descriptor.

  Return        : FILLP_OK on success.
                      Error code on failure.
********************************************************************/
FILLP_INT DLL_API FtEpollCtl(FILLP_INT epFd, FILLP_INT op, FILLP_INT fd, FILLP_CONST struct SpungeEpollEvent *event)
{
    return SpungeEpollCtl(epFd, op, fd, event);
}

FILLP_INT DLL_API FtEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents, FILLP_INT timeout)
{
    return SpungeEpollWait(epFd, events, maxEvents, timeout);
}

/*******************************************************************
  Function      : FtFcntl
  Description   : This function used to manipulate file descriptor.
  Return        : Value returned depends on cmd upon success.
                      Error code on failure.
********************************************************************/
FILLP_INT DLL_API FtFcntl(FILLP_INT fd, FILLP_INT cmd, FILLP_INT val)
{
#ifdef FILLP_LINUX
    return SockFcntl(fd, cmd, val);
#else
    FILLP_LOGERR("FILLP_LINUX Macro is not enabled. i.e. fcntl Functionality "
                 "not supported in OS other than Linux. but still invoked , index : %d", fd);

    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(cmd);
    FILLP_UNUSED_PARA(val);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
#endif
}

/*******************************************************************
  Function      : FtIoctl
  Description   : This function controls the I/O mode of a socket.
  Return        : FILLP_OK on success.
                      Error code on failure.
********************************************************************/
FILLP_INT DLL_API FtIoctl(FILLP_INT fd, FILLP_ULONG cmd, FILLP_CONST FILLP_INT *val)
{
#ifdef FILLP_LINUX
    return SockIoctlsocket(fd, (FILLP_SLONG)cmd, val);
#else
    FILLP_LOGERR("FILLP_LINUX Macro is not enabled. i.e. fcntl Functionality "
                 "not supported in OS other than Linux. but still invoked , index : %d", fd);
    FILLP_UNUSED_PARA(cmd);
    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(val);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
#endif
}

FILLP_INT32 FtInnerStartTrace(
    IN FILLP_UINT8 traceObjType,         /* FILLP_TRACE_OBJ_TYPE_ENUM */
    IN FILLP_CONST void *traceHandle,    /* Handle to be Stored in the FtSocket */
    IO FILLP_UINT8 *sockTraceFlag,       /* FtSocket's traceFlag */
    OUT void **sockTraceHandle)          /* FtSocket's traceHandle */
{
    switch (traceObjType) {
        case FILLP_TRACE_DIRECT_USER:
            if ((*sockTraceFlag == FILLP_TRACE_DIRECT_NETWORK) ||
                (*sockTraceFlag == FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE)) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE;
            } else {
                *sockTraceFlag = FILLP_TRACE_DIRECT_USER;
            }

            g_traceInfo.cmdTraceFlag = FILLP_TRUE;
            *sockTraceHandle = (void *)traceHandle;
            break;

        case FILLP_TRACE_DIRECT_NETWORK:
            if ((*sockTraceFlag == FILLP_TRACE_DIRECT_USER) ||
                (*sockTraceFlag == FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE)) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE;
            } else {
                *sockTraceFlag = FILLP_TRACE_DIRECT_NETWORK;
            }
            *sockTraceHandle = (void *)traceHandle;
            break;

        case FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE:
            *sockTraceFlag = FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE;
            *sockTraceHandle = (void *)traceHandle;
            g_traceInfo.cmdTraceFlag = FILLP_TRUE;
            break;

        default: /* Unknown trc object type */
            FILLP_LOGERR("Unknown trc object type (%u) received", traceObjType);
            SET_ERRNO(FILLP_EINVAL);
            return ERR_TRACE_OBJ_TYPE_INVALID;
    }

    return FILLP_OK;
}

FILLP_INT32 FtInnerStopTrace(
    IN FILLP_UINT8 traceObjType,         /* Type */
    IO FILLP_UINT8 *sockTraceFlag,       /* FtSocket's traceFlag */
    OUT void **sockTraceHandle)          /* FtSocket's traceHandle */
{
    switch (traceObjType) {
        case FILLP_TRACE_DIRECT_USER:
            if (*sockTraceFlag == FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_NETWORK;
            } else if (*sockTraceFlag == FILLP_TRACE_DIRECT_USER) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_DISABLE;
                *sockTraceHandle = FILLP_NULL_PTR;
            }

            g_traceInfo.cmdTraceFlag = FILLP_FALSE;
            break;

        case FILLP_TRACE_DIRECT_NETWORK:
            if (*sockTraceFlag == FILLP_TRACE_DIRECT_USER_NETWORK_ENABLE) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_USER;
            } else if (*sockTraceFlag == FILLP_TRACE_DIRECT_NETWORK) {
                *sockTraceFlag = FILLP_TRACE_DIRECT_DISABLE;
                *sockTraceHandle = FILLP_NULL_PTR;
            }
            break;

        case FILLP_TRACE_DIRECT_DISABLE:
            *sockTraceFlag = FILLP_TRACE_DIRECT_DISABLE;
            *sockTraceHandle = FILLP_NULL_PTR;
            g_traceInfo.cmdTraceFlag = FILLP_FALSE;
            break;

        default: /* Unknown trc object type */
            FILLP_LOGERR("Unknown trc object type (%u) received", traceObjType);
            return ERR_TRACE_OBJ_TYPE_INVALID;
    }

    return FILLP_OK;
}

static FILLP_INT32 FtStartStopTraceSock(IN struct FtSocket *sockft, IN FILLP_UINT8 traceObjType,
    IN FILLP_INT traceObj, IN FILLP_CONST void *traceHandle, FILLP_BOOL isStart)
{
    FILLP_INT32 ret;
    if (SYS_ARCH_RWSEM_TRYRDWAIT(&sockft->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("Socket-%d state is changing,maybe closing", sockft->index);
        /* Socket state is changing, continue try read wait again */
        if (traceObj != FILLP_CONFIG_ALL_SOCKET) {
            return ERR_FT_SOCKET_INVALID;
        }
        return ERR_OK;
    }

    if ((sockft->allocState == SOCK_ALLOC_STATE_FREE) || (sockft->allocState == SOCK_ALLOC_STATE_ERR)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sockft->sockConnSem);
        if (traceObj != FILLP_CONFIG_ALL_SOCKET) {
            FILLP_LOGERR("Socket is not in use, fillp_sock_id:%d", sockft->index);
            return ERR_FT_SOCKET_INVALID;
        }
        return ERR_OK;
    }

    ret = (isStart == FILLP_TRUE) ?
        FtInnerStartTrace(traceObjType, traceHandle, &sockft->traceFlag, &sockft->traceHandle) :
        FtInnerStopTrace(traceObjType, &sockft->traceFlag, &sockft->traceHandle);

    (void)SYS_ARCH_RWSEM_RDPOST(&sockft->sockConnSem);
    return ret;
}

FILLP_INT32 FtStartStopTrace(IN FILLP_UINT8 traceObjType, IN FILLP_INT traceObj,
                             IN FILLP_CONST void *traceHandle, FILLP_BOOL isStart)
{
    /* If Trance Obj is INVALID_INT, means need to set to all socket */
    FILLP_INT sockIndex = (traceObj != FILLP_CONFIG_ALL_SOCKET) ? traceObj : 0;
    FILLP_INT32 ret;
    struct FtSocket *sockft = FILLP_NULL_PTR;

    /* Check the state of stack */
    if ((g_spunge == FILLP_NULL_PTR) || (g_spunge->hasInited == FILLP_FALSE)) {
        FILLP_LOGERR("Stack is not in ACTIVE state");
        return ERR_STACK_NOT_INITED;
    }

    FILLP_LOGINF("Trace type:%u, traceObj:%d, isStart:%u", traceObjType, traceObj, isStart);
    if (traceObj == FILLP_CONFIG_ALL_SOCKET) {
        ret = (isStart == FILLP_TRUE) ?
            FtInnerStartTrace(traceObjType, traceHandle, &g_spunge->traceFlag, &g_spunge->traceHandle) :
            FtInnerStopTrace(traceObjType, &g_spunge->traceFlag, &g_spunge->traceHandle);
        if (ret != FILLP_OK) {
            FILLP_LOGERR("Start/Stop Trace fail ret %d", ret);
            return ret;
        }
    }

    if (SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used) <= 0) {
        FILLP_LOGINF("No Socket is created");
        return FILLP_OK;
    }

    do {
        sockft = SockGetSocket(sockIndex);
        if (sockft == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            return ERR_FT_SOCKET_INVALID;
        }
        sockIndex++;

        if ((sockft->allocState == SOCK_ALLOC_STATE_FREE) || (sockft->allocState == SOCK_ALLOC_STATE_ERR)) {
            if (traceObj != FILLP_CONFIG_ALL_SOCKET) {
                FILLP_LOGERR("Socket is not in use, fillp_sock_id:%d", sockft->index);
                return ERR_FT_SOCKET_INVALID;
            }
            continue;
        }

        ret = FtStartStopTraceSock(sockft, traceObjType, traceObj, traceHandle, isStart);
        if (ret != ERR_OK) {
            FILLP_LOGINF("Start/Stop Trace fail fillp_sock_id:%d", sockft->index);
            return ret;
        }
    } while ((traceObj == FILLP_CONFIG_ALL_SOCKET) && (sockIndex < SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used)));

    return FILLP_OK;
}

/*******************************************************************************
    Function    : FtStartTrace

    Description : This function is called by the FILLP Adapter to start the indication of
                  user apis and/network messages for a particular socket.

    Input       : traceObjType - Indication object as defined in FILLP_TRACE_OBJ_TYPE_ENUM.
                          and tell what kind indication should be done.
                  traceObj    - user should pass the FtSocket identification.
                          to set the indication for that particular socket.
                          (0xFFFFFFFF - means for all the sockets)
                  traceHandle  - traceHandle which will be transparently
                          passed to user while giving indication. 0xFFFFFFFF is the invalid handle.

    Output      : None

    Return      : FILLP_SUCCESS - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT32 FtStartTrace(
    IN FILLP_UINT8 traceObjType,        /* Type */
    IN FILLP_INT traceObj,             /* FtSocket index */
    IN FILLP_CONST void *traceHandle)    /* Handle to be Stored in the FtSocket */
{
    return FtStartStopTrace(traceObjType, traceObj, traceHandle, FILLP_TRUE);
}

/*******************************************************************************
    Function    : FtStopTrace

    Description : This function is called by the FILLP Adapter to stop the indication
                  for a particular socket.

    Input       : traceObjType - indication object as defined in FILLP_TRACE_OBJ_TYPE_ENUM.
                          and tell what kind indication should be done.
                  traceObj    - For a particular socket or for all the association(0xFFFFFFFF)

    Output      : None

    Return      : FILLP_SUCCESS - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT32 FtStopTrace(
    IN FILLP_UINT8 traceObjType,   /* Type */
    IN FILLP_INT traceObj)        /* Socket index */
{
    return FtStartStopTrace(traceObjType, traceObj, FILLP_NULL_PTR, FILLP_FALSE);
}

/*******************************************************************************
    Function    : FtRegTraceCallbackFn

    Description : This function is to register trce/ callback function for Fillp message trce and Fillp command Trce.

    Input       : traceFuncCallback -> Trce callback

    Output      : None

    Return      : FILLP_SUCCESS - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT32 FtRegTraceCallbackFn(IN FILLP_CONST FillpTraceSend traceFuncCallback)
{
    if (traceFuncCallback == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    g_traceInfo.fillpTraceSend = traceFuncCallback;
    return FILLP_OK;
}

/*******************************************************************************
    Function    : FillpDebugCmdHelp

    Description : This function will be invoked by the Adapter to print debg/
                    related help information.

    Input       : None

    Output      : None

    Return      : None
*******************************************************************************/
static void FillpDebugCmdHelp(void)
{
    /* Invoke LM macro to dbg output the help info with type  */
    FILLP_HELPBUTT("The Dbg Command Usage are as follows");

    FILLP_HELPBUTT("FILLP_DBGCMD_HELP(%d) - To show the dbg command help", FILLP_DBGCMD_HELP);

    FILLP_HELPBUTT("FILLP_DBGCMD_SET_PRINT_LEVEL(%d) - To set the dbg print level", FILLP_DBGCMD_SET_PRINT_LEVEL);

    FILLP_HELPBUTT("FILLP_DBGCMD_SHOW_PRINT_LEVEL(%d) - To show the current dbg level", FILLP_DBGCMD_SHOW_PRINT_LEVEL);

    FILLP_HELPBUTT("FILLP_DBGCMD_SHOW_SOCKET_INFO(%d) - To show important data of a particular socket",
                   FILLP_DBGCMD_SHOW_SOCKET_INFO);

    FILLP_HELPBUTT("FILLP_DBGCMD_SHOW_INIT_RESOURCE(%d) - To show the initialisation parameters",
                   FILLP_DBGCMD_SHOW_INIT_RESOURCE);

    FILLP_HELPBUTT("FILLP_DBGCMD_SHOW_GLOBAL_CONFIG_RESOURCE(%d) - Show all the GLOBAL configuration"
                   "parametrs of FillP STACK",
                   FILLP_DBGCMD_SHOW_GLOBAL_CONFIG_RESOURCE);

    FILLP_HELPBUTT("FILLP_DBGCMD_SHOW_SOCKET_CONFIG_RESOURCE(%d) - Show all the Socket level configuration parametrs"
                   " of FillP STACK (socket index 0xFFFF will display config common to all sockets)",
                   FILLP_DBGCMD_SHOW_SOCKET_CONFIG_RESOURCE);

    return;
}

/*******************************************************************************
    Function    : FillpDebugCmdGlobalConfigRes

    Description : This function will be invoked by the Adapter to print debg/
                    information related global stack config.

    Input       : None

    Output      : None

    Return      : None
*******************************************************************************/
static void FillpDebugCmdGlobalConfigRes(void)
{
    FILLP_SHOWDATABUTT("\r ------- FOLLOWING ARE FillP GLOBAL (STACK) level configuration parameters -------");

    FILLP_SHOWDATABUTT("FillP max UDP RX burst number is (FT_CONF_RX_BURST) = %u", g_resource.udp.rxBurst);

    FILLP_SHOWDATABUTT("FillP max socket number is (FT_CONF_MAX_SOCK_NUM) = %u", g_resource.common.maxSockNum);

    FILLP_SHOWDATABUTT("FillP Max Connection number is (FT_CONF_MAX_CONNECTION_NUM) =%u ",
                       g_resource.common.maxConnNum);

    FILLP_SHOWDATABUTT("FillP max Instance number is  = %u", g_resource.common.maxInstNum);

    FILLP_SHOWDATABUTT("FillP max receive cache packet number buffer size is"
                       "(FT_CONF_RECV_CACHE_PKT_NUM_BUFF_SIZE) = %u",
                       g_resource.common.recvCachePktNumBufferSize);

    FILLP_SHOWDATABUTT("FillP avoid core thread when CPU full is (FT_CONF_FULL_CPU) = %u",
                       g_resource.common.fullCpuEnable);

    FILLP_SHOWDATABUTT("FillP data message cache feature status is (FT_CONF_OUT_OF_ORDER_CATCHE_FEATURE) = %u",
                       g_resource.common.outOfOrderCacheEnable);

    FILLP_SHOWDATABUTT("FillP Flow control : Opposite set percentage (FT_CONF_OPPOSITE_SET_PERCENTAGE) = %u",
                       g_resource.flowControl.oppositeSetPercentage);

    FILLP_SHOWDATABUTT("FillP Flow control : MAX Rate percentage (FT_CONF_MAX_RATE_PERCENTAGE) = %u",
                       g_resource.flowControl.maxRatePercentage);

    FILLP_SHOWDATABUTT("FillP Flow control : NACK repeat times (FT_CONF_NACK_REPEAT_TIMES) = %u",
                       g_resource.flowControl.nackRepeatTimes);

    FILLP_SHOWDATABUTT("FillP Flow control : Packet loss allowed(FT_CONF_PACKET_LOSS_ALLOWED) = %u",
                       g_resource.flowControl.pktLossAllow);

    FILLP_SHOWDATABUTT("FillP Flow control : Support Rate Detection(FILLP_STACK_SUPPORT_RATE_DETECTIVE)"
                      " = NOT supported");

    FILLP_SHOWDATABUTT("FillP Flow control : Support Fairness (FT_CONF_SUPPORT_FAIRNESS) = %u",
                       g_resource.flowControl.supportFairness);

    FILLP_SHOWDATABUTT("FillP Flow control Fair Bandwidth support: Stack Send rate (FT_CONF_CORE_MAX_RATE) = %u Kbps",
                       g_resource.flowControl.maxRate);

    FILLP_SHOWDATABUTT("FillP Flow control Fair Bandwidth support: Stack Receive rate "
                       "(FT_CONF_CORE_MAX_RECV_RATE) = %u Kbps",
                       g_resource.flowControl.maxRecvRate);

    FILLP_SHOWDATABUTT("FillP Flow control : Stack Initial rate (FT_CONF_INITIAL_RATE) = %u Kbps",
                       g_resource.flowControl.initialRate);

    FILLP_SHOWDATABUTT("Timer Config : Data cache flush timer (FT_CONF_TIMER_RECV_CACHE_PKT_NUMBUFF) = %u",
                       g_resource.common.recvCachePktNumBufferTimeout);

    FILLP_SHOWDATABUTT("------- END OF FillP GLOBAL (STACK) level configuration parameters -------");

    return;
}

/*******************************************************************************
    Function    : FillpDebugCmdSetPrintLevel

    Description : This function will be invoked by the fillp debg/ function to
                set the print level

    Input       : content  : print level to set.

    Output      : None

    Return      : None
*******************************************************************************/
void FillpDebugCmdSetPrintLevel(FILLP_CONST void  *content)
{
    FILLP_UINT8 temp;
    if (content == FILLP_NULL_PTR) {
        FILLP_LOGERR("Input pointer is NULL");

        return;
    }

    temp = *((FILLP_UINT8 *)content);

    /* validate the dbg level in pucContent */
    if ((temp > FILLP_DBG_LVL_ERROR) || (temp < FILLP_DBG_LVL_DEBUG)) {
        FILLP_LOGERR("Dbg Level %u is not supported", temp);

        return;
    }
    g_fillpLmGlobal.debugLevel = temp;
}

/*******************************************************************************
    Function    : FillpDebugSocketConfigRes

    Description : This function will be invoked by the Adapter to print debg/
                    information related socket level stack config.

    Input       : resource : config resource structure to print info

    Output      : None

    Return      : None
*******************************************************************************/
void FillpDebugSocketConfigRes(FILLP_CONST struct GlobalAppResource *resource)
{
    FILLP_SHOWDATABUTT("\r FillP max UDP TX burst number is (FT_CONF_TX_BURST) = %u", resource->udp.txBurst);

    FILLP_SHOWDATABUTT("FillP keep alive timeout is (FT_CONF_TIMER_KEEP_ALIVE) = %u", resource->common.keepAliveTime);

    FILLP_SHOWDATABUTT("FillP max server allow send cache is (FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE) = %u",
                       resource->common.maxServerAllowSendCache);

    FILLP_SHOWDATABUTT("FillP max server allow receive cache is (FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE) = %u",
                       resource->common.maxServerAllowRecvCache);

    FILLP_SHOWDATABUTT("FillP max send cache is (FT_CONF_SEND_CACHE) = %u", resource->common.sendCache);

    FILLP_SHOWDATABUTT("FillP max receive cache is (FT_CONF_RECV_CACHE) = %u", resource->common.recvCache);

    FILLP_SHOWDATABUTT("FillP max send buffer size is (FILLP_STACK_UDP_SEND_BUFFER_SIZE) = %u",
                       resource->common.udpSendBufSize);

    FILLP_SHOWDATABUTT("FillP enableNackDelay flag is (FT_CONF_ENABLE_NACK_DELAY) = %u",
                       resource->common.enableNackDelay);

    FILLP_SHOWDATABUTT("FillP nackDelayTimeout is (FT_CONF_NACK_DELAY_TIMEOUT) = %lld",
                       resource->common.nackDelayTimeout);

    FILLP_SHOWDATABUTT("FillP EnlargePaxkInterval is (FT_CONF_ENLARGE_PACK_INTERVAL) = %u",
                       resource->common.enlargePackIntervalFlag);

    FILLP_SHOWDATABUTT("FillP max receive buffer size is (FT_CONF_RECV_BUFFER_SIZE) = %u",
                       resource->common.recvBufSize);

    FILLP_SHOWDATABUTT("FillP Flow control : Opposite set rate(FT_CONF_OPPOSITE_SET_RATE) = %u",
                       resource->flowControl.oppositeSetRate);

    FILLP_SHOWDATABUTT("FillP Flow control : Use Const Stack Send rate (FT_CONF_CONST_RATE) = %u",
                       resource->flowControl.constRateEnbale);

    FILLP_SHOWDATABUTT("FillP Flow control : maxRate(FT_CONF_MAX_RATE) = %u Kbps",
                       resource->flowControl.maxRate);

    FILLP_SHOWDATABUTT("FillP Flow control : maxRecvRate(FT_CONF_MAX_RECV_RATE) = %u Kbps",
                       resource->flowControl.maxRecvRate);

    FILLP_SHOWDATABUTT("FillP Flow control : packet size (FT_CONF_PACKET_SIZE) = %u", resource->flowControl.pktSize);

    FILLP_SHOWDATABUTT("FillP Flow control : Slow start (FT_CONF_SLOW_START) = %u", resource->flowControl.slowStart);

    FILLP_SHOWDATABUTT("Timer Config : Connection Timer (FT_CONF_TIMER_CONNECT) = %u", resource->common.connectTimeout);

    FILLP_SHOWDATABUTT("Timer Config : Connection retry Timer (FT_CONF_TIMER_CONNECTION_RETRY) = %u",
                       resource->common.connRetryTimeout);

    FILLP_SHOWDATABUTT("Timer Config : Disconnect retry Timer (FT_CONF_TIMER_DISCONNECT_RETRY_TIMEOUT) = %u",
                       resource->common.disconnectRetryTimeout);

    FILLP_SHOWDATABUTT("Timer Config : Keep alive Timer (FT_CONF_TIMER_KEEP_ALIVE) = %u",
                       resource->common.keepAliveTime);

    FILLP_SHOWDATABUTT("------- End OF FillP APP Config Resource Data -------");
}

/*******************************************************************************
    Function    : FillpDebugCmdSocketConfigRes

    Description : This function will be invoked by the Adapter to print debg/
                    information related socket level stack config.

    Input       : void  *content  : socket id for which information needs
                to be printed. 0xffff will print global resource.

    Output      : None

    Return      : None
*******************************************************************************/
void FillpDebugCmdSocketConfigRes(FILLP_CONST void  *content)
{
    struct GlobalAppResource *resource = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT sockIndex;

    if (content == FILLP_NULL_PTR) {
        FILLP_LOGERR("Input pointer is NULL");
        return;
    }

    sockIndex = *((FILLP_INT *)content);

    if ((sockIndex != FILLP_CONFIG_ALL_SOCKET) &&
        ((g_spunge == FILLP_NULL_PTR) || (g_spunge->hasInited == FILLP_FALSE))) {
        FILLP_LOGERR("Cannot set Socket level config value before stack initialization!!!");
        return;
    }

    if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            SET_ERRNO(FILLP_EBADF);
            return;
        }

        /* All configuration changes are not write protected, so other thread can read old value when this
        function is getting executed. but this is ok as per fillp design. */
        if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
            FILLP_LOGERR("Socket-%d state is changing,maybe closing", sockIndex);
            SET_ERRNO(FILLP_EBUSY);
            return;
        }

        if ((sock->allocState == SOCK_ALLOC_STATE_FREE) || (sock->allocState == SOCK_ALLOC_STATE_ERR)) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            FILLP_LOGERR("Invalid fillp_sock_id:%d \r", sockIndex);
            return;
        }

        resource = &sock->resConf;

        FILLP_SHOWDATABUTT("------- FOLLOWING ARE FillP Config Resource Data For Socket %d -------", sockIndex);

        FillpDebugSocketConfigRes(resource);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    } else {
        resource = &g_appResource;

        FILLP_SHOWDATABUTT("------- FOLLOWING ARE FillP Config Resource Common At FILLP level-------");
        FillpDebugSocketConfigRes(resource);
    }

    return;
}

/*******************************************************************************
    Function    : FillpDebugCmdShowInitRes

    Description : This function will be invoked by the Adapter to print debg/
                    information related stack initialization.

    Input       : None

    Output      : None

    Return      : None
*******************************************************************************/
static void FillpDebugCmdShowInitRes(void)
{
    FILLP_SHOWDATABUTT("------- FOLLOWING ARE FillP Init Resource Data -------");

    FILLP_SHOWDATABUTT("FillP max socket number is (FT_CONF_MAX_SOCK_NUM) = %u", g_resource.common.maxSockNum);

    FILLP_SHOWDATABUTT("FillP max Connection number is (FT_CONF_MAX_CONNECTION_NUM) = %u",
                       g_resource.common.maxConnNum);

    FILLP_SHOWDATABUTT("FillP max Instance number is = %u", g_resource.common.maxInstNum);

    FILLP_SHOWDATABUTT("------- End OF FillP Init Resource Data -------");

    return;
}
/*******************************************************************************
    Function    : FillpDebugControl

    Description : This function will be invoked by the Adapter to control the
                  output of the maintenance information.

    Input       :
                  ucCommand  -  The debugging command
                  pContent -  parameter of debugging command, this will be
                                NULL depending upon the command type

    Output      : None

    Return      : None
*******************************************************************************/
void FillpDebugControl(
    IN FILLP_UINT8  ucCommand, /* FillpDebugCmdEn */
    IN FILLP_CONST void *pContent)
{
    switch (ucCommand) {
        case FILLP_DBGCMD_HELP:
            FillpDebugCmdHelp();
            break;

        case FILLP_DBGCMD_SHOW_GLOBAL_CONFIG_RESOURCE:
            FillpDebugCmdGlobalConfigRes();
            break;

        case FILLP_DBGCMD_SHOW_SOCKET_CONFIG_RESOURCE:

            FillpDebugCmdSocketConfigRes(pContent);

            break;
        case FILLP_DBGCMD_SET_PRINT_LEVEL:

            FillpDebugCmdSetPrintLevel(pContent);
            break;

        case FILLP_DBGCMD_SHOW_PRINT_LEVEL:

            FILLP_SHOWLEVELBUTT("Current dbg level : %u", g_fillpLmGlobal.debugLevel);
            break;

        case FILLP_DBGCMD_SHOW_INIT_RESOURCE: /* Show all the INIT configuration of STACK */

            FillpDebugCmdShowInitRes();
            break;

        case FILLP_DBGCMD_SHOW_SOCKET_INFO: /* SHOW all the information about the FILLP socket/connection */

            FILLP_SHOWDATABUTT("Operation Not Supported ");

            break;

        default:

            FILLP_LOGERR("Unknown dbg command (%u) received", ucCommand);
            break;
    }

    return;
}

/*******************************************************************************
    Function    : FillpRegLMCallbackFn

    Description : This function is called by the Fillp Adapter to register the
                  Adapter's callback function for LM functionality.
                  If A function Pointer is passed as NULL, then it is omitted
                  to Copy. So User/Adapter can call this function to Register
                  the function pointers separately also.

    Input       :
                  lmFuncCallback - Pointer to LM callback function struct

    Output      : None

    Return      : ERR_OK - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT32 FillpRegLMCallbackFn(IN FILLP_CONST FillpLmCallbackFunc *lmFuncCallback)
{
    if ((lmFuncCallback == FILLP_NULL_PTR) || (lmFuncCallback->debugCallbackFunc == FILLP_NULL_PTR)) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    g_fillpLmGlobal.lmCallbackFn.debugCallbackFunc = lmFuncCallback->debugCallbackFunc;

    return ERR_OK;
}

/**
* @Description : This function is called by the Fillp Adapter to get the
                address which the requested socket bound to.
* @param : fd: a socket, which is create by FtSocket
*          name: the SockAddr that need to connect
*          namelen: length of the SockAddr structure
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtGetSockName(
    FILLP_INT fd,
    FILLP_SOCKADDR *name,
    socklen_t *namelen)
{
    return SockGetsockname(fd, name, namelen);
}

/**
* @Description : This function is called by the Fillp Adapter to get the
                peer address to which the requested socket is connected.
* @param : fd: a socket, which is create by FtSocket
*          name: the SockAddr
*          nameLen: length of the SockAddr structure
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtGetPeerName(
    FILLP_INT fd,
    FILLP_SOCKADDR *name,
    socklen_t *nameLen)
{
    return SockGetpeername(fd, name, nameLen);
}

/**
* @Description : This function is called by the Fillp Adapter to get system
*                socket parameters.
* @note: All parameters are passed uninterpreted to system interface, for RAW socket it always return failure

* @param : fd: a socket, which is create by FtSocket
*          level: When manipulating socket options, the level at which the option resides and the name of
*                 the option must be specified.
*          optName: Optname options are passed uninterpreted to system interface.
*          optVal: value is accessed by underlying system
*          optLen: value is accessed by underlying system
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtGetSockOpt(
    FILLP_INT           fd,
    FILLP_INT           level,
    FILLP_INT           optName,
    void               *optVal,
    FILLP_INT          *optLen)
{
    return SockGetSockOpt(fd, level, optName, optVal, optLen);
}

/**
* @Description : This function is called by the Fillp Adapter to set system
*                socket parameters.
* @note: All parameters are passed uninterpreted to system interface, for RAW socket it always return failure
*
* @param : fd: a socket, which is create by FtSocket
*          level: When manipulating socket options, the level at which the option resides and the name of
*                 the option must be specified.
*          optName: Optname options are passed uninterpreted to system interface.
*          optVal: value is accessed by underlying system
*          optLen: value is accessed by underlying system
* @return : success: ERR_OK  fail: error code
*/
FILLP_INT DLL_API FtSetSockOpt(
    FILLP_INT           fd,
    FILLP_INT           level,
    FILLP_INT           optName,
    FILLP_CONST void   *optVal,
    socklen_t           optLen)
{
    return SockSetSockOpt(fd, level, optName, optVal, optLen);
}

/*******************************************************************
  Function      : FtIoctlSocket
  Description   : This function controls the I/O mode of a socket.
  Return        : FILLP_OK on success.
                      Error code on failure.
********************************************************************/
FILLP_INT DLL_API FtIoctlSocket(FILLP_INT fd, FILLP_SLONG cmd, FILLP_CONST FILLP_INT *val)
{
#if defined(_WINDOWS) || defined(FILLP_WIN32)
    return SockIoctlsocket(fd, cmd, val);
#else
    FILLP_LOGERR("FILLP_WIN32 or _WINDOWS Macro is not enabled. i.e. ioctlsocket Functionality "
                 "not supported in OS other than windows. but still invoked , socket index : %d", fd);
    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(cmd);
    FILLP_UNUSED_PARA(val);
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
#endif
}


/*******************************************************************************
    Function    : FtFillpStatsGet

    Description : This function is called by the fillp Adapter to get the
                  statistics information for a each type.

    Input       : fd - socket index for which stats need to be provided
                  OutStats - fillp_statistics_pc, to which statistics will be copied.
                  user has to provide and free the buffer.
    Output      : pucStatsData - stats Data

    Return      : FILLP_SUCCESS - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT FtFillpStatsGet(
    IN FILLP_INT fd,
    OUT struct FillpStatisticsPcb *outStats)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    if (outStats == FILLP_NULL_PTR) {
        FILLP_LOGERR(" error: out parameter is NULLPTR");
        return ERR_NULLPTR;
    }

    sock = SockGetSocket(fd);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Invalid fillp_sock_id:%d", fd);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    /* All configuration changes are not write protected, so other thread can read old value when this
            function is getting executed. but this is ok as per fillp design. */
    if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("Socket-%d state is changing,maybe closing", fd);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    if (sock->allocState == SOCK_ALLOC_STATE_FREE) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOTSOCK);
        return -1;
    }

    if ((sock->netconn != FILLP_NULL_PTR) && (((struct FtNetconn *)sock->netconn)->pcb != FILLP_NULL_PTR)) {
        (void)memcpy_s(outStats, sizeof(struct FillpStatisticsPcb),
            &((struct FtNetconn *)sock->netconn)->pcb->fpcb.statistics, sizeof(struct FillpStatisticsPcb));
    } else {
        FILLP_LOGERR(" error: netconn/pcb is NULLPTR");
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOTCONN);
        return -1;
    }
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return FILLP_SUCCESS;
}

/*******************************************************************************
    Function    : FtFillpStatPackStat

    Description : This function is called by the FtFillpStatShow to show the
                  statistics info related to pack.
    Input       : pcb - socket pcb for which pack info needs to be displayed.

    Output      : None

    Return      : None
*******************************************************************************/
void FtFillpStatPackStat(FILLP_CONST struct FillpStatisticsPcb *pcb)
{
    FILLP_SHOWDATABUTT("FillpPackStastics :-");
    FILLP_SHOWDATABUTT("packInterval: %u", pcb->pack.packInterval);
    FILLP_SHOWDATABUTT("packTimePassed: %lld", pcb->pack.packTimePassed);

    FILLP_SHOWDATABUTT("periodRecvRate: %u", pcb->pack.periodRecvRate);
    FILLP_SHOWDATABUTT("maxRecvRate: %u", pcb->pack.maxRecvRate);
    FILLP_SHOWDATABUTT("packLostSeq: %u", pcb->pack.packLostSeq);
    FILLP_SHOWDATABUTT("packPktNum: %u", pcb->pack.packPktNum);
    FILLP_SHOWDATABUTT("periodRecvedOnes: %u", pcb->pack.periodRecvedOnes);
    FILLP_SHOWDATABUTT("periodDroped: %u", pcb->pack.periodDroped);
    FILLP_SHOWDATABUTT("periodRecvBits: %llu", pcb->pack.periodRecvBits);
    FILLP_SHOWDATABUTT("periodRecvPktLoss: %u", pcb->pack.periodRecvPktLoss);
    FILLP_SHOWDATABUTT("peerRtt: %u", pcb->pack.peerRtt);
    FILLP_SHOWDATABUTT("packSendTime: %lld", pcb->pack.packSendTime);
    FILLP_SHOWDATABUTT("periodSendRate: %u", pcb->pack.periodSendRate);
    FILLP_SHOWDATABUTT("periodAckByPackRate: %u", pcb->pack.periodAckByPackRate);
    FILLP_SHOWDATABUTT("packIntervalBackup: %u", pcb->pack.packIntervalBackup);
    FILLP_SHOWDATABUTT("packRttDetectTime: %lld", pcb->pack.packRttDetectTime);

    FILLP_SHOWDATABUTT("FillpPackStastics End's");

    return;
}

/*******************************************************************************
    Function    : FtFillpStatKeepAlive

    Description : This function is called by the FtFillpStatShow to show the
                  statistics info related to keep alive.
    Input       : pcb - socket pcb for which keep alive info needs to be displayed.

    Output      : None

    Return      : none
*******************************************************************************/
void FtFillpStatKeepAlive(FILLP_CONST struct FillpStatisticsPcb *pcb)
{
    FILLP_SHOWDATABUTT("FillpKeepAliveStastics :-");
    FILLP_SHOWDATABUTT("lastRecvTime: %lld", pcb->keepAlive.lastRecvTime);
    FILLP_SHOWDATABUTT("lastDataRecvTime: %lld", pcb->keepAlive.lastDataRecvTime);
    FILLP_SHOWDATABUTT("lastSendTime: %lld", pcb->keepAlive.lastSendTime);
    FILLP_SHOWDATABUTT("FillpKeepAliveStastics End's");

    return;
}

/*******************************************************************************
    Function    : FtFillpStatDebugStat

    Description : This function is called by the FtFillpStatShow to show the
                  statistics info related to debg/.
    Input       : pcb - socket pcb for which debg/ info needs to be displayed.

    Output      : None

    Return      : None
*******************************************************************************/
void FtFillpStatDebugStat(FILLP_CONST struct FillpStatisticsPcb *pcb)
{
    FILLP_SHOWDATABUTT("FillpStatatisticsDebugPcb :-");

    FILLP_SHOWDATABUTT("multiRetry: %d ", pcb->debugPcb.multiRetry);
    FILLP_SHOWDATABUTT("retryOne: %d ", pcb->debugPcb.retryOne);
    FILLP_SHOWDATABUTT("retryThreeTimes: %d ", pcb->debugPcb.retryThreeTimes);
    FILLP_SHOWDATABUTT("retryFourthTimes: %d ", pcb->debugPcb.retryFourthTimes);
    FILLP_SHOWDATABUTT("retryMore: %d ", pcb->debugPcb.retryMore);
    FILLP_SHOWDATABUTT("maxRetry: %d ", pcb->debugPcb.maxRetry);
    FILLP_SHOWDATABUTT("connReqSend: %u ", pcb->debugPcb.connReqSend);
    FILLP_SHOWDATABUTT("connReqFailed: %u ", pcb->debugPcb.connReqFailed);
    FILLP_SHOWDATABUTT("connReqAckSend: %u ", pcb->debugPcb.connReqAckSend);
    FILLP_SHOWDATABUTT("connReqAckFailed: %u ", pcb->debugPcb.connReqAckFailed);
    FILLP_SHOWDATABUTT("connConfirmSend: %u ", pcb->debugPcb.connConfirmSend);
    FILLP_SHOWDATABUTT("connConfirmFailed: %u ", pcb->debugPcb.connConfirmFailed);
    FILLP_SHOWDATABUTT("connConfirmAckSend: %u ", pcb->debugPcb.connConfirmAckSend);
    FILLP_SHOWDATABUTT("connConfirmAckFailed: %u ", pcb->debugPcb.connConfirmAckFailed);
    FILLP_SHOWDATABUTT("disconnReqSend: %u ", pcb->debugPcb.disconnReqSend);
    FILLP_SHOWDATABUTT("disconnReqFailed: %u ", pcb->debugPcb.disconnReqFailed);
    FILLP_SHOWDATABUTT("disconnRspSend: %u ", pcb->debugPcb.disconnRspSend);
    FILLP_SHOWDATABUTT("disconnRspFailed: %u ", pcb->debugPcb.disconnRspFailed);
    FILLP_SHOWDATABUTT("keepAliveProbeReqSend: %u ", pcb->debugPcb.keepAliveProbeReqSend);
    FILLP_SHOWDATABUTT("keepAliveProbeReqFailed: %u ", pcb->debugPcb.keepAliveProbeReqFailed);
    FILLP_SHOWDATABUTT("keepAliveProbeRspSend: %u ", pcb->debugPcb.keepAliveProbeRspSend);
    FILLP_SHOWDATABUTT("keepAliveProbeRspFailed: %u ", pcb->debugPcb.keepAliveProbeRspFailed);
    FILLP_SHOWDATABUTT("nackSend: %u ", pcb->debugPcb.nackSend);
    FILLP_SHOWDATABUTT("nackFailed: %u ", pcb->debugPcb.nackFailed);
    FILLP_SHOWDATABUTT("nackRcv: %u ", pcb->debugPcb.nackRcv);
    FILLP_SHOWDATABUTT("packSend: %u ", pcb->debugPcb.packSend);
    FILLP_SHOWDATABUTT("packFailed: %u ", pcb->debugPcb.packFailed);
    FILLP_SHOWDATABUTT("packRcv: %u ", pcb->debugPcb.packRcv);
    FILLP_SHOWDATABUTT("nackPktNum: %u ", pcb->debugPcb.nackPktNum);
    FILLP_SHOWDATABUTT("packIntervalPktNum: %u ", pcb->debugPcb.packIntervalPktNum);
    FILLP_SHOWDATABUTT("packIntervalSendBytes: %u ", pcb->debugPcb.packIntervalSendBytes);
    FILLP_SHOWDATABUTT("packIntervalSendPkt: %u ", pcb->debugPcb.packIntervalSendPkt);
    FILLP_SHOWDATABUTT("FillpStatatisticsDebugPcb End's ");

    return;
}

/*******************************************************************************
    Function    : FtFillpStatTraffic

    Description : This function is called by the FtFillpStatShow to show the
                  statistics info related to traffic.
    Input       : pcb - socket pcb for which traffic info needs to be displayed.

    Output      : None

    Return      : None
*******************************************************************************/
void FtFillpStatTraffic(FILLP_CONST struct FillpStatisticsPcb *pcb)
{
    FILLP_SHOWDATABUTT("Total Send Ones : %u,Bytes Sent %u, Send Failed ones : %u ",
                       pcb->traffic.totalSend, pcb->traffic.totalSendBytes, pcb->traffic.totalSendFailed);
    FILLP_SHOWDATABUTT("pktReceived %u,Bytes Received %u, invalid Ones : %u",
                       pcb->traffic.totalRecved, pcb->traffic.totalRecvedBytes, pcb->traffic.totalDroped);
    FILLP_SHOWDATABUTT("Retry Send Ones : %u ", pcb->traffic.totalRetryed);
    FILLP_SHOWDATABUTT("Out-of-order Ones : %u", pcb->traffic.totalOutOfOrder);
    FILLP_SHOWDATABUTT("Recv Lost : %u", pcb->traffic.totalRecvLost);

    return;
}

/*******************************************************************************
    Function    : FtFillpInnerStatShow

    Description : This function is called by the fillp Adapter to show the
                  statistics info.
    Input       : ulStatsType - Statistics type as defined in
                Different Statistics will be defined based on the Product requirements
                sockFd - Socket Index
    Output      : None
*******************************************************************************/
void FtFillpInnerStatShow(
    IN FILLP_UINT32 fillpStatsType,
    IN FILLP_CONST struct FillpStatisticsPcb *pcb)
{
    if ((fillpStatsType == FILLP_STATS_DIRECT_PACK) || (fillpStatsType == FILLP_STATS_DIRECT_ALL)) {
        FtFillpStatPackStat(pcb);
    }

    if ((fillpStatsType == FILLP_STATS_DIRECT_KEEP_ALIVE) || (fillpStatsType == FILLP_STATS_DIRECT_ALL)) {
        FtFillpStatKeepAlive(pcb);
    }

    if ((fillpStatsType == FILLP_STATS_DIRECT_DEBUG) || (fillpStatsType == FILLP_STATS_DIRECT_ALL)) {
        FtFillpStatDebugStat(pcb);
    }

    if ((fillpStatsType == FILLP_STATS_DIRECT_TRAFFIC) || (fillpStatsType == FILLP_STATS_DIRECT_ALL)) {
        FtFillpStatTraffic(pcb);
    }

    return;
}

/*******************************************************************************
    Function    : FtFillpStatShow

    Description : This function is called by the fillp Adapter to show the
                  statistics info.
    Input       : ulFillpStatsType - Statistics type as defined in
                Different Statistics will be defined based on the Product requirements
                fd - Socket Index
    Output      : None

    Return      : FILLP_SUCCESS - In success case
                  Other error code in case of failure
*******************************************************************************/
FILLP_INT FtFillpStatShow(
    IN FILLP_UINT32 fillpStatsType,
    IN FILLP_INT    fd)
{
    struct FillpStatisticsPcb *pcb = FILLP_NULL_PTR;
    struct FtSocket *sock = SockGetSocket(fd);

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("ERR_NULLPTR FtSocket sockFd = %d \r", fd);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("Socket-%d state is changing,maybe closing", fd);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    if ((sock->allocState == SOCK_ALLOC_STATE_FREE) ||
        (sock->netconn == FILLP_NULL_PTR) ||
        (((struct FtNetconn *)sock->netconn)->pcb) == FILLP_NULL_PTR) {
        FILLP_LOGERR("ERR_NULLPTR FtSocket sockFd = %d", fd);
        SET_ERRNO(FILLP_EBADF);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    if (fillpStatsType > FILLP_STATS_DIRECT_ALL) {
        FILLP_LOGERR("invalid fillpStatsType = %u \r", fillpStatsType);
        SET_ERRNO(FILLP_EINVAL);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    pcb = &(((struct FtNetconn *)sock->netconn)->pcb->fpcb.statistics);

    FtFillpInnerStatShow(fillpStatsType, pcb);

    FILLP_SHOWDATABUTT("Total Sockets : %d,Total Free Sockets : %d", g_spunge->sockTable->size,
                       FillpRingFreeEntries(&(g_spunge->sockTable->freeQueqe->ring)));
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return FILLP_SUCCESS;
}

#define FILLP_REG_OS_BASIC_LIB_FUNC(funSt, func) do { \
    if ((funSt)->sysLibBasicFunc.func != FILLP_NULL_PTR) { \
        g_fillpOsBasicLibFun.func = (funSt)->sysLibBasicFunc.func; \
    } \
} while (0)

void FtRegCopyOsBasicLibFunc(IN FILLP_CONST FillpSysLibCallbackFuncSt *libSysFunc)
{
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, memCalloc);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, memAlloc);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, memFree);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, fillpStrLen);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, fillpRand);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, fillpCreateThread);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArcInit);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArcGetCurTimeLongLong);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArchAtomicInc);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArchAtomicDec);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArchAtomicRead);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArchAtomicSet);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysArchCompAndSwap);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysSleepMs);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, sysUsleep);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, rtePause);
    FILLP_REG_OS_BASIC_LIB_FUNC(libSysFunc, cryptoRand);
    /* This is mandatory callback, so if it is NULL then it will fail in FillpApiRegLibSysFunc itself */
    g_fillpOsBasicLibFun.cryptoRand = libSysFunc->sysLibBasicFunc.cryptoRand;
}

#define FILLP_REG_OS_SEM_LIB_FUNC(funSt, func) do { \
    if ((funSt)->sysLibSemFunc.func != FILLP_NULL_PTR) { \
        g_fillpOsSemLibFun.func = (funSt)->sysLibSemFunc.func; \
    } \
} while (0)

void FtRegCopyOsSemLibFunc(IN FILLP_CONST FillpSysLibCallbackFuncSt *libSysFunc)
{
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemClose);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemInit);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemTryWait);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemWait);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemPost);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemDestroy);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSemWaitTimeout);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemInit);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemTryRDWait);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemTryWRWait);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemRDPost);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemWRPost);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchRWSemDestroy);
    FILLP_REG_OS_SEM_LIB_FUNC(libSysFunc, sysArchSchedYield);
}

#define FILLP_REG_OS_SOCKET_LIB_FUNC(funSt, func) do { \
    if ((funSt)->sysLibSockFunc.func != FILLP_NULL_PTR) { \
        g_fillpOsSocketLibFun.func = (funSt)->sysLibSockFunc.func; \
    } \
} while (0)

void FtRegCopyOsSocketLibFunc(IN FILLP_CONST FillpSysLibCallbackFuncSt *libSysFunc)
{
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, socketCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, select);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, bindCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, closeSocketCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, recvFromCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, sendtoCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, ioctl);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fcntl);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, setSockOpt);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, getSockOpt);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, sendCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, getSockNameCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, connectCallbackFunc);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncFdClr);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncFdSet);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncFdIsSet);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncCreateFdSet);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncDestroyFdSet);
    FILLP_REG_OS_SOCKET_LIB_FUNC(libSysFunc, fillpFuncCopyFdSet);
}

FILLP_INT32 FillpApiRegLibSysFunc(
    IN FILLP_CONST FillpSysLibCallbackFuncSt *libSysFunc,
    IN FILLP_CONST void *para)  /* For random function */
{
    if (g_spunge != FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EOPNOTSUPP);
        return -1;
    }

    if (FILLP_INVALID_PTR(libSysFunc)) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    FillpRegLibSysFunc();

    if (FILLP_INVALID_PTR(libSysFunc->sysLibBasicFunc.cryptoRand)) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    /* Basic Os function Registration */
    FtRegCopyOsBasicLibFunc(libSysFunc);

    /* Semaphore function Registration */
    FtRegCopyOsSemLibFunc(libSysFunc);

    /* Socket function registration */
    FtRegCopyOsSocketLibFunc(libSysFunc);

    FILLP_UNUSED_PARA(para);
    return FILLP_SUCCESS;
}

FILLP_INT32 FillpApiRegAppCallbackFunc(IN FILLP_CONST FillpAppCallbackFunc *appCbkFunc)
{
    if (FILLP_INVALID_PTR(appCbkFunc)) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    g_fillpAppCbkFun.fillpSockCloseCbkFunc = appCbkFunc->fillpSockCloseCbkFunc;

    return FILLP_SUCCESS;
}

FILLP_CHAR_PTR DLL_API FtGetVersion(void)
{
    return (FILLP_VERSION);
}

FILLP_INT DLL_API FtGetErrno(void)
{
#ifdef FILLP_LINUX
    return errno;
#elif defined(FILLP_WIN32)
    return WSAGetLastError();
#endif
}

FILLP_ULLONG DLL_API FtGetStackTime(FILLP_INT instInx)
{
    if ((g_spunge == FILLP_NULL_PTR) || (g_spunge->hasInited == FILLP_FALSE)) {
        FILLP_LOGERR("Stack not ready");
        return 0;
    }

    if ((instInx < 0) || ((FILLP_UINT)instInx >= g_spunge->insNum)) {
        FILLP_LOGERR("Inst index is out of range it should be [0,%u)", g_spunge->insNum);
        return 0;
    }

    return (FILLP_ULLONG)g_spunge->instPool[instInx].curTime;
}

/*******************************************************************************
    Function    : FtApiRegEventCallbackFunc

    Description : Register the event callback function on the socket.

    Input       : fd          -  Indicates a socket created by the FtSocket API.
                  evtCbkFunc  -  Pointer to event callback function FillpEvtCbkFunc.

    Output      : None.

    Return      :
                  0 : Success
                 -1 : Failure
*******************************************************************************/
FILLP_INT DLL_API FtApiRegEventCallbackFunc(IN FILLP_INT fd, IN FillpEvtCbkFunc evtCbkFunc)
{
    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(evtCbkFunc);
    FILLP_LOGERR("regist evt callback not support yet");
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
}

/*******************************************************************************
    Function    : FtApiUnregEventCallbackFunc

    Description : unregister the event callback function on the socket.

    Input       : fd          -  Indicates a socket created by the FtSocket API.
                  evtCbkFunc  -  Pointer to event callback function FillpEvtCbkFunc.

    Output      : None.

    Return      :
                  0 : Success
                 -1 : Failure
*******************************************************************************/
FILLP_INT DLL_API FtApiUnregEventCallbackFunc(IN FILLP_INT fd, IN FillpEvtCbkFunc evtCbkFunc)
{
    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(evtCbkFunc);
    FILLP_LOGERR("unregist evt callback not support yet");
    SET_ERRNO(FILLP_EOPNOTSUPP);
    return -1;
}

/*******************************************************************************
    Function    : FtApiEventInfoGet

    Description : Get the event info on the socket.

    Input       : fd          -  Indicates a socket created by the FtSocket API.
                  info->evt   -  Indicates the event type.

    Output      : info->info  -  Indicates the event info according to the event type.

    Return      :
                  0 : Success
                 -1 : Failure
*******************************************************************************/
FILLP_INT DLL_API FtApiEventInfoGet(IN FILLP_INT fd, IO FtEventCbkInfo *info)
{
    return SockEventInfoGet(fd, info);
}

FILLP_INT DLL_API FtSetDfxEventCb(void *softObj, FillpDfxEventCb evtCb)
{
    return FillpDfxEvtCbSet(softObj, evtCb);
}

FILLP_INT FtDfxHiDumper(FILLP_UINT32 argc, const FILLP_CHAR **argv, void *softObj, FillpDfxDumpFunc dump)
{
#ifdef FILLP_ENABLE_DFX_HIDUMPER
    return FillpDfxDump(argc, argv, softObj, dump);
#else
    (void)argc;
    (void)argv;
    (void)softObj;
    (void)dump;
    FILLP_LOGERR("unsupport FtFillpDfxDump");
    return -1;
#endif /* FILLP_ENABLE_DFX_HIDUMPER */
}

#ifdef __cplusplus
}
#endif

