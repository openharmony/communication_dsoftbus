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

#ifndef FILLP_TYPES_H
#define FILLP_TYPES_H

#ifdef FILLP_LINUX

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef FILLP_MAC
#include <mach/task.h>
#include <mach/semaphore.h>
#endif

#if !defined(FILLP_LW_LITEOS)
#ifndef __USE_GNU
#define __USE_GNU
#endif
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>

#ifndef FILLP_MAC
#include <sys/prctl.h>
#endif
#include <sched.h>
#include <unistd.h>
#include <sys/time.h>
#if !defined(FILLP_LW_LITEOS)
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/syscall.h>
#else
#include "lwip/sockets.h"
#endif

#if !defined(FILLP_LW_LITEOS) && !defined(FILLP_MAC)
#include <sys/epoll.h>
#endif

#define FILLP_STDCALL
#define DLL_API __attribute__ ((visibility ("default")))
#else
#include <WinSock2.h>
#include <windows.h>
#include <WinBase.h>
#include <Ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <windows.h>
#include <math.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "WS2_32")
#ifdef DLL_SUPPORT
#ifdef DLL_IMPLEMENT
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif
#else
#define DLL_API
#endif

#define FILLP_STDCALL __stdcall

#ifndef _WINDOWS
#ifdef _WIN32
#define _WINDOWS
#else

#ifdef _WIN64
#define _WINDOWS
#endif
#endif
#endif
#endif

#ifdef __cplusplus
#define FILLP_NULL_PTR 0
#else
#define FILLP_NULL_PTR ((void*)0)
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif

typedef char FILLP_CHAR;
typedef unsigned char FILLP_UCHAR;
typedef signed char FILLP_INT8;
typedef unsigned char FILLP_UINT8;
typedef unsigned short FILLP_UINT16;
typedef signed short FILLP_INT16;
typedef unsigned char FILLP_BOOL;
typedef unsigned int FILLP_UINT;
typedef signed int FILLP_INT;
typedef unsigned long long FILLP_ULLONG;
typedef long long FILLP_LLONG;
typedef signed long FILLP_SLONG;
typedef unsigned long FILLP_ULONG;
typedef signed int FILLP_INT32;
typedef unsigned int FILLP_UINT32;

typedef FILLP_INT FillpErrorType;
typedef unsigned long DWORD;

#define FILLP_INVALID_UINT32 0xFFFFFFFF
#define FILLP_INVALID_INT 0x7FFFFFFF
#define FILLP_MAX_UNSHORT_VAL 0xFFFF /* max value of unsinged short */
#define FILLP_FALSE 0
#define FILLP_TRUE 1
#define FILLP_SUCCESS 0
#define FILLP_FAILURE 1
#define FILLP_CONST const
#define IO   /* Input and Out param */
#define IN   /* Input param */
#define OUT  /* Output param */

#ifndef FILLP_FIONBIO
#define FILLP_FIONBIO 1 /* Set/Unset socket non-blocking */
#endif

#define FILLP_UNUSED_PARA(para) (void)(para)

/* higher value kept so that it should not clash with linux header files */
#define IPPROTO_FILLP 512

/* cmsg type used in FtSendFrame */
#define FILLP_CMSG_TYPE_FRAME 0x1

/* fillp socket options */
#define FILLP_PKT_DATA_OPTS_TIMESTAMP 0x01
#define FILLP_SOCK_SEND_CACHE_INFO 0x2
#define FILLP_SOCK_FC_ALG 0x03
#define FILLP_SOCK_DIRECTLY_SEND 0x4
#define FILLP_SOCK_BW_DET_ALGO 0x5
#define FILLP_SOCK_BW_DET_PARAMS 0x6
#define FILLP_SOCK_CQE_ALGO 0x7
#define FILLP_SOCK_CQE_PARAMS 0x8
#define FILLP_SOCK_MIRACAST_VIDEO_PARAMS 0x9
#define FILLP_SEMI_RELIABLE 0xa
#define FILLP_SOCK_TRAFFIC 0x10

#define FILLP_IPV6_ADDR_LEN 4

#define FILLP_ALG_BASE 0
#define FILLP_ALG_ONE 1
#define FILLP_ALG_TWO 2
#define FILLP_ALG_THREE 3
#define FILLP_ALG_MSG 4

/* define character bit */
#define FILLP_SUPPORT_PACK_WITH_HRBB 0X01 /* send head receiving buffer bubble in pack packet */
#define FILLP_SUPPORT_PACK_WITH_PKT_IVAR 0X02

/* Valid opcodes to issue to sys_epoll_ctl() */
#define SPUNGE_EPOLL_CTL_ADD 1
#define SPUNGE_EPOLL_CTL_DEL 2
#define SPUNGE_EPOLL_CTL_MOD 3

/* Dbg ID for all files */
#define  FILLP_DEBUG_ID_ALL                 0xFFFFFFFFFFFFFFFF  /* To enable logs for all the modules */

/**
 * @defgroup FillpDebugCmdEn
 * @ingroup Enums
 * @par Prototype
 *
 * @datastruct SPUNGE_SHUT_RD Denotes the read close of the socket.
 * However can continue to send data from peer socket
 * @datastruct SPUNGE_SHUT_WR Denotes the write close of the socket.
 * However can continue to receive data from peer socket
 * @datastruct SPUNGE_SHUT_RDWR Denotes the read and write close of the socket. Equivalent to RST of TCP
 */
enum SpungeSockShutdownCmd {
    SPUNGE_SHUT_RD,
    SPUNGE_SHUT_WR,
    SPUNGE_SHUT_RDWR,
};

/**
 * @defgroup CommonMacros
 * @ingroup Macros
 * @par Prototype
 */
#if defined(FILLP_LINUX)
#define SPUNGE_EPOLLIN    EPOLLIN    /* The associated file is available for read(2) operations. */
#define SPUNGE_EPOLLOUT   EPOLLOUT   /* The associated file is available for write(2) operations. */
#define SPUNGE_EPOLLERR   EPOLLERR   /* Error condition happened on the associat */
#define SPUNGE_EPOLLET    EPOLLET    /* Edge trigger support */
#define SPUNGE_EPOLLHUP   EPOLLHUP   /* Hang up happened on the associated socket */
#define SPUNGE_EPOLLRDHUP EPOLLRDHUP /* Peer closed */
#else
#define SPUNGE_EPOLLIN    0x0001    /* The associated file is available for read(2) operations. */
#define SPUNGE_EPOLLOUT   0x0004    /* The associated file is available for write(2) operations. */
#define SPUNGE_EPOLLERR   0x0008    /* Error condition happened on the associat */
#define SPUNGE_EPOLLET    (1u << 31) /* Edge trigger support */
#define SPUNGE_EPOLLHUP   0x0010    /* Hang up happened on the associated socket */
#define SPUNGE_EPOLLRDHUP 0x2000    /* Peer closed */
#endif

#if defined(FILLP_LINUX) && !defined(FILLP_MAC)
#pragma pack(push, 4)
#else
#pragma pack(push, 8)
#endif

/**
 * Indicates spunge epoll data.
 */
union SpungeEpollData {
    void *ptr; /* Indicates a pointer to the epoll data. */
    FILLP_INT fd; /* Indicates the file descriptor. */
    FILLP_UINT32 u32; /* Indicates 32-bit data. */
    FILLP_ULLONG u64; /* Indicates 64-bit data. */
};

/**
 * Provides spunge epoll event data.
 */
struct SpungeEpollEvent {
    FILLP_UINT32 events; /* Indicates Epoll events. */
    union SpungeEpollData data; /* Indicates the user data variable. */
};
#pragma pack(pop)

/**
 * @defgroup e Error Codes
 * @ingroup Macros
 * @par Marcos
 */
#if !defined(FILLP_LW_LITEOS)
#define ERR_OK 0
#endif
#define FILLP_OK ERR_OK
#define FILLP_NULL 0
#define ERR_NULLPTR (-1) /* NULL Point Error */
#define ERR_NOBUFS (-2) /* No buf/item to malloc */
#define FILLP_ERR_CONN (-3) /* connection err */
#define ERR_PARAM (-4) /* EINVAL */
#define ERR_NORES (-5) /* No resource */
#define ERR_FAILURE (-7) /* general sem init failures and socket init failures */
#define ERR_FEATURE_MACRO_NOT_ENABLED (-10)
#define FILLP_ERR_VAL (-13)
#define ERR_CONNREFUSED (-14)
#define ERR_NO_SOCK (-200)
#define ERR_NO_REBIND (-201)
#define ERR_EAGAIN (-205)
#define ERR_NO_SYS_SOCK (-207)
#define FILLP_ERR_ISCONN (-208)
#define FILLP_ERR_EALREADY (-209)
#define ERR_CONN_TIMEOUT (-300)
#define ERR_ADP_SYS_CALLBACK_NOT_REGISTERED (-303)
#define ERR_SOCK_TYPE_ERR (-306)
#define ERR_SYSTEM_MEMORY_FAILURE (-308)
#define ERR_STACK_ALREADY_INITIALD (-402)
#define ERR_UNDERCLOSURE (-500) /* ft socket is already under closure */
#define ERR_WRONGSTATE (-501) /* api is invoked in wrong connection state */
#define ERR_NONBLOCK_UNDERCONNECT (-503)
#define ERR_EINPROGRESS (-504)
#define ERR_FT_SOCKET_INVALID (-506)
#define ERR_TRACE_OBJ_TYPE_INVALID (-507)
#define ERR_STACK_NOT_INITED (-518) /* Stack is not in ACTIVE state */
#define ERR_HMAC_SHA2_DIGEST_MISMATCH (-519)
#define ERR_STALE_COOKIE_ERROR (-520)
#define ERR_COOKIE_PORT_MISMATCH (-521)
#define ERR_REMOTE_REJECT_OR_CLOSE (-522)
#define ERR_NON_FATAL (-523)
#define ERR_REMOTE_REJECT_VERSION (-524)
#define ERR_COMM (-1000) /* general error */
#define ERR_SOCK_BIND (-1001) /* bind failed */
#ifdef FILLP_WIN32
#ifndef ERROR_WAS_LOCKED
/* WinError.h: 717717 (0x2CD) {Page Locked} One of the pages to lock was already locked */
#define ERROR_WAS_LOCKED 0x2CD
#endif /* #ifndef ERROR_WAS_LOCKED */
#endif /* #ifdef FILLP_WIN32 */

#ifdef FILLP_LINUX
#define FILLP_EAGAIN           EAGAIN
#define FILLP_EWOULDBLOCK      FILLP_EAGAIN
#define FILLP_EINPROGRESS      EINPROGRESS
#define FILLP_EINVAL           EINVAL
#define FILLP_EBADF            EBADF
#define FILLP_ENOMEM           ENOMEM
#define FILLP_EPIPE            EPIPE
#define FILLP_EFAULT           EFAULT
#define FILLP_ENOTCONN         ENOTCONN
#define FILLP_ECONNRESET       ECONNRESET
#define FILLP_ENODATA          ENODATA
#define FILLP_ENOBUFS          ENOBUFS
#define FILLP_ETIMEDOUT        ETIMEDOUT
#define FILLP_ECONNREFUSED     ECONNREFUSED
#define FILLP_EPROTOTYPE       EPROTOTYPE
#define FILLP_ENOPROTOOPT      ENOPROTOOPT
#define FILLP_EPROTONOSUPPORT  EPROTONOSUPPORT
#define FILLP_ESOCKTNOSUPPORT  ESOCKTNOSUPPORT
#define FILLP_EOPNOTSUPP       EOPNOTSUPP
#define FILLP_EPFNOSUPPORT     EPFNOSUPPORT
#define FILLP_EAFNOSUPPORT     EAFNOSUPPORT
#define FILLP_EADDRINUSE       EADDRINUSE
#define FILLP_EBUSY            EBUSY
#define FILLP_ENOTSOCK         ENOTSOCK
#define FILLP_EISCONN          EISCONN
#define FILLP_ENOENT           ENOENT
#define FILLP_EEXIST           EEXIST
#define FILLP_EMFILE           EMFILE
#define FILLP_EALREADY         EALREADY

#elif defined(FILLP_WIN32)
#define FILLP_EAGAIN           WSAEWOULDBLOCK
#define FILLP_EWOULDBLOCK      FILLP_EAGAIN
#define FILLP_EINPROGRESS      WSAEINPROGRESS
#define FILLP_EINVAL           WSAEINVAL
#define FILLP_EBADF            WSAEBADF
#define FILLP_ENOMEM           WSA_NOT_ENOUGH_MEMORY
#define FILLP_EPIPE            WSAENOTCONN
#define FILLP_EFAULT           WSAEFAULT
#define FILLP_ENOTCONN         WSAENOTCONN
#define FILLP_ECONNRESET       WSAECONNRESET
#define FILLP_ENODATA          WSAENOMORE
#define FILLP_ENOBUFS          WSAENOBUFS
#define FILLP_ETIMEDOUT        WSAETIMEDOUT
#define FILLP_ECONNREFUSED     WSAECONNREFUSED
#define FILLP_EPROTOTYPE       WSAEPROTOTYPE
#define FILLP_ENOPROTOOPT      WSAENOPROTOOPT
#define FILLP_EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define FILLP_ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#define FILLP_EOPNOTSUPP       WSAEOPNOTSUPP
#define FILLP_EPFNOSUPPORT     WSAEPFNOSUPPORT
#define FILLP_EAFNOSUPPORT     WSAEAFNOSUPPORT
#define FILLP_EADDRINUSE       WSAEADDRINUSE
#define FILLP_EBUSY            ERROR_WAS_LOCKED
#define FILLP_ENOTSOCK         WSAENOTSOCK
#define FILLP_EISCONN          WSAEISCONN
#define FILLP_ENOENT           WSANO_DATA
#define FILLP_EEXIST           WSAEALREADY
#define FILLP_EMFILE           WSAEMFILE
#define FILLP_EALREADY         WSAEALREADY
#endif

#define FILLP_SIZE_T size_t
#if defined(FILLP_LINUX)

#define FILLP_ATOMIC

/**
 * Provides the data to store atomic operations value.
 */
#ifdef FILLP_ATOMIC
#ifdef FILLP_LW_LITEOS
typedef atomic_t SysArchAtomic;
#else
typedef struct {
    volatile FILLP_INT counter; /* Indicates the counter to store atomic operations value. */
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
} AtomicT;
typedef AtomicT SysArchAtomic;
#endif
#endif /* FILLP_ATOMIC */

#ifndef FILLP_MAC
typedef struct {
    FILLP_INT counter;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} SemT;
#define SYS_ARCH_SEM SemT
#endif

#ifdef FILLP_MAC
#define SYS_ARCH_SEM semaphore_t
#endif

#if defined(FILLP_LW_LITEOS)
typedef struct InnerSysArchRwSem {
    pthread_mutex_t readMutex;
    pthread_mutex_t writeMutex;
    volatile int readCount;
} SYS_ARCH_RW_SEM;

#else
#define SYS_ARCH_RW_SEM pthread_rwlock_t
#endif
#elif defined(FILLP_WIN32)

typedef volatile FILLP_INT SysArchAtomic;

/**
 * Provides a semaphore.
 */
#define SYS_ARCH_SEM HANDLE
typedef struct InnerSysArchRwSem {
    volatile FILLP_ULONG sem; /* Indicates a semaphore. */
} SYS_ARCH_RW_SEM;
#else
# error "system atomic function need to define !!!"
#endif

typedef struct sockaddr FILLP_SOCKADDR;

/**
* Provides thread parameters.
*/
struct ThreadParam {
    void (*func)(void *param); /* Indicates a pointer to the spunge main thread function. */
    void *param; /* Indicates a pointer to the spunge instance. */
};

/**
* Provides the FillP debug level values.
*/
typedef enum {
    FILLP_DBG_LVL_DEBUG = 1, /* Indicates the FillP debug level. */
    FILLP_DBG_LVL_DETAIL, /* Indicates the FillP debug details. */
    FILLP_DBG_LVL_INFO, /* Indicates the FillP debug information. */
    FILLP_DBG_LVL_WARNING, /* Indicates the FillP debug level warning. */
    FILLP_DBG_LVL_ERROR, /* Indicates the FillP debug level error. */
    FILLP_DBG_LVL_BUTT, /* Indicates the end of the enum. */
    FILLP_DBG_LVL_HELP,
    FILLP_DBG_LVL_SHOWDATA,
    FILLP_DBG_LVL_SHOWLEVEL,
} FillpDebugLevel;

/**
* Provides the debug type values.
*/
typedef enum {
    /* Provides information about all other debug commands which a developer can use. */
    FILLP_DBG_HELP,
    /* Provides all runtime error/warning/info logs, based on the level
     * set by developer/debugger(FILLP_DBGCMD_SET_PRINT_LEVEL) */
    FILLP_DBG_PRINT,
    /* Provides information on the existing level for run time debug information set by the developer. */
    FILLP_DBG_SHOW_LEVEL,
    /* Provides function trace information, if enabled by the developer. */
    FILLP_DBG_FUNC_TRACE,
    /* Provides information requested by the developer using debug interface. */
    FILLP_DBG_SHOW_DATA,
    /* Provides all the product/user related log information. */
    FILLP_DBG_LOG
} FillpDebugType;

typedef enum {
    FILLP_PACK_STATE_NORMAL = 1,
    FILLP_PACK_STATE_ENLARGE,
    FILLP_PACK_STATE_KEEP_ALIVE
} FillpPackSendState;

/**
 * @ingroup FillPDebug
 * @brief
 * This callback is use for debug send.
 *
 * @param[in] debugType @ref FillpDebugType
 * @param[in] debugLvl @ref FillpDebugLevel
 * @param[in] debugId Indicates the file and line information.
 * @param[in] format Specifies the actual message.
 *
 * @return
 * On success : FILLP_SUCCESS
 * On failure : FILLP_FAILURE
 */
typedef void (*FillpDebugSendFunc)(IN FILLP_UINT32 debugType, IN FILLP_UINT32 debugLvl,
    IN FILLP_UINT32 debugId, IN FILLP_CHAR *format, ...);

/**
* Provides information about LM callback function.
*/
typedef struct {
    FillpDebugSendFunc debugCallbackFunc; /* Registers debug information output callback function. */
} FillpLmCallbackFunc;

/**
 * @ingroup FillPDebug
 * @brief
 * Sets the debug log level.
 *
 * @param[in] logLevel Defines the log level. Refer @ref FillpDebugLevel.
 * @return
 * FILLP_SUCCESS on success, otherwise error codes.
 */
extern FILLP_INT32 DLL_API FillpApiSetDebugLogLevel(IN FILLP_UINT8 logLevel);

/**
 * @ingroup FillPDebug
 * @brief
 * Sets the log enable/disable status for different modules.
 *
 * @param[in] logModules ORed values of all the modules for which log needs to
 * be enabled. If set to 0xFFFFFFFF, then it is enabled for all the modules.
 * @return
 * FILLP_SUCCESS on success, otherwise error codes.
 */
extern FILLP_UINT32 DLL_API FillpApiConfigLogModules(IN FILLP_ULLONG logModules);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is used to info APP that fillp socket is about to close and destroy, so APP
 * can do something before fillp socket destroy.
 *
 * @param[in] udpSock udp socket fd
 * @param[in] localAddr Indicates the local socket address
 * @param[in] peerAddr Indicates the peer socket address
 *
 * @return
 * void
 */
typedef void (*FillpSockCloseCbkFunc)(IN FILLP_INT udpSock, IN struct sockaddr *localAddr,
    IN struct sockaddr *peerAddr);

/**
 * Structure of app callback functions.
 */
typedef struct {
    FillpSockCloseCbkFunc fillpSockCloseCbkFunc; /* Registers fillp socket close callback function. */
} FillpAppCallbackFunc;

typedef void (*FillpEventPollCbFunc)(void *argEpInfo, int fd, int event);

enum {
    NONE,
    VIDEO_I,
    VIDEO_P,
    VIDEO_MAX = 50,
    AUDIO = VIDEO_MAX + 1,
    AUDIO_MAX = 100,
};

#define FRAME_INFO_BITMAP_SLICE_END 0x00000001 /* last data of the slice */
#define FRAME_INFO_BITMAP_FRAME_END 0x00000002 /* last data of the frame,
                                                * when set, the SLICE_END or the LAYER_END no need to set */
#define FRAME_INFO_BITMAP_LAYER_END 0x00000004 /* last data of the layer */

struct FrameInfo {
    FILLP_INT frameType; /* I or P frame */
    FILLP_INT seqNum; /* frame sequence number, different slice or layer data has the same sequence,
                       * range [0 ~ 2147483647] */
    FILLP_INT subSeqNum; /* slice number of the frame, started at 0 of a new slice */
    FILLP_INT level; /* level of the scalable video coding, 0: basic level, 1: extend level 1, 2: extend level 2 */
    FILLP_SLONG timestamp; /* time of the frame in codec, us. it's optional and value 0 means no time got */
    FILLP_UINT32 bitMap;
};

/**
 * the event type
 */
typedef enum {
    FT_EVT_FRAME_STATS,
    FT_EVT_TRAFFIC_DATA,
    FT_EVT_MAX,
} FtEnumEventType;

typedef enum {
    FILLP_FRAME_COST_LT10MS = 0,
    FILLP_FRAME_COST_LT30MS,
    FILLP_FRAME_COST_LT50MS,
    FILLP_FRAME_COST_LT75MS,
    FILLP_FRAME_COST_LT100MS,
    FILLP_FRAME_COST_LT120MS,
    FILLP_FRAME_COST_GE120MS,
    FILLP_FRAME_COST_MAX,
} FillpFrameCost;

typedef enum {
    FILLP_FRAME_BIT_RATE_LT3M = 0,
    FILLP_FRAME_BIT_RATE_LT6M,
    FILLP_FRAME_BIT_RATE_LT10M,
    FILLP_FRAME_BIT_RATE_LT20M,
    FILLP_FRAME_BIT_RATE_LT30M,
    FILLP_FRAME_BIT_RATE_GE30M,
    FILLP_FRAME_BIT_RATE_MAX,
} FillpFrameBitRate;

typedef struct {
    FILLP_UINT32 costTimeStatsCnt[FILLP_FRAME_COST_MAX];
    FILLP_UINT32 sendBitRateStatsCnt[FILLP_FRAME_BIT_RATE_MAX];
} FillpFrameSendStats;

#define FILLP_TRAFFIC_LEN 32
typedef struct {
    FILLP_UCHAR stats[FILLP_TRAFFIC_LEN];
} FillpTrafficInfo;

/**
 * Structure of event callback information.
 */
typedef struct {
    FtEnumEventType evt;
    union {
        FillpFrameSendStats frameSendStats;
        FillpTrafficInfo trafficData;
        FILLP_UINT32 reserved;
    } info;
} FtEventCbkInfo;

/**
 * @ingroup fillpevt
 * @brief  This callback is used to info APP when some events occur.
 *
 * @param[in] fd    Indicates a socket created by the FtSocket API.
 * @param[in] info  Pointer to event callback information FtEventCbkInfo.
 *
 * @return
 * On Success : returns 0
 * On Failure : returns -1
 */
typedef FILLP_INT (*FillpEvtCbkFunc)(IN FILLP_INT fd, IN FILLP_CONST FtEventCbkInfo *info);

#define FILLP_DFX_EVENT_NAME_LEN 33

typedef enum {
    FILLP_DFX_EVENT_TYPE_FAULT,
    FILLP_DFX_EVENT_TYPE_STATISTIC,
    FILLP_DFX_EVENT_TYPE_SECURITY,
    FILLP_DFX_EVENT_TYPE_BEHAVIOR,
} FillpDfxEvtType;

typedef enum {
    FILLP_DFX_EVENT_LEVEL_CRITICAL,
    FILLP_DFX_EVENT_LEVEL_MINOR,
} FillpDfxEventLevel;

typedef enum {
    FILLP_DFX_PARAM_TYPE_BOOL,
    FILLP_DFX_PARAM_TYPE_UINT8,
    FILLP_DFX_PARAM_TYPE_UINT16,
    FILLP_DFX_PARAM_TYPE_INT32,
    FILLP_DFX_PARAM_TYPE_UINT32,
    FILLP_DFX_PARAM_TYPE_UINT64,
    FILLP_DFX_PARAM_TYPE_FLOAT,
    FILLP_DFX_PARAM_TYPE_DOUBLE,
    FILLP_DFX_PARAM_TYPE_STRING
} FillpDfxEventParamType;

typedef struct {
    FillpDfxEventParamType type;
    FILLP_CHAR paramName[FILLP_DFX_EVENT_NAME_LEN];
    union {
        FILLP_UINT8 u8v;
        FILLP_UINT16 u16v;
        FILLP_INT32 i32v;
        FILLP_UINT32 u32v;
        FILLP_ULLONG u64v;
        float f;
        double d;
        FILLP_CHAR str[FILLP_DFX_EVENT_NAME_LEN];
    } val;
} FillpDfxEventParam;

typedef struct {
    FILLP_CHAR eventName[FILLP_DFX_EVENT_NAME_LEN];
    FillpDfxEvtType type;
    FillpDfxEventLevel level;
    FILLP_UINT32 paramNum;
    FillpDfxEventParam *paramArray;
} FillpDfxEvent;

/**
 * @ingroup fillpevt
 * @brief  report dstream event
 *
 * @param[in] softObj   any useful message to FillpDfxEventCb
 * @param[in]    info   event detail
 */
typedef void (*FillpDfxEventCb)(void *softObj, const FillpDfxEvent *info);

/**
 * @ingroup fillpevt
 * @brief  function to printf data.
 *
 * @param[in] softObj   any useful message to FillpDfxDumpFunc
 * @param[in]    data   dump string to print
 * @param[in]     len   lenth of data
 */
typedef void (*FillpDfxDumpFunc)(void *softObj, const FILLP_CHAR *data, FILLP_UINT32 len);

#ifdef __cplusplus
}
#endif

#endif

