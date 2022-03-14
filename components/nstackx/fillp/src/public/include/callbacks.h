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

#ifndef CALLBACKS_H
#define CALLBACKS_H
#include "fillpinc.h"
#include "fillp_os.h"

#ifdef FILLP_MAC
#include <mach/task.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/mach_init.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_CONST_2    2
#define FILLP_CONST_100  100
#define FILLP_CONST_1K   1000
#define FILLP_CONST_10K  10000
#define FILLP_CONST_1M   1000000

#if defined(FILLP_LINUX) && defined(FILLP_MAC)

typedef uint64_t FillpSysArchTime;

#elif defined(FILLP_LINUX)

typedef struct timespec FillpSysArchTime;

#elif defined(FILLP_WIN32)

typedef struct FillpSysArchTimeSt {
    LARGE_INTEGER time;
} FillpSysArchTime;

#endif


void *FillpMemCalloc(IN FILLP_UINT32 nitems, IN FILLP_UINT32 size);

/*******************************************************************************
    Adption     : FillpMemAlloc

    Description : Adp Adption if user has not registered the callback for malloc

    Input         :
                    size: Requested size to be allocated

    Output       :None

    Return       : FILLP_NULL_PTR
 *******************************************************************************/
void  *FillpMemAlloc(IN FILLP_UINT32 size);


/*******************************************************************************
    Adption     : FillpMemFree

    Description : Adp Adption if user has not registered the callback for free

    Input         :
                    addr                   : Base address of memory to be freed

    Output       :None

    Return       : FILLP_FAILURE
 *******************************************************************************/
void FillpMemFree(IN void *addr);

void *FillpMemChr(IN FILLP_CONST void *s, IN FILLP_INT c, IN FILLP_SIZE_T n);

/*******************************************************************************
    Adption     : FillpStrLen

    Description : Adp function if user has not registered the callback for strlen

    Input         :
                    pSrc                    : String

    Output       :None

    Return       : FILLP_NULL_PTR
 *******************************************************************************/
FILLP_UINT32 FillpStrLen(IN FILLP_CHAR *str);

/*******************************************************************************
    Function     : FillpAdpSelect

    Description : Adp function if user has not registered the callback for select
 *******************************************************************************/
FILLP_INT  FillpSelect(
    IN FILLP_INT maxFd, /* fd value to be selected */
    IN void *rdFds, /* fd for read */
    IN void *wrFds, /* fd for write */
    IO void *exceptFds, /* fd for errors */
    IN void *timeout); /* max time for select to wait */


void FillpFuncFdClr(
    IN FILLP_UINT sockFd, /* socket fd */
    IN FT_FD_SET clrFdSet);

void FillpFuncFdSet(
    IN FILLP_UINT sockFd, /* socket fd */
    IN FT_FD_SET setFd);

FILLP_INT FillpFuncFdIsSet(
    IN FILLP_INT sockFd, /* socket fd */
    IN FT_FD_SET issetFd);


FT_FD_SET FillpFuncCreateFdSet(void);

void FillpFuncDestroyFdSet(IN FT_FD_SET destroyFdSet);

FILLP_INT32 FillpFuncCopyFdSet(IO FT_FD_SET dstFdSet, IN FT_FD_SET srcFdSet);


/*******************************************************************************
    Function     : FillpRand

    Description : Adp function if user has not registered the callback for rand
 *******************************************************************************/
FILLP_UINT32 FillpRand(IN void);


/*******************************************************************************
    Function     : FillpCreateThread

    Description : Adp function if user has not registered the callback for rand
 *******************************************************************************/
FILLP_INT FillpCreateThread(IN void *param, IO void *threadId);


/*******************************************************************************
    Function     : FillpSysArchInit

    Description : Adp function if user has not registered the callback for  initializing the
                       use of the Winsock DLL by a process
 *******************************************************************************/
FILLP_INT FillpSysArchInit(IN void);

/*******************************************************************************
    Function     : FillpAdpSysArcGetCurTime

    Description : Adp function if user has not registered the callback for getting system current time
 *******************************************************************************/
FILLP_LLONG FillpSysArchGetCurTimeLonglong(IN void);

/*******************************************************************************
    Function     : FillpSysArchAtomicInc

    Description : Adp function if user has not registered the callback for increment the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicInc(IO SysArchAtomic *var, FILLP_INT val);

/*******************************************************************************
    Function     : FillpSysArchAtomicIncAndTest

    Description : Adp function if user has not registered the callback for increment and test the value
 *******************************************************************************/
FILLP_BOOL FillpSysArchAtomicIncAndTest(IO SysArchAtomic *var);

/*******************************************************************************
    Function     : FillpSysArchAtomicDec

    Description : Adp function if user has not registered the callback for decrement the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicDec(IO SysArchAtomic *var, FILLP_INT val);

/*******************************************************************************
    Function     : FillpSysArchAtomicDecAndTest

    Description : Adp function if user has not registered the callback for decrement and test the value
 *******************************************************************************/
FILLP_BOOL FillpSysArchAtomicDecAndTest(IO SysArchAtomic *var);

/*******************************************************************************
    Function     : FillpSysArchAtomicDec

    Description : Adp function if user has not registered the callback for read the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicRead(IO SysArchAtomic *var);

/*******************************************************************************
    Function     : FillpSysArchAtomicSet

    Description : Adp function if user has not registered the callback for automatic exchange the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicSet(IN SysArchAtomic *var, FILLP_INT newValue);

/*******************************************************************************
    Function     : FillpAdpSysArchCompAndSwap

    Description : Adp function if user has not registered the callback for compare and swap a value
 *******************************************************************************/
FILLP_INT FillpSysArchCompAndWwap(IO volatile FILLP_ULONG *sem,
    IN volatile FILLP_ULONG oldValue,
    IN volatile FILLP_ULONG exchange);


/*******************************************************************************
    Function     : FillpSysSleepMs

    Description : Adp function if user has not registered the callback for sleep
 *******************************************************************************/
void FillpSysSleepMs(IN FILLP_UINT time); /* In Millseconds */

FILLP_INT FillpSysSleepUs(IN FILLP_UINT time); /* In seconds */


/*******************************************************************************
    Function     : FillpAdpRtePause

    Description : Adp function if user has not registered the callback for pause
 *******************************************************************************/
void FillpAdpRtePause(void);


/*******************************************************************************
    Function     : FillpSemTryWait

    Description : Adp function if user has not registered the callback for semaphore try wait
 *******************************************************************************/
FILLP_INT FillpSemTryWait(IN SYS_ARCH_SEM *sem);

/*******************************************************************************
    Function     : FillpSemWait

    Description : Adp function if user has not registered the callback for semaphore wait
 *******************************************************************************/
FILLP_INT FillpSemWait(IN SYS_ARCH_SEM *sem);

FILLP_INT FillpRwSemTryRdWait(IN SYS_ARCH_RW_SEM *sem);

FILLP_INT FillpRwSemTryWrWait(IN SYS_ARCH_RW_SEM *sem);


/*******************************************************************************
    Function     : FillpRwSemRdPost

    Description : Adp function if user has not registered the callback for semaphore post
 *******************************************************************************/
FILLP_INT FillpRwSemRdPost(IN SYS_ARCH_RW_SEM *sem);

/*******************************************************************************
    Function     : FillpRwSemWrPost

    Description : Adp function if user has not registered the callback for semaphore post

 *******************************************************************************/
FILLP_INT FillpRwSemWrPost(IN SYS_ARCH_RW_SEM *sem);

/*******************************************************************************
    Function     : FillpRwSemDestroy

    Description : Adp function if user has not registered the callback for semaphore destroy
 *******************************************************************************/
FILLP_INT FillpRwSemDestroy(IN SYS_ARCH_RW_SEM *sem);

/*******************************************************************************
    Function     : FillpSemPost

    Description : Adp function if user has not registered the callback for semaphore post
 *******************************************************************************/
FILLP_INT FillpSemPost(IN SYS_ARCH_SEM *sem);

/*******************************************************************************
    Function     : FillpSemDestroy

    Description : Adp function if user has not registered the callback for semaphore destroy
 *******************************************************************************/
FILLP_INT FillpSemDestroy(IN SYS_ARCH_SEM *sem);


/*******************************************************************************
    Function     : FillpFuncCreateSocket

    Description : Adp function if user has not registered the Create socket callback
 *******************************************************************************/
FILLP_INT32 FillpFuncCreateSocket(
    IN FILLP_INT32 domain, /* the address family */
    IN FILLP_INT32 type, /* new socket */
    IN FILLP_INT32 protocol); /* protocol to be used */


/*******************************************************************************
    Function     : FillpFuncBindSocket

    Description : Adp function if user has not registered the Bind socket callback function

 *******************************************************************************/
FILLP_INT32 FillpFuncBindSocket(
    IN FILLP_INT32 sockFd, /* socket fd */
    IN FILLP_CONST void *myAddr, /* bind addr */
    IN FILLP_INT32 addrLen); /* addr length */


FILLP_INT FillpFuncIoCtlSocket(
    FILLP_INT fd,
    FILLP_INT type,
    FILLP_ULONG *parg);


FILLP_INT32 FillpFuncGetSockName(
    IN FILLP_INT32 sockFd, /* socket fd */
    IN void *myAddr, /* bind addr */
    IN void *addrLen); /* addr length */


FILLP_INT32 FillpFuncConnectSocket(
    IN FILLP_INT32 sockFd, /* socket fd */
    IN FILLP_CONST void *myAddr, /* bind addr */
    IN FILLP_INT32 addrLen); /* addr length */


/*******************************************************************************
    Function     : FillpFuncCloseSocket

    Description : Adp function if user has not registered the close socket callback function
 *******************************************************************************/
FILLP_INT32 FillpFuncCloseSocket(IN FILLP_INT32 sockFd);


/*******************************************************************************
    Function     : FillpFuncSendTo

    Description : Adp function if user has not registered the sendto callback function
 *******************************************************************************/
FILLP_INT FillpFuncSendTo(
    IN FILLP_INT sockFd,
    IN const void *buf,
    IN FILLP_SIZE_T len,
    IN FILLP_INT flags,
    IN const void *to,
    IN FILLP_SIZE_T toLen);


/*******************************************************************************
    Function     : FillpFuncRecvFrom

    Description : Adp function if user has not registered the receive from callback function
 *******************************************************************************/
FILLP_INT  FillpFuncRecvFrom(
    IN FILLP_INT sockFd,
    OUT void *buf,
    IN FILLP_SIZE_T len,
    IN FILLP_INT flags,
    OUT void *from,
    IO FILLP_SIZE_T *fromLen);


FILLP_INT FillpFuncSend(
    IN FILLP_INT sockFd, /* Connection fd */
    IN const void *buffer, /* buffer to hold data to be sent */
    IN FILLP_INT len, /* no of bytes to be sent */
    IN FILLP_INT flags); /* flags to tell the status */


/* callback for SYS_ARCH_SEM_CLOSE */
FILLP_INT FillpSysArchSemClose(SYS_ARCH_SEM *sem);

/* callback for SYS_ARCH_SEM_WAIT_TIMEOUT */
FILLP_INT FillpSysArchSemWaitTimeout(SYS_ARCH_SEM *sem, FILLP_SLONG timeout);


/*******************************************************************************
    Function     : FillpRegLibSysFunc

    Description : FILLP user invokes this function to register the system interface functions to be used by FILLP stack.
                  The function pointers of all system functions defined by FILLP_SYS_APPLIB_CALLBACK_FUNC_ST are passed
                  to FILLP stack to be registered and used during the run time of the stack.
                  The user is expected to pass a valid function pointer. Passing NULL as any of the function pointer
                  results in failure. This function should be called before initializing the stack.

    Input         : pstAdpAppLibSysFunc: Pointer to system interface callback function structure
                    (FILLP_SYS_APPLIB_CALLBACK_FUNC_ST).


    Output       :None

    Return       : Fillp_SUCCESS - Success
                       ERROR CODES    - Failure
*******************************************************************************/

void FillpRegLibSysFunc(IN void);


void FillpSysOsDeinit(IN void);

FILLP_INT FillpFuncFcntl(
    IN FILLP_INT fd, /* connection fd */
    IN FILLP_INT cmd, /* command to perform on socket */
    IN FILLP_INT val); /* arguments for socket */


FILLP_INT FillpFuncSetSockOpt(
    IN FILLP_INT sockFd,
    IN FILLP_INT level,
    IN FILLP_INT optName,
    IN FILLP_CONST void *optVal,
    IN FILLP_INT optLen);


FILLP_INT FillpFuncGetSockOpt(
    IN FILLP_INT sockFd,
    IN FILLP_INT level,
    IN FILLP_INT optName,
    IO void *optVal,
    IO FILLP_INT *optLen);

FILLP_INT  FillpArchInitSem(
    IO SYS_ARCH_SEM  *sem,
    IN FILLP_ULONG value);

void FillpSysArchCompilerBarrier(void);


FILLP_LLONG FillpSysAdaptArchGetCurTimeLonglong();

#ifdef __cplusplus
}
#endif


#endif  /* CALLBACKS_H */

