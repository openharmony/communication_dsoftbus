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

#include "callbacks.h"

#ifdef FILLP_LINUX

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include "semaphore.h"
#include <pthread.h>
#ifndef FILLP_MAC
#include <sys/prctl.h>
#endif
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>
#if defined(FILLP_LW_LITEOS)
#include "los_sem.h"
#include "los_typedef.h"
#include "los_memory.h"
#include "los_atomic.h"
#include "los_task.h"
#include "lwip/sockets.h"
#else
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <math.h>
#include "securec.h"
#include "securectype.h"

#else

#include <WinSock2.h>
#include <windows.h>
#include <WinBase.h>
#include <Ws2tcpip.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <process.h>
#include <windows.h>
#include <math.h>

#include <tchar.h>
#include "securec.h"
#include "securectype.h"


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
extern "C" {
#endif

#ifdef FILLP_WIN32
LARGE_INTEGER g_fillpBasePerformanceFrequency;
#endif

#ifdef FILLP_MAC
mach_port_t g_fillpMacSelf;
clock_serv_t g_sclock;
static mach_timebase_info_data_t g_macTimeBaseInfo;
#endif


#ifdef FILLP_LINUX
#if defined(FILLP_LW_LITEOS)
static FILLP_INT FillpSysAdptArchAtomicInc(SysArchAtomic *v, FILLP_INT val)
{
    return atomic_add_return(val, v);
}

static FILLP_BOOL FillpSysAdptArchAtomicIncAndTest(SysArchAtomic *v)
{
    return atomic_inc_return(v) == 0;
}

static FILLP_INT FillpSysAdptArchAtomicDec(SysArchAtomic *v, FILLP_INT val)
{
    return atomic_add_return(-val, v);
}

static FILLP_BOOL FillpSysAdptArchAtomicDecAndTest(SysArchAtomic *v)
{
    return (FILLP_BOOL)atomic_dec_and_test(v);
}

static FILLP_INT FillpSysAdptArchAtomicRead(SysArchAtomic *v)
{
    return atomic_read(v);
}

static FILLP_INT FillpSysAdptArchAtomicSet(SysArchAtomic *target, FILLP_INT newValue)
{
    return atomic_set(target, newValue);
}
#else
static FILLP_INT FillpSysAdptArchAtomicInc(SysArchAtomic *v, FILLP_INT val)
{
    return __sync_add_and_fetch(&v->counter, val);
}

static FILLP_BOOL FillpSysAdptArchAtomicIncAndTest(SysArchAtomic *v)
{
    return __sync_add_and_fetch(&v->counter, 1) == 0;
}

static FILLP_INT FillpSysAdptArchAtomicDec(SysArchAtomic *v, FILLP_INT val)
{
    return __sync_sub_and_fetch(&v->counter, val);
}

static FILLP_BOOL FillpSysAdptArchAtomicDecAndTest(SysArchAtomic *v)
{
    return __sync_sub_and_fetch(&v->counter, 1) == 0;
}

static FILLP_INT FillpSysAdptArchAtomicRead(SysArchAtomic *v)
{
    return v->counter;
}

static FILLP_INT FillpSysAdptArchAtomicSet(SysArchAtomic *target, FILLP_INT newValue)
{
    return target->counter = newValue;
}
#endif

#else

static FILLP_INT FillpSysAdptArchAtomicInc(SysArchAtomic *v, long value)
{
    return InterlockedExchangeAdd((LONG volatile *)(uintptr_t)v, value) + value;
}

static FILLP_BOOL FillpSysAdptArchAtomicIncAndTest(SysArchAtomic *v)
{
    return InterlockedIncrement((LONG volatile *)(uintptr_t)v) == 0;
}

static FILLP_INT FillpSysAdptArchAtomicDec(SysArchAtomic *v, long value)
{
    return InterlockedExchangeAdd((LONG volatile *)(uintptr_t)v, (-value)) - value;
}

static FILLP_BOOL FillpSysAdptArchAtomicDecAndTest(SysArchAtomic *v)
{
    return InterlockedDecrement((LONG volatile *)(uintptr_t)v) == 0;
}

static SysArchAtomic FillpSysAdptArchAtomicRead(SysArchAtomic *v)
{
    return *v;
}

static FILLP_INT FillpSysAdptArchAtomicSet(SysArchAtomic *target, IN FILLP_INT value)
{
    return InterlockedExchange((LONG volatile *)(uintptr_t)target, value);
}

#endif


/*******************************************************************************
    Adption     : FillpMemCalloc

    Description : Adp Adption if user has not registered the callback for malloc

    Input         :
                    nitems                   : Partition number
                    size: Requested size to be allocated

    Output       :None

    Return       : FILLP_NULL_PTR
 *******************************************************************************/
void *FillpMemCalloc(IN FILLP_UINT32 nitems, IN FILLP_UINT32 size)
{
    void *ptr;

    ptr = calloc((size_t)nitems, (size_t)size);
    return ptr;
}

void *FillpMemAlloc(IN FILLP_UINT32 size)
{
    void *ptr;

    ptr = malloc((size_t)size);
    return ptr;
}

/*******************************************************************************
    Adption     : FillpMemFree

    Description : Adp Adption if user has not registered the callback for free

    Input         :
                    addr                   : Base address of memory to be freed

    Output       :None

    Return       : FILLP_FAILURE
 *******************************************************************************/
void FillpMemFree(IN void *addr)
{
    if (addr != FILLP_NULL_PTR) {
        free(addr);
    }
}

void *FillpMemChr(IN FILLP_CONST void *s, IN FILLP_INT c, IN FILLP_SIZE_T n)
{
    if (s == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    return (memchr(s, c, n));
}

/*******************************************************************************
    Adption     : FillpStrLen

    Description : Adp function if user has not registered the callback for strlen

    Input         :
                    pSrc                    : String

    Output       :None

    Return       : FILLP_NULL_PTR
 *******************************************************************************/
FILLP_UINT32 FillpStrLen(IN FILLP_CHAR *str)
{
    if (str == FILLP_NULL_PTR) {
        return 0;
    }
    return (FILLP_UINT32)strlen(str);
}


/*******************************************************************************
    Function     : FillpAdpSelect

    Description : Adp function if user has not registered the callback for select

    Input         :

    Output       :

    Return       :
 *******************************************************************************/
FILLP_INT FillpSelect(
    IN FILLP_INT maxFd, /* fd value to be selected */
    IN void *rdFds, /* fd for read */
    IN void *wrFds, /* fd for write */
    IO void *exceptFds, /* fd for errors */
    IN void *timeout) /* max time for select to wait */
{
#if defined(FILLP_LW_LITEOS)
    return lwip_select(maxFd, rdFds, wrFds, exceptFds, timeout);
#else
    return select(maxFd, rdFds, wrFds, exceptFds, timeout);
#endif
}


void FillpFuncFdClr(
    IN FILLP_UINT sockFd, /* socket fd */
    IN FT_FD_SET clrFdSet)
{
    FD_CLR((int)sockFd, (fd_set *)clrFdSet);
}

void FillpFuncFdSet(
    IN FILLP_UINT sockFd, /* socket fd */
    IN FT_FD_SET setFd)
{
    FD_SET((int)sockFd, (fd_set *)setFd);
}

FILLP_INT FillpFuncFdIsSet(
    IN FILLP_INT sockFd, /* socket fd */
    IN FT_FD_SET isSetFd)
{
    return FD_ISSET(sockFd, (fd_set *)isSetFd);
}

FT_FD_SET FillpFuncCreateFdSet(void)
{
    return FillpMemCalloc(sizeof(fd_set), 1);
}

void FillpFuncDestroyFdSet(IN FT_FD_SET destroyFdSet)
{
    FillpMemFree(destroyFdSet);
}

FILLP_INT32 FillpFuncCopyFdSet(IO FT_FD_SET dstFdSet, IN FT_FD_SET srcFdSet)
{
    if ((dstFdSet == FILLP_NULL_PTR) || (srcFdSet == FILLP_NULL_PTR)) {
        return -1;
    }

    return memcpy_s(dstFdSet, sizeof(fd_set), srcFdSet, sizeof(fd_set));
}


/*******************************************************************************
    Function     : FillpRand

    Description : Adp function if user has not registered the callback for rand

 *******************************************************************************/
FILLP_UINT32 FillpRand(IN void)
{
    return (FILLP_UINT32)rand();
}

#ifdef FILLP_LINUX
static void *FillpThreadFun(void *param)
{
    struct ThreadParam *threadParam = (struct ThreadParam *)param;
    threadParam->func(threadParam->param);

    return 0;
}
#else

static unsigned int FILLP_STDCALL FillpThreadFun(void *param)
{
    struct ThreadParam *threadParam = (struct ThreadParam *)param;
    threadParam->func(threadParam->param);

    return 0;
}


#endif

/*******************************************************************************
    Function     : FillpCreateThread

    Description : Adp function if user has not registered the callback for create thread

 *******************************************************************************/
FILLP_INT FillpCreateThread(IN void *param, IO void *threadId)
{
#ifdef FILLP_LINUX

    return pthread_create((pthread_t *)threadId, FILLP_NULL_PTR, FillpThreadFun, (void *)param);
#else /* for Windows */

    _beginthreadex(FILLP_NULL_PTR, 0, FillpThreadFun, param, 0, threadId);
    return 0;

#endif
}


/*******************************************************************************
    Function     : FillpSysArchInit

    Description : Adp function if user has not registered the callback for  initializing the
                       use of the Winsock DLL by a process

 *******************************************************************************/

#if defined(FILLP_LINUX) && defined(FILLP_MAC)

#define FillpSysArchGetCurTime(time) (*(time) = mach_absolute_time())

FILLP_LLONG FillpSysArchTimeToLonglong(FILLP_CONST FillpSysArchTime *time)
{
    if (g_macTimeBaseInfo.denom == 0) {
        return 0;
    }
    FILLP_LLONG l_time = (((*time) * g_macTimeBaseInfo.numer) / (g_macTimeBaseInfo.denom * FILLP_CONST_1K));
    return l_time;
}

#elif defined(FILLP_LINUX)

#define FillpSysArchGetCurTime(time) (void)clock_gettime(CLOCK_MONOTONIC, time)

FILLP_LLONG FillpSysArchTimeToLonglong(FILLP_CONST FillpSysArchTime *ptime)
{
    FILLP_LLONG l_time = ((FILLP_LLONG)ptime->tv_sec) * FILLP_CONST_1M + (ptime->tv_nsec / FILLP_CONST_1K);
    return l_time;
}


#elif defined(FILLP_WIN32)

void FillpSysArchInitTime()
{
    (void)QueryPerformanceFrequency(&g_fillpBasePerformanceFrequency);
    g_fillpBasePerformanceFrequency.QuadPart /= FILLP_CONST_10K;
}

void FillpSysArchGetCurTime(FillpSysArchTime *timeValue)
{
    /* Windows 2000 and later. ---------------------------------- */
    QueryPerformanceCounter(&(timeValue->time));
}

FILLP_LLONG FillpSysArchTimeToLonglong(FILLP_CONST FillpSysArchTime *timeValue)
{
    if (g_fillpBasePerformanceFrequency.QuadPart == 0) {
        return 0;
    }

    return ((FILLP_LLONG)(timeValue->time.QuadPart * FILLP_CONST_100) / g_fillpBasePerformanceFrequency.QuadPart);
}

#endif


FILLP_LLONG FillpSysAdaptArchGetCurTimeLonglong()
{
    FillpSysArchTime timeValue;
    FillpSysArchGetCurTime(&timeValue);
    return FillpSysArchTimeToLonglong(&timeValue);
}

FILLP_INT FillpSysArchInit(IN void)
{
#ifdef FILLP_LINUX

    return ERR_OK;

#else /* for Windows */

    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(FILLP_CONST_2, FILLP_CONST_2);
    if (WSAStartup(sockVersion, &wsaData) != 0) {
        return ERR_FAILURE;
    }
    FillpSysArchInitTime();
    return ERR_OK;

#endif
}

/*******************************************************************************
    Function     : FillpAdpSysArcGetCurTime

    Description : Adp function if user has not registered the callback for getting system current time
 *******************************************************************************/
FILLP_LLONG FillpSysArchGetCurTimeLonglong(IN void)
{
    return FillpSysAdaptArchGetCurTimeLonglong();
}


/*******************************************************************************
    Function     : FillpSysArchAtomicInc

    Description : Adp function if user has not registered the callback for increment the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicInc(IO SysArchAtomic *var, FILLP_INT val)
{
    return FillpSysAdptArchAtomicInc(var, val);
}

/*******************************************************************************
    Function     : FillpSysArchAtomicIncAndTest

    Description : Adp function if user has not registered the callback for increment and test the value
 *******************************************************************************/
FILLP_BOOL FillpSysArchAtomicIncAndTest(IO SysArchAtomic *var)
{
    return FillpSysAdptArchAtomicIncAndTest(var);
}

/*******************************************************************************
    Function     : FillpSysArchAtomicDec

    Description : Adp function if user has not registered the callback for decrement the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicDec(IO SysArchAtomic *var, FILLP_INT val)
{
    return FillpSysAdptArchAtomicDec(var, val);
}

/*******************************************************************************
    Function     : FillpSysArchAtomicDecAndTest

    Description : Adp function if user has not registered the callback for decrement and test the value
 *******************************************************************************/
FILLP_BOOL FillpSysArchAtomicDecAndTest(IO SysArchAtomic *var)
{
    return FillpSysAdptArchAtomicDecAndTest(var);
}

/*******************************************************************************
    Function     : FillpSysArchAtomicDec

    Description : Adp function if user has not registered the callback for read the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicRead(IO SysArchAtomic *var)
{
    return FillpSysAdptArchAtomicRead(var);
}

/*******************************************************************************
    Function     : FillpSysArchAtomicSet

    Description : Adp function if user has not registered the callback for automatic exchange the value
 *******************************************************************************/
FILLP_INT FillpSysArchAtomicSet(IN SysArchAtomic *var, FILLP_INT newValue)
{
    return FillpSysAdptArchAtomicSet(var, newValue);
}

/*******************************************************************************
    Function     : FillpSysArchCompAndWwap

    Description : Adp function if user has not registered the callback for compare and swap a value
 *******************************************************************************/
FILLP_INT FillpSysArchCompAndWwap(
    IO volatile FILLP_ULONG *sem,
    IN volatile FILLP_ULONG oldValue,
    IN volatile FILLP_ULONG exchange)
{
#ifdef FILLP_LINUX
    return (FILLP_INT)__sync_bool_compare_and_swap(sem, (FILLP_LLONG)(FILLP_ULLONG)oldValue,
        (FILLP_LLONG)(FILLP_ULLONG)exchange);
#else /* for Windows */
    return ((InterlockedCompareExchange((LONG volatile *)sem, (LONG)exchange, (LONG)oldValue)) == (LONG)oldValue);
#endif
}

/*******************************************************************************
    Function     : FillpSysSleepMs

    Description : Adp function if user has not registered the callback for sleep
 *******************************************************************************/
#ifdef FILLP_LINUX
/* use nanosleep as usleep is Obsolete by CC */
#define FILLP_ADP_SLEEP_MS(_ms) do  { \
    struct timespec delay; \
    delay.tv_sec = (_ms) / FILLP_CONST_1K; \
    delay.tv_nsec = ((_ms) % FILLP_CONST_1K) * FILLP_CONST_1K * FILLP_CONST_1K; \
    (void) nanosleep (&delay, FILLP_NULL_PTR); \
} while (0)

#else

#define FILLP_ADP_SLEEP_MS(a) Sleep(a)

#endif

void FillpSysSleepMs(IN FILLP_UINT timeValue) /* In Millseconds */
{
    FILLP_ADP_SLEEP_MS(timeValue);
}

FILLP_INT FillpSysSleepUs(IN FILLP_UINT timeValue) /* In micro seconds */
{
#ifdef FILLP_LINUX
    struct timespec tmsp;
    tmsp.tv_sec = timeValue / FILLP_CONST_1M;
    tmsp.tv_nsec = (timeValue % FILLP_CONST_1M) * FILLP_CONST_1K;
    return nanosleep(&tmsp, FILLP_NULL_PTR);
#else
    FILLP_UNUSED_PARA(timeValue);
    return 0;
#endif
}


/*******************************************************************************
    Function     : FillpAdpRtePause

    Description : Adp function if user has not registered the callback for pause
 *******************************************************************************/
void FillpAdpRtePause(void)
{
#ifdef FILLP_LINUX
    (void)sleep(0);
#endif
}

#ifdef FILLP_LINUX

#define FILLP_ADAPT_SYS_ARCH_SEM_COND_INIT(sem, value) do { \
    pthread_condattr_t attr; \
    (void)pthread_condattr_init(&attr); \
    (void)pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
    (void)pthread_cond_init(&(sem)->cond, &attr); \
    (void)pthread_condattr_destroy(&attr); \
    (sem)->counter = (FILLP_INT)(value); \
} while (0)

#define FILLP_ADAPT_SYS_ARCH_SEM_INIT(sem, value, ret) do { \
    if (pthread_mutex_init(&(sem)->mutex, FILLP_NULL_PTR) == 0) { \
        FILLP_ADAPT_SYS_ARCH_SEM_COND_INIT(sem, value); \
        (ret) = FILLP_OK; \
    } else { \
        (ret) = ERR_NULLPTR; \
    } \
} while (0)

#else

#define FILLP_ADAPT_SYS_ARCH_SEM_INIT(sem, value, ret) do {                           \
        HANDLE tempSem = CreateSemaphore(FILLP_NULL_PTR, (FILLP_SLONG)(value),        \
            0xffffff, FILLP_NULL_PTR);                                                \
        if (tempSem == FILLP_NULL_PTR) {                                              \
            (ret) = ERR_NULLPTR;                                                      \
        } else {                                                                      \
            *(sem) = tempSem;                                                         \
            (ret) = FILLP_OK;                                                         \
        }                                                                             \
    } while (0)

#endif

/*******************************************************************************
    Function     : FillpArchInitSem

    Description : Adp function if user has not registered the callback for semaphore init
 *******************************************************************************/
FILLP_INT FillpArchInitSem(IO SYS_ARCH_SEM *sem, IN FILLP_ULONG value)
{
#ifndef FILLP_MAC
    FILLP_INT ret;
    FILLP_ADAPT_SYS_ARCH_SEM_INIT(sem, value, ret);
    return ret;
#endif

#ifdef FILLP_MAC
    kern_return_t ret;
    ret = semaphore_create(g_fillpMacSelf, sem, SYNC_POLICY_FIFO, value);

    return ret;
#endif
}

#ifdef FILLP_LINUX
#define FILLP_ADAPT_SYS_ARCH_SEM_TRYWAIT(sem) sem_trywait(sem)

#define FILLP_ADAPT_SYS_ARCH_SEM_WAIT(sem) sem_wait(sem)

#define FILLP_ADAPT_SYS_ARCH_SEM_POST(sem) sem_post(sem)

#define FILLP_ADAPT_SYS_ARCH_SEM_DESTROY(sem) sem_destroy(sem)

#if defined(FILLP_LW_LITEOS)
staic FillpErrorType FillpAdaptSysArchRwsemInit(SYS_ARCH_RW_SEM *sem)
{
    int ret = pthread_mutex_init(&sem->readMutex, FILLP_NULL_PTR);
    if (ret != 0) {
        return ERR_PARAM;
    }
    ret = pthread_mutex_init(&sem->writeMutex, FILLP_NULL_PTR);
    if (ret != 0) {
        (void)pthread_mutex_destroy(&sem->readMutex);
        return ERR_PARAM;
    }
    sem->readCount = 0;
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemTryrdwait(SYS_ARCH_RW_SEM *sem)
{
    int ret = pthread_mutex_trylock(&sem->readMutex);
    if (ret != 0) {
        return ERR_EAGAIN;
    }
    sem->readCount++;
    if (sem->readCount == 1) {
        ret = pthread_mutex_trylock(&sem->writeMutex);
        if (ret != 0) {
            sem->readCount--;
            (void)pthread_mutex_unlock(&sem->readMutex);
            return ERR_EAGAIN;
        }
    }
    (void)pthread_mutex_unlock(&sem->readMutex);
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemRdPost(SYS_ARCH_RW_SEM *sem)
{
    int ret = pthread_mutex_lock(&sem->readMutex);
    if (ret != 0) {
        return ERR_PARAM;
    }
    sem->readCount--;
    if (sem->readCount == 0) {
        (void)pthread_mutex_unlock(&sem->writeMutex);
    }
    (void)pthread_mutex_unlock(&sem->readMutex);
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemTrywrwait(SYS_ARCH_RW_SEM *sem)
{
    int ret = pthread_mutex_trylock(&sem->writeMutex);
    if (ret != 0) {
        return ERR_EAGAIN;
    }
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemWrPost(SYS_ARCH_RW_SEM *sem)
{
    (void)pthread_mutex_unlock(&sem->writeMutex);
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemDestroy(SYS_ARCH_RW_SEM *sem)
{
    (void)pthread_mutex_destroy(&sem->readMutex);
    (void)pthread_mutex_destroy(&sem->writeMutex);
    sem->readCount = 0;
    return ERR_OK;
}

#else /* FILLP_LW_LITEOS */
#define FillpAdaptSysArchRwsemInit(sem) pthread_rwlock_init((sem), FILLP_NULL_PTR)

#define FillpAdaptSysArchRwsemTryrdwait(sem) pthread_rwlock_tryrdlock(sem)

#define FillpAdaptSysArchRwsemTrywrwait(sem) pthread_rwlock_trywrlock(sem)

#define FillpAdaptSysArchRwsemRdPost(sem) pthread_rwlock_unlock(sem)

#define FillpAdaptSysArchRwsemWrPost(sem) pthread_rwlock_unlock(sem) // The same with rdpost in linux

#define FillpAdaptSysArchRwsemDestroy(sem) pthread_rwlock_destroy(sem)
#endif /* FILLP_LW_LITEOS */

#else /* FILLP_LINUX */

#define FILLP_ADAPT_SYS_ARCH_SEM_WAIT(sem)      WaitForSingleObject(*(sem), 0xffffff)

#define FILLP_ADAPT_SYS_ARCH_SEM_TRYWAIT(sem)   WaitForSingleObject(*(sem), 0)

#define FILLP_ADAPT_SYS_ARCH_SEM_POST(sem)      ReleaseSemaphore(*(sem), 1, FILLP_NULL_PTR)

#define FILLP_ADAPT_SYS_ARCH_SEM_DESTROY(sem)   CloseHandle(*(sem))


#define SYS_ARCH_RWSEM_RD_LOCK_STEP 0x2
#define SYS_ARCH_RWSEM_WR_LOCK_FLAG 0x01

#define CAS(sem, oldValue, newValue) FillpSysArchCompAndWwap((sem), (oldValue), (newValue))

static FillpErrorType FillpAdaptSysArchRwsemInit(SYS_ARCH_RW_SEM *sem)
{
    sem->sem = 0x0;
    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemTryrdwait(SYS_ARCH_RW_SEM *sem)
{
    FILLP_ULONG oldValue;
    FILLP_ULONG nextValue;

    do {
        oldValue = sem->sem;
        if (oldValue & SYS_ARCH_RWSEM_WR_LOCK_FLAG) { // Write lock
            return ERR_FAILURE;
        }
        nextValue = oldValue + SYS_ARCH_RWSEM_RD_LOCK_STEP;
    } while (!CAS(&sem->sem, oldValue, nextValue));
    return ERR_OK;
}


static FillpErrorType FillpAdaptSysArchRwsemTrywrwait(SYS_ARCH_RW_SEM *sem)
{
    FILLP_ULONG oldValue;
    FILLP_ULONG nextValue;

    do {
        oldValue = sem->sem;
        if (oldValue != 0x0) {
            return ERR_FAILURE;
        }
        nextValue = oldValue | SYS_ARCH_RWSEM_WR_LOCK_FLAG;
    } while (!CAS(&sem->sem, oldValue, nextValue));

    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemRdPost(SYS_ARCH_RW_SEM *sem)
{
    FILLP_ULONG oldValue;
    FILLP_ULONG nextValue;

    do {
        oldValue = sem->sem;
        nextValue = oldValue - SYS_ARCH_RWSEM_RD_LOCK_STEP;
    } while (!CAS(&sem->sem, oldValue, nextValue));

    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemWrPost(SYS_ARCH_RW_SEM *sem)
{
    FILLP_ULONG oldValue;
    FILLP_ULONG nextValue;

    do {
        oldValue = sem->sem;
        nextValue = oldValue & (~SYS_ARCH_RWSEM_WR_LOCK_FLAG);
    } while (!CAS(&sem->sem, oldValue, nextValue));

    return ERR_OK;
}

static FillpErrorType FillpAdaptSysArchRwsemDestroy(SYS_ARCH_RW_SEM *sem)
{
    if (sem->sem != 0x0) {
        return ERR_FAILURE;
    }

    return ERR_OK;
}

#endif /* FILLP_LINUX */

/*******************************************************************************
    Function     : FillpSemTryWait

    Description : Adp function if user has not registered the callback for semaphore try wait
 *******************************************************************************/
FILLP_INT FillpSemTryWait(IN SYS_ARCH_SEM *sem)
{
#ifndef FILLP_MAC
#ifdef FILLP_LINUX
    FILLP_INT ret;

    if (pthread_mutex_trylock(&sem->mutex) != 0) {
        return -1;
    }
    if (sem->counter > 0) {
        sem->counter--;
        ret = 0;
    } else {
        ret = -1;
    }
    (void)pthread_mutex_unlock(&sem->mutex);
    return ret;
#else
    return (FILLP_INT)FILLP_ADAPT_SYS_ARCH_SEM_TRYWAIT(sem);
#endif
#else
    /* sem try wait is not implemented in MAC, so simulate it using sem timeout
         Below timeout value is arrive by doing the throughput test in 2 mthods:
         a) Test by registering normal semaphore_wait
         b) Test by registering semaphore_timedwait with timeout value
    */
    mach_timespec_t mts;
    FILLP_SLONG timeout = 1;
    mts.tv_sec = 0;
    mts.tv_nsec = 0;
    clock_get_time(g_sclock, &mts);

    mts.tv_sec += timeout / FILLP_CONST_1K;
    mts.tv_nsec += (timeout % FILLP_CONST_1K) * FILLP_CONST_1M;

    return semaphore_timedwait(*sem, mts);

#endif
}

/*******************************************************************************
    Function     : FillpSemWait

    Description : Adp function if user has not registered the callback for semaphore wait
 *******************************************************************************/
FILLP_INT FillpSemWait(IN SYS_ARCH_SEM *sem)
{
#ifndef FILLP_MAC
#ifdef FILLP_LINUX
    if (pthread_mutex_lock(&sem->mutex) != 0) {
        return -1;
    }
    while (sem->counter <= 0) {
        if (pthread_cond_wait(&sem->cond, &sem->mutex) != 0) {
            (void)pthread_mutex_unlock(&sem->mutex);
            return -1;
        }
    }
    sem->counter--;
    (void)pthread_mutex_unlock(&sem->mutex);
    return 0;
#else
    return (FILLP_INT)FILLP_ADAPT_SYS_ARCH_SEM_WAIT(sem);
#endif
#else
    kern_return_t ret;
    ret = semaphore_wait(*sem);
    return ret;
#endif
}


/*******************************************************************************
    Function     : FillpSemPost

    Description : Adp function if user has not registered the callback for semaphore post
 *******************************************************************************/
FILLP_INT FillpSemPost(IN SYS_ARCH_SEM *sem)
{
#ifndef FILLP_MAC
#ifdef FILLP_LINUX
    if (pthread_mutex_lock(&sem->mutex) != 0) {
        return -1;
    }
    sem->counter++;
    (void)pthread_cond_signal(&sem->cond);
    (void)pthread_mutex_unlock(&sem->mutex);
    return 0;
#else
    return (FILLP_ADAPT_SYS_ARCH_SEM_POST(sem) == 0);
#endif
#else
    kern_return_t ret;
    ret = semaphore_signal(*sem);
    return ret;
#endif
}

/*******************************************************************************
    Function     : FillpSemDestroy

    Description : Adp function if user has not registered the callback for semaphore destroy
 *******************************************************************************/
FILLP_INT FillpSemDestroy(IN SYS_ARCH_SEM *sem)
{
#ifndef FILLP_MAC
#ifdef FILLP_LINUX
    FILLP_INT ret = pthread_mutex_lock(&(sem->mutex));
    if (ret != 0) {
        return -1;
    }

    if (pthread_cond_destroy(&(sem->cond)) != 0) {
        ret = -1;
    }
    if (pthread_mutex_unlock(&(sem->mutex)) != 0) {
        ret = -1;
    }
    if (pthread_mutex_destroy(&(sem->mutex)) != 0) {
        ret = -1;
    }
    return ret;
#else
    return FILLP_ADAPT_SYS_ARCH_SEM_DESTROY(sem);
#endif
#else
    kern_return_t ret;
    ret = semaphore_destroy(g_fillpMacSelf, *sem);
    return ret;
#endif
}

static FILLP_INT FillpArchInitRwSem(IO SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemInit(sem);
}


FILLP_INT FillpRwSemTryRdWait(IN SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemTryrdwait(sem);
}

FILLP_INT FillpRwSemTryWrWait(IN SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemTrywrwait(sem);
}

/*******************************************************************************
    Function     : FillpRwSemDestroy

    Description : Adp function if user has not registered the callback for semaphore destroy
 *******************************************************************************/
FILLP_INT FillpRwSemDestroy(IN SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemDestroy(sem);
}

/*******************************************************************************
    Function     : FillpRwSemWrPost

    Description : Adp function if user has not registered the callback for semaphore post
 *******************************************************************************/
FILLP_INT FillpRwSemWrPost(IN SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemWrPost(sem);
}

/*******************************************************************************
    Function     : FillpRwSemRdPost

    Description : Adp function if user has not registered the callback for semaphore post
 *******************************************************************************/
FILLP_INT FillpRwSemRdPost(IN SYS_ARCH_RW_SEM *sem)
{
    return FillpAdaptSysArchRwsemRdPost(sem);
}


/*******************************************************************************
    Function     : FillpFuncCreateSocket

    Description : Adp function if user has not registered the Create socket callback
 *******************************************************************************/
FILLP_INT32  FillpFuncCreateSocket(
    IN FILLP_INT32 domain,   /* the address family */
    IN FILLP_INT32 type,     /* new socket */
    IN FILLP_INT32 protocol) /* protocol to be used */
{
    return (FILLP_INT32)socket((int)domain, (int)type, (int)protocol);
}

/*******************************************************************************
    Function     : FillpFuncBindSocket

    Description : Adp function if user has not registered the Bind socket callback function
 *******************************************************************************/
FILLP_INT32 FillpFuncBindSocket(
    IN FILLP_INT32 sockFd, /* socket fd */
    IN FILLP_CONST void *myAddr, /* bind addr */
    IN FILLP_INT32 addrLen) /* addr length */
{
    return (FILLP_INT32)bind(sockFd, myAddr, (socklen_t)addrLen);
}

FILLP_INT32 FillpFuncConnectSocket(
    IN FILLP_INT32 sockFd,       /* socket fd */
    IN FILLP_CONST void *myAddr, /* bind addr */
    IN FILLP_INT32 addrLen)      /* addr length */
{
    return connect(sockFd, myAddr, (socklen_t)addrLen);
}

FILLP_INT32 FillpFuncGetSockName(
    IN FILLP_INT32 sockFd, /* socket fd */
    IN void *myAddr,       /* bind addr */
    IN void *addrLen)      /* addr length */
{
#ifdef FILLP_WIN32
    return getsockname(sockFd, (struct sockaddr *)myAddr, (int *)addrLen);
#else
    return getsockname(sockFd, (struct sockaddr *)myAddr, (socklen_t *)addrLen);
#endif
}


FILLP_INT FillpFuncIoCtlSocket(FILLP_INT fd, FILLP_INT type, FILLP_ULONG *parg)
{
#ifdef FILLP_WIN32
    return ioctlsocket(fd, type, (FILLP_ULONG *)parg);
#else
    return ioctl(fd, (FILLP_ULONG)type, parg);

#endif
}


FILLP_INT FillpFuncFcntl(
    IN FILLP_INT fd,  /* connection fd */
    IN FILLP_INT cmd, /* command to perform on socket */
    IN FILLP_INT val) /* arguments for socket */
{
#if defined(FILLP_LW_LITEOS)
    return lwip_fcntl(fd, cmd, val);
#elif defined(FILLP_WIN32)
    FILLP_UNUSED_PARA(fd);
    FILLP_UNUSED_PARA(cmd);
    FILLP_UNUSED_PARA(val);
    return 0;
#else
    return fcntl(fd, cmd, val);
#endif
}

FILLP_INT FillpFuncSetSockOpt(IN FILLP_INT sockFd, IN FILLP_INT level, IN FILLP_INT optName,
    IN FILLP_CONST void *optVal, IN FILLP_INT optLen)
{
    return setsockopt(sockFd, level, optName, optVal, (socklen_t)optLen);
}

FILLP_INT FillpFuncGetSockOpt(IN FILLP_INT sockFd, IN FILLP_INT level, IN FILLP_INT optName, IO void *optVal,
    IO FILLP_INT *optLen)
{
#ifdef FILLP_WIN32
    return getsockopt(sockFd, level, optName, (char *)optVal, (int *)optLen);
#else
    return getsockopt(sockFd, level, optName, optVal, (socklen_t *)optLen);
#endif
}


/*******************************************************************************
    Function     : FillpFuncCloseSocket

    Description : Adp function if user has not registered the close socket callback function
 *******************************************************************************/
FILLP_INT32 FillpFuncCloseSocket(IN FILLP_INT32 sockFd)
{
#ifdef FILLP_LINUX

    return close(sockFd);

#else /* For Windows */

    return closesocket(sockFd);

#endif
}

/*******************************************************************************
    Function     : FillpFuncSendTo

    Description : Adp function if user has not registered the sendto callback function
 *******************************************************************************/
FILLP_INT FillpFuncSendTo(IN FILLP_INT sockFd, IN const void *buf, IN FILLP_SIZE_T len, IN FILLP_INT flags,
    IN const void *to, IN FILLP_SIZE_T toLen)
{
#ifdef FILLP_WIN64
    return (FILLP_INT)sendto(sockFd, buf, (FILLP_INT)len, flags, to, (socklen_t)toLen);
#else
    return (FILLP_INT)sendto(sockFd, buf, len, flags, to, (socklen_t)toLen);
#endif
}

/*******************************************************************************
    Function     : FillpFuncRecvFrom
    Description  : Adp function if user has not registered the receive from callback function
 *******************************************************************************/
FILLP_INT FillpFuncRecvFrom(IN FILLP_INT sockFd, OUT void *buf, IN FILLP_SIZE_T len, IN FILLP_INT flags,
    OUT void *from, IO FILLP_SIZE_T *fromLen)
{
#ifdef FILLP_WIN32
#ifdef FILLP_WIN64
    return (FILLP_INT)recvfrom(sockFd, buf, (int)len, flags, (struct sockaddr *)from, (int *)fromLen);
#else
    return (FILLP_INT)recvfrom(sockFd, buf, len, flags, (struct sockaddr *)from, (int *)fromLen);
#endif
#else
    return (FILLP_INT)recvfrom(sockFd, buf, len, flags, from, (socklen_t *)fromLen);
#endif
}

FILLP_INT FillpFuncSend(
    IN FILLP_INT sockFd,   /* Connection fd */
    IN const void *buffer, /* buffer to hold data to be sent */
    IN FILLP_INT len,      /* no of bytes to be sent */
    IN FILLP_INT flags)    /* flags to tell the status */
{
    return (FILLP_INT)send(sockFd, buffer, (FILLP_SIZE_T)(unsigned int)len, flags);
}

#ifdef FILLP_LINUX
FILLP_INT FillpAdaptSysArchSemClose(SYS_ARCH_SEM *sem)
{
#ifndef FILLP_MAC
    return FillpSemDestroy(sem);
#endif

    /* Once inited with semaphore_create() in callback sysArchSemInit, it will be destroyed
        semaphore_destroy() in sysArchSemDestroy. here is no semaphore_close() in MAC
    */
#ifdef FILLP_MAC
    FILLP_UNUSED_PARA(sem);
    return FILLP_SUCCESS;
#endif
}

#else

FILLP_INT FillpAdaptSysArchSemClose(SYS_ARCH_SEM *sem)
{
    return CloseHandle(*sem);
}

#endif

/* callback for sys_arch_named_sem_close */
FILLP_INT FillpSysArchSemClose(SYS_ARCH_SEM *sem)
{
    return FillpAdaptSysArchSemClose(sem);
}

#ifdef FILLP_LINUX
static FILLP_INT FillpAdaptSysArchSemWaitTimeout(SYS_ARCH_SEM *sem, FILLP_SLONG timeout)
{
#ifndef FILLP_MAC
    FILLP_LLONG start;
    FILLP_LLONG end;
    FillpSysArchTime timeValue;

    (void)clock_gettime(CLOCK_MONOTONIC, &timeValue);
    start = FillpSysArchTimeToLonglong(&timeValue);
    end = start + (timeout * FILLP_CONST_1K);
    timeValue.tv_sec = (time_t)(end / FILLP_CONST_1M);
    timeValue.tv_nsec = (long)((end % FILLP_CONST_1M) * FILLP_CONST_1K);

    if (pthread_mutex_lock(&sem->mutex) != 0) {
        return -1;
    }
    while (sem->counter <= 0) {
        if (pthread_cond_timedwait(&sem->cond, &sem->mutex, &timeValue) != 0) {
            (void)pthread_mutex_unlock(&sem->mutex);
            return -1;
        }
    }
    sem->counter--;
    (void)pthread_mutex_unlock(&sem->mutex);
    return 0;

#endif

#ifdef FILLP_MAC
    mach_timespec_t mts;
    mts.tv_sec = 0;
    mts.tv_nsec = 0;
    clock_get_time(g_sclock, &mts);

    mts.tv_sec += timeout / FILLP_CONST_1K;
    mts.tv_nsec += (timeout % FILLP_CONST_1K) * FILLP_CONST_1M;

    return semaphore_timedwait(*sem, mts);
#endif
}

#else

FILLP_INT FillpAdaptSysArchSemWaitTimeout(SYS_ARCH_SEM *sem, FILLP_SLONG timeout)
{
    DWORD ret = WaitForSingleObject(*sem, timeout);
    if (ret == WAIT_TIMEOUT) {
        return ERR_OK;
    } else {
        return ERR_COMM;
    }
}

FILLP_INT FillpAdaptSysArchSemTryWait(SYS_ARCH_SEM *sem, FILLP_SLONG timeout)
{
    return WaitForSingleObject(*sem, timeout);
}

#endif

/* callback for sys_arch_named_sem_wait_timeout */
FILLP_INT FillpSysArchSemWaitTimeout(SYS_ARCH_SEM *sem, FILLP_SLONG timeout)
{
    return FillpAdaptSysArchSemWaitTimeout(sem, timeout);
}

static FILLP_INT FillpSysArchSchedYield(void)
{
#ifdef FILLP_LINUX
#if defined(FILLP_LW_LITEOS)
    return LOS_TaskYield();
#else
    return sched_yield();
#endif
#else
    return FILLP_SUCCESS;
#endif
}

#if defined(FILLP_MAC)
void FillpSysOsInit(IN void)
{
    g_fillpMacSelf = mach_task_self();
    host_get_clock_service(g_fillpMacSelf, SYSTEM_CLOCK, &g_sclock);
    (void)mach_timebase_info(&g_macTimeBaseInfo);
}
#elif defined(FILLP_WIN32)
void FillpSysOsInit(IN void)
{
    FillpSysArchInitTime();
}
#else
#define FillpSysOsInit()
#endif

#if defined(FILLP_MAC)
void FillpSysOsDeinit(IN void)
{
    mach_port_deallocate(g_fillpMacSelf, g_sclock);
}
#else
void FillpSysOsDeinit(IN void)
{
    return;
}
#endif

static void FillpRegBasicFun(void)
{
    /* Basic Os function Registration start */
    g_fillpOsBasicLibFun.memCalloc = FillpMemCalloc;
    g_fillpOsBasicLibFun.memAlloc = FillpMemAlloc;
    g_fillpOsBasicLibFun.memFree = FillpMemFree;
    g_fillpOsBasicLibFun.memChr = FillpMemChr;
    g_fillpOsBasicLibFun.fillpStrLen = FillpStrLen;
    g_fillpOsBasicLibFun.fillpRand = FillpRand;
    g_fillpOsBasicLibFun.fillpCreateThread = FillpCreateThread;
    g_fillpOsBasicLibFun.sysArcInit = FillpSysArchInit;
    g_fillpOsBasicLibFun.sysArcGetCurTimeLongLong = FillpSysArchGetCurTimeLonglong;
    g_fillpOsBasicLibFun.sysArchAtomicInc = FillpSysArchAtomicInc;
    g_fillpOsBasicLibFun.sysArchAtomicIncAndTest = FillpSysArchAtomicIncAndTest;
    g_fillpOsBasicLibFun.sysArchAtomicDec = FillpSysArchAtomicDec;
    g_fillpOsBasicLibFun.sysArchAtomicDecAndTest = FillpSysArchAtomicDecAndTest;
    g_fillpOsBasicLibFun.sysArchAtomicRead = FillpSysArchAtomicRead;
    g_fillpOsBasicLibFun.sysArchAtomicSet = FillpSysArchAtomicSet;
    g_fillpOsBasicLibFun.sysArchCompAndSwap = FillpSysArchCompAndWwap;
    g_fillpOsBasicLibFun.sysSleepMs = FillpSysSleepMs;
    g_fillpOsBasicLibFun.sysUsleep = FillpSysSleepUs;
    g_fillpOsBasicLibFun.rtePause = FillpAdpRtePause;
    /* product MUST register for this, there is no default callback function for this */
    g_fillpOsBasicLibFun.cryptoRand = FILLP_NULL_PTR;

    /* Semaphore function Registration start */
    g_fillpOsSemLibFun.sysArchSemClose = FillpSysArchSemClose;
    g_fillpOsSemLibFun.sysArchSemInit = FillpArchInitSem;
    g_fillpOsSemLibFun.sysArchSemTryWait = FillpSemTryWait;
    g_fillpOsSemLibFun.sysArchSemWait = FillpSemWait;
    g_fillpOsSemLibFun.sysArchSemPost = FillpSemPost;
    g_fillpOsSemLibFun.sysArchSemDestroy = FillpSemDestroy;
    g_fillpOsSemLibFun.sysArchSemWaitTimeout = FillpSysArchSemWaitTimeout;
    g_fillpOsSemLibFun.sysArchRWSemInit = FillpArchInitRwSem;
    g_fillpOsSemLibFun.sysArchRWSemTryRDWait = FillpRwSemTryRdWait;
    g_fillpOsSemLibFun.sysArchRWSemTryWRWait = FillpRwSemTryWrWait;
    g_fillpOsSemLibFun.sysArchRWSemRDPost = FillpRwSemRdPost;
    g_fillpOsSemLibFun.sysArchRWSemWRPost = FillpRwSemWrPost;
    g_fillpOsSemLibFun.sysArchRWSemDestroy = FillpRwSemDestroy;
    g_fillpOsSemLibFun.sysArchSchedYield = FillpSysArchSchedYield;
}

/*******************************************************************************
    Function     : FillpRegAdpLibSysFunc

    Des            : Adaptor function
    Input         : None


    Output       :None

    Return       :None
 *******************************************************************************/
void FillpRegLibSysFunc(IN void)
{
    FillpSysOsInit();

    FillpRegBasicFun();

    /* Socket function registration Start */
    g_fillpOsSocketLibFun.socketCallbackFunc = FillpFuncCreateSocket;
    g_fillpOsSocketLibFun.select = FillpSelect;
    g_fillpOsSocketLibFun.bindCallbackFunc = FillpFuncBindSocket;
    g_fillpOsSocketLibFun.closeSocketCallbackFunc = FillpFuncCloseSocket;
    g_fillpOsSocketLibFun.recvFromCallbackFunc = FillpFuncRecvFrom;
    g_fillpOsSocketLibFun.sendtoCallbackFunc = FillpFuncSendTo;
    g_fillpOsSocketLibFun.ioctl = FillpFuncIoCtlSocket;
    g_fillpOsSocketLibFun.fcntl = FillpFuncFcntl;
    g_fillpOsSocketLibFun.setSockOpt = FillpFuncSetSockOpt;
    g_fillpOsSocketLibFun.getSockOpt = FillpFuncGetSockOpt;
    g_fillpOsSocketLibFun.sendCallbackFunc = FillpFuncSend;
    g_fillpOsSocketLibFun.getSockNameCallbackFunc = FillpFuncGetSockName;
    g_fillpOsSocketLibFun.connectCallbackFunc = FillpFuncConnectSocket;
    g_fillpOsSocketLibFun.fillpFuncFdClr = FillpFuncFdClr;
    g_fillpOsSocketLibFun.fillpFuncFdSet = FillpFuncFdSet;
    g_fillpOsSocketLibFun.fillpFuncFdIsSet = FillpFuncFdIsSet;
    g_fillpOsSocketLibFun.fillpFuncCreateFdSet = FillpFuncCreateFdSet;
    g_fillpOsSocketLibFun.fillpFuncDestroyFdSet = FillpFuncDestroyFdSet;
    g_fillpOsSocketLibFun.fillpFuncCopyFdSet = FillpFuncCopyFdSet;

    /* Other function registration Start */
    g_fillpAppCbkFun.fillpSockCloseCbkFunc = FILLP_NULL_PTR;
}

#ifdef __cplusplus
}
#endif
