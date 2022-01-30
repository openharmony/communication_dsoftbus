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

#ifndef FILLP_FUNCTIONS_H
#define FILLP_FUNCTIONS_H

#include "fillp_os.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_FD_CLR   (g_fillpOsSocketLibFun.fillpFuncFdClr)
#define FILLP_FD_SET   (g_fillpOsSocketLibFun.fillpFuncFdSet)
#define FILLP_FD_ISSET (g_fillpOsSocketLibFun.fillpFuncFdIsSet)


#define FILLP_FD_CREATE_FD_SET   (g_fillpOsSocketLibFun.fillpFuncCreateFdSet)
#define FILLP_FD_DESTROY_FD_SET  (g_fillpOsSocketLibFun.fillpFuncDestroyFdSet)
#define FILLP_FD_COPY_FD_SET     (g_fillpOsSocketLibFun.fillpFuncCopyFdSet)


#define FILLP_GETSOCKOPT               (g_fillpOsSocketLibFun.getSockOpt)
#define FILLP_SETSOCKOPT               (g_fillpOsSocketLibFun.setSockOpt)
#define FILLP_IOCTLSOCKET              (g_fillpOsSocketLibFun.ioctl)
#define FILLP_FCNTL                    (g_fillpOsSocketLibFun.fcntl)
#define FILLP_SOCKET                   (g_fillpOsSocketLibFun.socketCallbackFunc)
#define FILLP_BIND                     (g_fillpOsSocketLibFun.bindCallbackFunc)
#define FILLP_GETSOCKNAME              (g_fillpOsSocketLibFun.getSockNameCallbackFunc)
#define FILLP_CONNECT                  (g_fillpOsSocketLibFun.connectCallbackFunc)
#define FILLP_SENDTO                   (g_fillpOsSocketLibFun.sendtoCallbackFunc)
#define FILLP_SEND                     (g_fillpOsSocketLibFun.sendCallbackFunc)
#define FILLP_RECVFROM                 (g_fillpOsSocketLibFun.recvFromCallbackFunc)
#define FILLP_STRLEN                   (g_fillpOsBasicLibFun.fillpStrLen)
#define FILLP_CALLOC                   (g_fillpOsBasicLibFun.memCalloc)
#define FILLP_MALLOC                   (g_fillpOsBasicLibFun.memAlloc)
#define FILLP_FREE                     (g_fillpOsBasicLibFun.memFree)
#define FILLP_SELECT                   (g_fillpOsSocketLibFun.select)
#define FILLP_RAND                     (g_fillpOsBasicLibFun.fillpRand)
#define FILLP_CRYPTO_RAND              (g_fillpOsBasicLibFun.cryptoRand)
#define FILLP_CLOSE                    (g_fillpOsSocketLibFun.closeSocketCallbackFunc)
#define FILLP_MEMCHR                   (g_fillpOsBasicLibFun.memChr)
#define FILLP_SYS_START_NEWTHREAD      (g_fillpOsBasicLibFun.fillpCreateThread)
#define SYS_ARCH_INIT                  (g_fillpOsBasicLibFun.sysArcInit)
#define SYS_ARCH_GET_CUR_TIME_LONGLONG (g_fillpOsBasicLibFun.sysArcGetCurTimeLongLong)
#define CAS                            (g_fillpOsBasicLibFun.sysArchCompAndSwap)
#define FILLP_SLEEP_MS                 (g_fillpOsBasicLibFun.sysSleepMs)
#define FILLP_RTE_PAUSE                (g_fillpOsBasicLibFun.rtePause)
#define SYS_ARCH_ATOMIC_INC            (g_fillpOsBasicLibFun.sysArchAtomicInc)
#define SYS_ARCH_ATOMIC_INC_AND_TEST   (g_fillpOsBasicLibFun.sysArchAtomicIncAndTest)
#define SYS_ARCH_ATOMIC_DEC            (g_fillpOsBasicLibFun.sysArchAtomicDec)
#define SYS_ARCH_ATOMIC_DEC_AND_TEST   (g_fillpOsBasicLibFun.sysArchAtomicDecAndTest)
#define SYS_ARCH_ATOMIC_READ           (g_fillpOsBasicLibFun.sysArchAtomicRead)
#define SYS_ARCH_ATOMIC_SET            (g_fillpOsBasicLibFun.sysArchAtomicSet)
#define FILLP_USLEEP                   (g_fillpOsBasicLibFun.sysUsleep)

/* Once inited with semaphore_create() in callback sysArchSemInit, it will be destroyed
    semaphore_destroy() in sysArchSemDestroy. There is no semaphore_close() in MAC
*/
#ifndef FILLP_MAC
#define SYS_ARCH_SEM_CLOSE           (g_fillpOsSemLibFun.sysArchSemClose)
#endif

#define SYS_ARCH_SEM_INIT         (g_fillpOsSemLibFun.sysArchSemInit)
#define SYS_ARCH_SEM_TRYWAIT      (g_fillpOsSemLibFun.sysArchSemTryWait)
#define SYS_ARCH_SEM_WAIT         (g_fillpOsSemLibFun.sysArchSemWait)
#define SYS_ARCH_SEM_POST         (g_fillpOsSemLibFun.sysArchSemPost)
#define SYS_ARCH_SEM_DESTROY      (g_fillpOsSemLibFun.sysArchSemDestroy)
#define SYS_ARCH_SEM_WAIT_TIMEOUT (g_fillpOsSemLibFun.sysArchSemWaitTimeout)
#define SYS_ARCH_SCHED_YIELD      (g_fillpOsSemLibFun.sysArchSchedYield)

static inline void sys_arch_compiler_barrier(void)
{
#ifdef FILLP_LINUX
#if !defined(__clang__) && (((__GNUC__ <= 4) && (__GNUC_MINOR__ < 4)) || (__GNUC__ <= 3))
    #error "GCC 4.4.0 FIXED GCC Bug[36793] x86-64 does not get __sync_synchronize right"
#endif
    __sync_synchronize();
#else
    MemoryBarrier();
#endif
}

#define SYS_ARCH_RWSEM_INIT         (g_fillpOsSemLibFun.sysArchRWSemInit)
#define SYS_ARCH_RWSEM_TRYRDWAIT    (g_fillpOsSemLibFun.sysArchRWSemTryRDWait)
#define SYS_ARCH_RWSEM_TRYWRWAIT    (g_fillpOsSemLibFun.sysArchRWSemTryWRWait)
#define SYS_ARCH_RWSEM_RDPOST       (g_fillpOsSemLibFun.sysArchRWSemRDPost)
#define SYS_ARCH_RWSEM_WRPOST       (g_fillpOsSemLibFun.sysArchRWSemWRPost)
#define SYS_ARCH_RWSEM_DESTROY      (g_fillpOsSemLibFun.sysArchRWSemDestroy)
#define SYS_ARCH_RWSEM_WAIT_TIMEOUT (g_fillpOsSemLibFun.pfSysArchRWSemWaitTimeout)

#define FILLP_SOCKETCLOSE_CBK (g_fillpAppCbkFun.fillpSockCloseCbkFunc)

#ifdef __cplusplus
}
#endif

#endif /* FILLP_FUNCTIONS_H */
