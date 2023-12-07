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

#ifndef FILLP_OS_H
#define FILLP_OS_H

#include "fillptypes.h"
#include "fillpcallbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED
#define FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED 10
#endif

#define FILLP_INVALID_PTR(Ptr) (FILLP_NULL_PTR ==  (Ptr))

#ifdef FILLP_LITTLE_ENDIAN

#define FILLP_NTOHL(x) \
    ((((x)&0x000000ff) << 24) | (((x)&0x0000ff00) << 8) | (((x)&0x00ff0000) >> 8) | (((x)&0xff000000) >> 24))

#define FILLP_NTOHS(x) (FILLP_UINT16)((((x)&0x00ff) << 8) | (((x)&0xff00) >> 8))

#define FILLP_NTOHLL(x)                                                                                              \
    ((((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | (((x) >> 24) & 0x0000000000FF0000) |  \
        (((x) >> 8) & 0x00000000FF000000) | (((x) << 8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) | \
        (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000))


#define FILLP_HTONL(x) FILLP_NTOHL(x)
#define FILLP_HTONS(x) FILLP_NTOHS(x)
#define FILLP_HTONLL(x) FILLP_NTOHLL(x)

#else
#define FILLP_NTOHL(x) (x)
#define FILLP_NTOHS(x) (x)
#define FILLP_HTONL(x) (x)
#define FILLP_HTONS(x) (x)
#define FILLP_HTONLL(x) (x)
#define FILLP_NTOHLL(x) (x)
#endif

#define FILLP_ONE_SECOND 1000
#define FILLP_BPS_TO_KBPS 1000
#define FILLP_NULL_NUM 0x0

#if defined(FILLP_LINUX)
#define FILLP_THREAD pthread_t
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif
#elif defined(FILLP_WIN32)
#define FILLP_THREAD unsigned int
#define unlikely(x) (x)
#else
#error "define systhread type and unlikely !!!"
#endif

typedef struct FillpLmGlobalStruct {
    FILLP_ULLONG logModules; /* Modules for which logs needs to enabled */
    FILLP_UINT8 debugLevel;  /* dbg level : FillpDebugLevel */
    FILLP_UINT8 funcTrace;   /* Open(1) and Close(0) function trc flag */
    FILLP_BOOL mgtMsgLog;    /* Enable/Disable the management message log */
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd;
#endif
    FillpLmCallbackFunc lmCallbackFn;
} FillpLmGlobal;

extern FillpSysLibBasicCallbackFuncSt g_fillpOsBasicLibFun;
extern FillpSysLibSemCallbackFuncSt g_fillpOsSemLibFun;
extern FillpSysLibSockCallbackFuncSt g_fillpOsSocketLibFun;
extern FillpAppCallbackFunc g_fillpAppCbkFun;
extern FillpLmGlobal g_fillpLmGlobal;

#ifdef __cplusplus
}
#endif

#endif /* FILLP_OS_H */
