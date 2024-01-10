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

#ifndef SPUNGE_APP_H
#define SPUNGE_APP_H
#include "sockets.h"
#include "queue.h"
#include "hlist.h"
#include "fillpinc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Called for providing Developer related function indication info */
#define FILLP_APP_LM_FILLPCMDTRACE_OUTPUT(traceMsg)                                         \
    do {                                                                                    \
        if ((g_traceInfo.cmdTraceFlag) && (g_traceInfo.fillpTraceSend != FILLP_NULL_PTR)) { \
            (*g_traceInfo.fillpTraceSend) traceMsg;                                         \
        }                                                                                   \
    } while (0)

struct FtSocket *SpungeAllocSock(FILLP_INT allocType);
void SpungeDelEpInstFromFtSocket(struct FtSocket *sock, FILLP_INT epFd);

#ifdef __cplusplus
}
#endif

#endif // SPUNGE_APP_H
