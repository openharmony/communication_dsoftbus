/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DFILE_DFX_H
#define NSTACKX_DFILE_DFX_H
#include <limits.h>
#include "nstackx_dfile.h"
#include "nstackx_list.h"
#include "nstackx_dfile_session.h"
typedef struct DFileSessionNode {
    List list;
    uint16_t sessionId;
    DFileSession *session;
} DFileSessionNode;

#ifdef __cplusplus
extern "C" {
#endif
#ifdef DFILE_ENABLE_HIDUMP

DFileSessionNode *GetDFileSessionNodeById(uint16_t sessionId);
#define DUMP_INFO_MAX 1000
#define DUMP_DECIMAL 10

extern pthread_mutex_t g_dFileSessionChainMutex;
extern List g_dFileSessionChain;

int32_t HidumpHelp(char *message, size_t *size);
int32_t HidumpList(char *message, size_t *size);
int32_t HidumpInformation(char *message, size_t *size, char *opt);
int32_t HidumpMessage(char *message, size_t *size, char *opt);

bool GetDfileHiDumpStatus();
#endif

void WaitFileHeaderTimeoutEvent(DFileTransErrorCode errorCode);
void DFileServerCreateEvent(void);
void DFileClientCreateEvent(void);
void DFileSendFileBeginEvent(void);
void PeerShuttedEvent(void);
void TransferCompleteEvent(const double rate);
void AcceptSocketEvent(void);

#ifdef __cplusplus
}
#endif
#endif
