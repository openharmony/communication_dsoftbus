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

#ifndef NSTACKX_DFILE_SEND_H
#define NSTACKX_DFILE_SEND_H

#include "nstackx_dfile_session.h"
#include "nstackx_list.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t SendOutboundFrame(DFileSession *session, QueueNode **preQueueNode);
int32_t SendDataFrame(DFileSession *session, List *unsent, uint32_t threadIdx, uint8_t socketIndex);
void DestroyIovList(List *head, DFileSession *s, uint32_t tid);
int32_t TcpSocketRecv(DFileSession *session, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
    const socklen_t *addrLen);
int32_t SocketRecvForTcp(DFileSession *session, uint8_t *buffer, struct sockaddr_in *srcAddr,
    const socklen_t *addrLen);

#ifdef __cplusplus
}
#endif

#endif
