/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_SESSION_CONNECT_H
#define SOFTBUS_SESSION_CONNECT_H

#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_uk_manager.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int32_t TransSrvDataListInit(void);
void TransSrvDataListDeinit(void);
int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd);
void TransSrvDelDataBufNode(int channelId);
int32_t TransTdcPostBytes(
    int32_t channelId, TdcPacketHead *packetHead, const char *data, const UkIdInfo *ukIdInfo);
int32_t TransTdcProcessPacket(int32_t channelId);
int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId, int32_t type, int32_t *pktModule);

int32_t NotifyChannelOpenFailedBySessionConn(const SessionConn *conn, int32_t errCode);
int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode);
int32_t TransDealTdcChannelOpenResult(int32_t channelId, int32_t openResult, pid_t callingPid);
void TransAsyncTcpDirectChannelTask(int32_t channelId);
int32_t TransDealTdcCheckCollabResult(int32_t channelId, int32_t checkResult, pid_t callingPid);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_SESSION_CONNECT_H
