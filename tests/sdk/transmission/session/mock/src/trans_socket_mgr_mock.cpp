/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "trans_socket_mgr_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_socketMgrInterface = nullptr;

TransSocketMgrMock::TransSocketMgrMock()
{
    g_socketMgrInterface = reinterpret_cast<void *>(this);
}

TransSocketMgrMock::~TransSocketMgrMock()
{
    g_socketMgrInterface = nullptr;
}

static TransSocketMgrInterface *GetManagerInterface()
{
    return reinterpret_cast<TransSocketMgrInterface *>(g_socketMgrInterface);
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetQosValue(const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal)
{
    return GetManagerInterface()->GetQosValue(qos, qosCount, type, value, defVal);
}

int TransDataSeqInfoListInit(void)
{
    return GetManagerInterface()->TransDataSeqInfoListInit();
}

void TransAsyncSendBytesTimeoutProc(void)
{
    return GetManagerInterface()->TransAsyncSendBytesTimeoutProc();
}

void ClientCheckWaitTimeOut(const ClientSessionServer *serverNode, SessionInfo *sessionNode,
    int32_t waitOutSocket[], uint32_t capacity, uint32_t *num)
{
    return GetManagerInterface()->ClientCheckWaitTimeOut(serverNode, sessionNode, waitOutSocket, capacity, num);
}

void ClientUpdateIdleTimeout(const ClientSessionServer *serverNode, SessionInfo *sessionNode, ListNode *destroyList)
{
    return GetManagerInterface()->ClientUpdateIdleTimeout(serverNode, sessionNode, destroyList);
}

void ClientCleanUpIdleTimeoutSocket(const ListNode *destroyList)
{
    return GetManagerInterface()->ClientCleanUpIdleTimeoutSocket(destroyList);
}

void ClientCleanUpWaitTimeoutSocket(int32_t waitOutSocket[], uint32_t waitOutNum)
{
    return GetManagerInterface()->ClientCleanUpWaitTimeoutSocket(waitOutSocket, waitOutNum);
}

void DestroyClientSessionByNetworkId(const ClientSessionServer *server,
    const char *networkId, int32_t type, ListNode *destroyList)
{
    return GetManagerInterface()->DestroyClientSessionByNetworkId(server, networkId, type, destroyList);
}

void ClientDestroySession(const ListNode *destroyList, ShutdownReason reason)
{
    return GetManagerInterface()->ClientDestroySession(destroyList, reason);
}
#ifdef __cplusplus
}
#endif
}
