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

#ifndef TRANS_SOCKET_MGR_MOCK_H
#define TRANS_SOCKET_MGR_MOCK_H

#include <gmock/gmock.h>

#include "client_trans_session_manager_struct.h"
#include "common_list.h"
#include "softbus_error_code.h"
#include "trans_type.h"

namespace OHOS {
class TransSocketMgrInterface {
public:
    TransSocketMgrInterface() {};
    virtual ~TransSocketMgrInterface() {};

    virtual int32_t GetQosValue(const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal) = 0;
    virtual int TransDataSeqInfoListInit(void) = 0;
    virtual void TransAsyncSendBytesTimeoutProc(void) = 0;
    virtual void ClientCheckWaitTimeOut(const ClientSessionServer *serverNode, SessionInfo *sessionNode,
        int32_t waitOutSocket[], uint32_t capacity, uint32_t *num) = 0;
    virtual void ClientUpdateIdleTimeout(
        const ClientSessionServer *serverNode, SessionInfo *sessionNode, ListNode *destroyList) = 0;
    virtual void ClientCleanUpIdleTimeoutSocket(const ListNode *destroyList) = 0;
    virtual void ClientCleanUpWaitTimeoutSocket(int32_t waitOutSocket[], uint32_t waitOutNum) = 0;
    virtual void DestroyClientSessionByNetworkId(const ClientSessionServer *server,
        const char *networkId, int32_t type, ListNode *destroyList) = 0;
    virtual void ClientDestroySession(const ListNode *destroyList, ShutdownReason reason) = 0;
};

class TransSocketMgrMock : public TransSocketMgrInterface {
public:
    TransSocketMgrMock();
    ~TransSocketMgrMock() override;

    MOCK_METHOD5(GetQosValue, int32_t(
        const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal));
    MOCK_METHOD0(TransDataSeqInfoListInit, int(void));
    MOCK_METHOD0(TransAsyncSendBytesTimeoutProc, void(void));
    MOCK_METHOD5(ClientCheckWaitTimeOut, void(const ClientSessionServer *serverNode, SessionInfo *sessionNode,
        int32_t waitOutSocket[], uint32_t capacity, uint32_t *num));
    MOCK_METHOD3(ClientUpdateIdleTimeout, void(
        const ClientSessionServer *serverNode, SessionInfo *sessionNode, ListNode *destroyList));
    MOCK_METHOD1(ClientCleanUpIdleTimeoutSocket, void(const ListNode *destroyList));
    MOCK_METHOD2(ClientCleanUpWaitTimeoutSocket, void(int32_t waitOutSocket[], uint32_t waitOutNum));
    MOCK_METHOD4(DestroyClientSessionByNetworkId, void(const ClientSessionServer *server,
        const char *networkId, int32_t type, ListNode *destroyList));
    MOCK_METHOD2(ClientDestroySession, void(const ListNode *destroyList, ShutdownReason reason));
};

} // namespace OHOS
#endif // TRANS_SOCKET_MGR_MOCK_H
