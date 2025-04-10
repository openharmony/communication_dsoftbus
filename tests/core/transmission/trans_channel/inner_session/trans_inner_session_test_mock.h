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

#ifndef TRANS_INNER_SESSION_TEST_MOCK_H
#define TRANS_INNER_SESSION_TEST_MOCK_H

#include <gmock/gmock.h>
#include "softbus_app_info.h"
#include "softbus_trans_def.h"
#include "trans_inner.h"

namespace OHOS {
class TransInnerSessionInterface {
public:
    TransInnerSessionInterface() {};
    virtual ~TransInnerSessionInterface() {};
    virtual int32_t TransCreateSessionServer(
        const char *pkgName, const char *sessionName, int32_t uid, int32_t pid) = 0;
    virtual int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo) = 0;
    virtual int32_t TransProxyGetAppInfoById(int16_t channelId, AppInfo *appInfo) = 0;
    virtual int32_t DirectChannelCreateListener(int32_t fd) = 0;
    virtual int32_t InnerAddSession(InnerSessionInfo *innerInfo) = 0;
    virtual int32_t TransInnerAddDataBufNode(int32_t channelId, int32_t fd, int32_t channelType) = 0;
    virtual int32_t ServerSideSendAck(int32_t sessionId, int32_t result) = 0;
    virtual int32_t ProxyDataRecvHandler(int32_t channelId, const char *data, uint32_t len) = 0;
    virtual int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo) = 0;
    virtual int32_t TransSendData(int32_t channelId, const void *data, uint32_t len) = 0;
};

class TransInnerSessionInterfaceMock : public TransInnerSessionInterface {
public:
    TransInnerSessionInterfaceMock();
    ~TransInnerSessionInterfaceMock() override;
    MOCK_METHOD4(TransCreateSessionServer, int32_t (
        const char *pkgName, const char *sessionName, int32_t uid, int32_t pid));
    MOCK_METHOD2(GetAppInfoById, int32_t (int32_t channelId, AppInfo *appInfo));
    MOCK_METHOD2(TransProxyGetAppInfoById, int32_t (int16_t channelId, AppInfo *appInfo));
    MOCK_METHOD1(DirectChannelCreateListener, int32_t (int32_t fd));
    MOCK_METHOD1(InnerAddSession, int32_t (InnerSessionInfo *innerInfo));
    MOCK_METHOD3(TransInnerAddDataBufNode, int32_t (int32_t channelId, int32_t fd, int32_t channelType));
    MOCK_METHOD2(ServerSideSendAck, int32_t (int32_t sessionId, int32_t result));
    MOCK_METHOD3(ProxyDataRecvHandler, int32_t (int32_t channelId, const char *data, uint32_t len));
    MOCK_METHOD2(TransOpenChannel, int32_t (const SessionParam *param, TransInfo *transInfo));
    MOCK_METHOD3(TransSendData, int32_t (int32_t channelId, const void *data, uint32_t len));
};
} // namespace OHOS
#endif // TRANS_INNER_SESSION_TEST_MOCK_H
