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

#ifndef TRANS_TCP_DIRECT_LISTENER_TEST_MOCK_H
#define TRANS_TCP_DIRECT_LISTENER_TEST_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "softbus_app_info.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"

namespace OHOS {
class TransTcpDirectListenerInterface {
public:
    TransTcpDirectListenerInterface() {};
    virtual ~TransTcpDirectListenerInterface() {};
    virtual char *PackRequest(const AppInfo *appInfo) = 0;
    virtual int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data) = 0;
    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;
};

class TransTcpDirectListenerInterfaceMock : public TransTcpDirectListenerInterface {
public:
    TransTcpDirectListenerInterfaceMock();
    ~TransTcpDirectListenerInterfaceMock() override;
    MOCK_METHOD1(PackRequest, char *(const AppInfo *appInfo));
    MOCK_METHOD3(TransTdcPostBytes, int32_t(int32_t channelId, TdcPacketHead *packetHead, const char *data));
    MOCK_METHOD2(AuthGetServerSide, int32_t(int64_t authId, bool *isServer));
    MOCK_METHOD2(AuthGetConnInfo, int32_t(AuthHandle authHandle, AuthConnInfo *connInfo));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_LISTENER_TEST_MOCK_H

