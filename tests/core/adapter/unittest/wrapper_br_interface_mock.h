/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef WRAPPER_BR_INTERFACE_MOCK_H
#define WRAPPER_BR_INTERFACE_MOCK_H

#include "wrapper_br_interface.h"
#include <gmock/gmock.h>
#include <mutex>

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gap.h"
#include "c_header/ohos_bt_spp.h"
#include "c_header/ohos_bt_socket.h"

namespace OHOS {
class WrapperBrInterface {
public:
    WrapperBrInterface() { };
    virtual ~WrapperBrInterface() { };

    virtual int SppServerCreate(BtCreateSocketPara *socketPara, const char *name, unsigned int len) = 0;
    virtual int32_t SppServerClose(int32_t serverFd) = 0;
    virtual int32_t SocketConnectEx(const BluetoothCreateSocketPara *socketPara, const BdAddr *bdAddr,
        int32_t psm, BtSocketConnectionCallback *callback) = 0;
    virtual int32_t SppDisconnect(int32_t clientFd) = 0;
    virtual bool IsSppConnected(int32_t clientFd) = 0;
    virtual int32_t SppServerAccept(int32_t serverFd) = 0;
    virtual int SppWrite(int clientId, const char *data, const unsigned int len) = 0;
    virtual int SppRead(int clientId, char *buf, const unsigned int bufLen) = 0;
    virtual int32_t SppGetRemoteAddr(int32_t clientFd, BdAddr *remoteAddr) = 0;
    virtual int32_t SocketGetScn(int32_t serverFd) = 0;
    virtual int32_t SetConnectionPriority(const BdAddr *bdAddr, BtSocketPriority priority) = 0;
};

class WrapperBrInterfaceMock : public WrapperBrInterface {
public:
    WrapperBrInterfaceMock();
    ~WrapperBrInterfaceMock() override;

    MOCK_METHOD3(SppServerCreate, int(BtCreateSocketPara *socketPara, const char *name, unsigned int len));
    MOCK_METHOD1(SppServerClose, int32_t(int32_t serverFd));
    MOCK_METHOD4(SocketConnectEx, int32_t(const BluetoothCreateSocketPara *socketPara, const BdAddr *bdAddr,
        int32_t psm, BtSocketConnectionCallback *callback));
    MOCK_METHOD1(SppDisconnect, int32_t(int32_t clientFd));
    MOCK_METHOD1(IsSppConnected, bool(int32_t clientFd));
    MOCK_METHOD1(SppServerAccept, int32_t(int32_t serverFd));
    MOCK_METHOD3(SppWrite, int(int clientId, const char *data, const unsigned int len));
    MOCK_METHOD3(SppRead, int(int clientId, char *buf, const unsigned int bufLen));
    MOCK_METHOD2(SppGetRemoteAddr, int32_t(int32_t clientFd, BdAddr *remoteAddr));
    MOCK_METHOD1(SocketGetScn, int32_t(int32_t serverFd));
    MOCK_METHOD2(SetConnectionPriority, int32_t(const BdAddr *bdAddr, BtSocketPriority priority));
};
} // namespace OHOS
#endif // WRAPPER_BR_INTERFACE_MOCK_H