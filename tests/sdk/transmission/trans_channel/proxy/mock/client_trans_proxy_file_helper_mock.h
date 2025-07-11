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

#ifndef CLIENT_TRANS_PROXY_MANAGER_MOCK_H
#define CLIENT_TRANS_PROXY_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "client_trans_pending.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "trans_proxy_process_data.h"
#include "trans_server_proxy.h"

namespace OHOS {
class ClientTransProxyFileHelperInterface {
public:
    ClientTransProxyFileHelperInterface() {};
    virtual ~ClientTransProxyFileHelperInterface() {};
    virtual int32_t ClientTransProxyPackAndSendData(int32_t channelId, const void* data, uint32_t len,
        ProxyChannelInfoDetail* info, SessionPktType pktType) = 0;
    virtual int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info) = 0;
    virtual uint32_t SoftBusLtoHl(uint32_t value) = 0;
    virtual uint32_t SoftBusHtoLl(uint32_t value) = 0;
    virtual uint64_t SoftBusLtoHll(uint64_t value) = 0;
    virtual uint64_t SoftBusHtoLll(uint64_t value) = 0;
    virtual uint32_t SoftBusNtoHl(uint32_t netlong) = 0;
    virtual int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset) = 0;
    virtual uint16_t SoftBusHtoLs(uint16_t value) = 0;
    virtual uint16_t RTU_CRC(const unsigned char *puchMsg, uint16_t usDataLen) = 0;
    virtual int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber) = 0;
};

class ClientTransProxyFileHelperInterfaceMock : public ClientTransProxyFileHelperInterface {
public:
    ClientTransProxyFileHelperInterfaceMock();
    ~ClientTransProxyFileHelperInterfaceMock() override;
    MOCK_METHOD5(ClientTransProxyPackAndSendData, int32_t (int32_t channelId, const void* data, uint32_t len,
        ProxyChannelInfoDetail* info, SessionPktType pktType));
    MOCK_METHOD2(ClientTransProxyGetInfoByChannelId, int32_t (int32_t channelId, ProxyChannelInfoDetail *info));
    MOCK_METHOD1(SoftBusLtoHl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusHtoLl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusLtoHll, uint64_t (uint64_t value));
    MOCK_METHOD1(SoftBusHtoLll, uint64_t (uint64_t value));
    MOCK_METHOD1(SoftBusNtoHl, uint32_t (uint32_t netlong));
    MOCK_METHOD1(SoftBusHtoLs, uint16_t (uint16_t value));
    MOCK_METHOD4(SoftBusPreadFile, int64_t (int32_t fd, void *buf, uint64_t readBytes, uint64_t offset));
    MOCK_METHOD2(RTU_CRC, uint16_t (const unsigned char *puchMsg, uint16_t usDataLen));
    MOCK_METHOD2(FrameIndexToType, int32_t (uint64_t index, uint64_t frameNumber));
};
}
#endif