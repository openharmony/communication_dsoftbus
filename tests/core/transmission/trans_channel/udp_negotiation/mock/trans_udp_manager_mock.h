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

#ifndef TRANS_UDP_MANAGER_MOCK_H
#define TRANS_UDP_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "trans_udp_channel_manager.h"
#include "bus_center_info_key_struct.h"


namespace OHOS {
class TransUdpManagerInterface {
public:
    TransUdpManagerInterface() {};
    virtual ~TransUdpManagerInterface() {};
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
};

class TransUdpManagerMock : public TransUdpManagerInterface {
public:
    TransUdpManagerMock();
    ~TransUdpManagerMock() override;
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char *, InfoKey, char *, uint32_t));
};

} // namespace OHOS
#endif // TRANS_TCP_DIRECT_SESSIONCONN_MOCK_H
