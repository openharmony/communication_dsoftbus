/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbusproxychannellistener_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "softbus_transmission_interface.h"

namespace OHOS {
#define SESSION_NAME_SIZE_MAX 256
#define DEVICE_ID_SIZE_MAX 65
#define TEST_PEER_NETWORK_ID "com.test.trans.demo.peerNetworkId"
#define TEST_SESSION_NAME "com.test.trans.demo.sessionname"

void TransOpenNetWorkingChannelSessionNameTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size >= SESSION_NAME_SIZE_MAX)) {
        return;
    }

    char mySessionName[SESSION_NAME_SIZE_MAX] = {0};
    if (memcpy_s(mySessionName, SESSION_NAME_SIZE_MAX, data, size)) {
        return;
    }

    char peerNetworkId[DEVICE_ID_SIZE_MAX] = TEST_PEER_NETWORK_ID;

    TransOpenNetWorkingChannel(mySessionName, peerNetworkId, nullptr);
}

void TransOpenNetWorkingChannelPeerNetworkIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size >= DEVICE_ID_SIZE_MAX) || (size < 0)) {
        return;
    }

    char peerNetworkId[DEVICE_ID_SIZE_MAX] = {0};
    if (memcpy_s(peerNetworkId, DEVICE_ID_SIZE_MAX, data, size)) {
        return;
    }

    const char *mySessionName = TEST_SESSION_NAME;
    TransOpenNetWorkingChannel(mySessionName, peerNetworkId, nullptr);
}

void TransCloseNetWorkingChannelTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t channelId = 0;
    if (memcpy_s(&channelId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    TransCloseNetWorkingChannel(channelId);
}

void TransSendNetworkingMessageTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t channelId;
    if (memcpy_s(&channelId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    int32_t priority = 1;
    if (memcpy_s(&priority, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    char myData[SESSION_NAME_SIZE_MAX];
    if (size < sizeof(myData)) {
        return;
    }
    if (memcpy_s(myData, SESSION_NAME_SIZE_MAX, data, sizeof(myData) - 1)) {
        return;
    }

    uint32_t dataLen = 0;
    if (memcpy_s(&channelId, sizeof(uint32_t), data, sizeof(uint32_t)) != EOK) {
        return;
    }

    TransSendNetworkingMessage(channelId, myData, dataLen, priority);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransOpenNetWorkingChannelSessionNameTest(data, size);
    OHOS::TransOpenNetWorkingChannelPeerNetworkIdTest(data, size);
    OHOS::TransCloseNetWorkingChannelTest(data, size);
    OHOS::TransSendNetworkingMessageTest(data, size);
    return 0;
}
