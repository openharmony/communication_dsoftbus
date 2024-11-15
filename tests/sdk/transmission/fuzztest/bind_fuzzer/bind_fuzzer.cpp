/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bind_fuzzer.h"
#include <memory>
#include <securec.h>
#include "socket.h"

namespace OHOS {
static void OnBindFuzzTest(int32_t socket, PeerSocketInfo info)
{
    (void)socket;
    (void)info;
}

static void OnShutdownFuzzTest(int32_t socket, ShutdownReason reason)
{
    (void)socket;
    (void)reason;
}

static void OnBytesFuzzTest(int32_t socket, const void *data, uint32_t dataLen)
{
    (void)socket;
    (void)data;
    (void)dataLen;
}

static void OnMessageFuzzTest(int32_t socket, const void *data, uint32_t dataLen)
{
    (void)socket;
    (void)data;
    (void)dataLen;
}

static void OnStreamFuzzTest(int32_t socket, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    (void)socket;
    (void)data;
    (void)ext;
    (void)param;
}

static void OnFileFuzzTest(int32_t socket, FileEvent *event)
{
    (void)socket;
    (void)event;
}

static void OnQosFuzzTest(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    (void)socket;
    (void)eventId;
    (void)qos;
    (void)qosCount;
}

static void OnErrorFuzzTest(int32_t socket, int32_t errCode)
{
    (void)socket;
    (void)errCode;
}

static bool OnNegotiateFuzzTest(int32_t socket, PeerSocketInfo info)
{
    (void)socket;
    (void)info;
    return true;
}

void BindTestWithSocketId(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW, .value = 160 * 1024 * 1024},
        {.qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = 10},
        {.qos = QOS_TYPE_MIN_LATENCY, .value = 5},
    };

    ISocketListener listener = {
        .OnBind = OnBindFuzzTest,
        .OnShutdown = OnShutdownFuzzTest,
        .OnBytes = OnBytesFuzzTest,
        .OnMessage = OnMessageFuzzTest,
        .OnStream = OnStreamFuzzTest,
        .OnFile = OnFileFuzzTest,
        .OnQos = OnQosFuzzTest,
        .OnError = OnErrorFuzzTest,
        .OnNegotiate = OnNegotiateFuzzTest
    };

    (void)Bind(socketId, qosInfo, sizeof(qosInfo)/sizeof(qosInfo[0]), &listener);
}

void BindTestWithQosInfo(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(QosTV))) {
        return;
    }

    int32_t socketId = 1;

    size_t count = size / sizeof(QosTV);
    if (count == 0) {
        return;
    }

    std::unique_ptr<QosTV[]> qosInfo = std::make_unique<QosTV[]>(count);
    if (memcpy_s(qosInfo.get(), sizeof(QosTV) * count, data, sizeof(QosTV) * count) != EOK) {
        return;
    }

    ISocketListener listener = {
        .OnBind = OnBindFuzzTest,
        .OnShutdown = OnShutdownFuzzTest,
        .OnBytes = OnBytesFuzzTest,
        .OnMessage = OnMessageFuzzTest,
        .OnStream = OnStreamFuzzTest,
        .OnFile = OnFileFuzzTest,
        .OnQos = OnQosFuzzTest,
        .OnError = OnErrorFuzzTest,
        .OnNegotiate = OnNegotiateFuzzTest
    };

    (void)Bind(socketId, qosInfo.get(), count, &listener);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::BindTestWithSocketId(data, size);
    OHOS::BindTestWithQosInfo(data, size);
    return 0;
}
