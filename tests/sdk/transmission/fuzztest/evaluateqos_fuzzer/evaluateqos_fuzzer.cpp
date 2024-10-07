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

#include "evaluateqos_fuzzer.h"
#include <memory>
#include <string>
#include <securec.h>
#include "socket.h"

namespace OHOS {
static std::string DEFAULT_SOCKET_PEER_NETWORKID =
    "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm";
void EvaluateQosTestWithNetworkId(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    const size_t bufSize = size + 1;
    std::unique_ptr<char[]> peerNetworkId = std::make_unique<char[]>(bufSize);
    if (memset_s(peerNetworkId.get(), bufSize, 0, bufSize) != EOK) {
        return;
    }

    if (memcpy_s(peerNetworkId.get(), bufSize, data, size) != EOK) {
        return;
    }

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW, .value = 160 * 1024 * 1024},
        {.qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = 10},
        {.qos = QOS_TYPE_MIN_LATENCY, .value = 5},
    };

    (void)EvaluateQos(peerNetworkId.get(), DATA_TYPE_MESSAGE, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]));
}

void EvaluateQosTestWithDataType(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(TransDataType))) {
        return;
    }

    TransDataType socketDataType = DATA_TYPE_BUTT;
    if (memcpy_s(&socketDataType, sizeof(TransDataType), data, sizeof(TransDataType)) != EOK) {
        return;
    }

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW, .value = 160 * 1024 * 1024},
        {.qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = 10},
        {.qos = QOS_TYPE_MIN_LATENCY, .value = 5},
    };

    (void)EvaluateQos(DEFAULT_SOCKET_PEER_NETWORKID.c_str(), socketDataType, qosInfo,
        sizeof(qosInfo) / sizeof(qosInfo[0]));
}

void EvaluateQosTestWithQosInfo(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(QosTV))) {
        return;
    }

    size_t count = size / sizeof(QosTV);
    if (count == 0) {
        return;
    }

    std::unique_ptr<QosTV[]> qosInfo = std::make_unique<QosTV[]>(count);
    if (memcpy_s(qosInfo.get(), sizeof(QosTV) * count, data, sizeof(QosTV) * count) != EOK) {
        return;
    }
    (void)EvaluateQos(DEFAULT_SOCKET_PEER_NETWORKID.c_str(), DATA_TYPE_MESSAGE, qosInfo.get(), count);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::EvaluateQosTestWithNetworkId(data, size);
    return 0;
}
