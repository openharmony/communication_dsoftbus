/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "transserverproxyextern_fuzzer.h"

#include <chrono>
#include <thread>
#include "securec.h"

#include "softbus_adapter_mem.h"
#include "trans_server_proxy.h"

#define LOOP_SLEEP_MILLS 100

namespace OHOS {
class TransServerProxyExternTestEnv {
public:
    TransServerProxyExternTestEnv()
    {
        isInited_ = false;
        (void)TransServerProxyInit();
        isInited_ = true;
    }

    ~TransServerProxyExternTestEnv()
    {
        isInited_ = false;
        TransServerProxyDeInit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

void TransServerProxyDeInitTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    TransServerProxyDeInit();
}

void ServerIpcCreateSessionServerTest(const uint8_t *data, size_t size)
{
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(data));
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));

    (void)ServerIpcCreateSessionServer(pkgName, sessionName);
    (void)ServerIpcCreateSessionServer(nullptr, sessionName);
    (void)ServerIpcCreateSessionServer(pkgName, nullptr);
    (void)ServerIpcCreateSessionServer(nullptr, nullptr);
}

void ServerIpcRemoveSessionServerTest(const uint8_t *data, size_t size)
{
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(data));
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));

    (void)ServerIpcRemoveSessionServer(pkgName, sessionName);
    (void)ServerIpcRemoveSessionServer(nullptr, sessionName);
    (void)ServerIpcRemoveSessionServer(pkgName, nullptr);
    (void)ServerIpcRemoveSessionServer(nullptr, nullptr);
}

static void InitSessionAttribute(const uint8_t *data, size_t size, SessionAttribute *sessionAttr)
{
    sessionAttr->dataType = *(reinterpret_cast<const int32_t *>(data));
    sessionAttr->attr.streamAttr.streamType = *(reinterpret_cast<const int32_t *>(data));
}

static void InitSessionParam(
    const uint8_t *data, size_t size, SessionParam *sessionParam, SessionAttribute *sessionAttr)
{
    bool boolParam = (size % 2 == 0) ? true : false;
    char *charParam = boolParam ? const_cast<char *>(reinterpret_cast<const char *>(data)) : nullptr;

    sessionParam->sessionName = charParam;
    sessionParam->peerSessionName = charParam;
    sessionParam->peerDeviceId = charParam;
    sessionParam->groupId = charParam;
    sessionParam->attr = sessionAttr;
    sessionParam->sessionId = *(reinterpret_cast<const int32_t *>(data));
    sessionParam->isQosLane = boolParam;
    sessionParam->isAsync = boolParam;
}

void ServerIpcOpenSessionTest(const uint8_t *data, size_t size)
{
    TransInfo transInfo = {
        .channelId = *(reinterpret_cast<const int32_t *>(data)),
        .channelType = *(reinterpret_cast<const int32_t *>(data)),
    };

    SessionAttribute sessionAttr = { 0 };
    InitSessionAttribute(data, size, &sessionAttr);

    SessionParam sessionParam = { 0 };
    InitSessionParam(data, size, &sessionParam, &sessionAttr);

    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
}

void ServerIpcOpenAuthSessionTest(const uint8_t *data, size_t size)
{
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));
    ConnectionAddr connectionAddr;
    connectionAddr.type = CONNECTION_ADDR_SESSION;
    connectionAddr.info.session.sessionId = *(reinterpret_cast<const int32_t *>(data));
    connectionAddr.info.session.channelId = *(reinterpret_cast<const int32_t *>(data));
    connectionAddr.info.session.type = *(reinterpret_cast<const int32_t *>(data));
    (void)ServerIpcOpenAuthSession(sessionName, &connectionAddr);
    (void)ServerIpcOpenAuthSession(nullptr, &connectionAddr);
    (void)ServerIpcOpenAuthSession(sessionName, nullptr);
    (void)ServerIpcOpenAuthSession(nullptr, nullptr);
}

void ServerIpcNotifyAuthSuccessTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));

    (void)ServerIpcNotifyAuthSuccess(channelId, channelType);
}

void ServerIpcCloseChannelTest(const uint8_t *data, size_t size)
{
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));

    (void)ServerIpcCloseChannel(sessionName, channelId, channelType);
}

void ServerIpcCloseChannelWithStatisticsTest(const uint8_t *data, size_t size)
{
    if (size < sizeof(uint64_t)) {
        return;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    uint64_t laneId = *(reinterpret_cast<const uint64_t *>(data));

    (void)ServerIpcCloseChannelWithStatistics(channelId, laneId, data, size);
}

void ServerIpcReleaseResourcesTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));

    (void)ServerIpcReleaseResources(channelId);
}

void ServerIpcSendMessageTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t msgType = *(reinterpret_cast<const int32_t *>(data));

    (void)ServerIpcSendMessage(channelId, channelType, data, size, msgType);
}

void ServerIpcQosReportTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t appType = *(reinterpret_cast<const int32_t *>(data));
    int32_t quality = *(reinterpret_cast<const int32_t *>(data));

    (void)ServerIpcQosReport(channelId, channelType, appType, quality);
}

void ServerIpcStreamStatsTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    StreamSendStats streamSendStats;
    streamSendStats.costTimeStatsCnt[FRAME_COST_LT10MS] = *(reinterpret_cast<const uint32_t *>(data));
    streamSendStats.sendBitRateStatsCnt[FRAME_BIT_RATE_LT3M] = *(reinterpret_cast<const uint32_t *>(data));
    (void)ServerIpcStreamStats(channelId, channelType, &streamSendStats);
}

void ServerIpcRippleStatsTest(const uint8_t *data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    TrafficStats trafficStats;
    trafficStats.stats[0] = 't';
    trafficStats.stats[1] = 'e';
    (void)ServerIpcRippleStats(channelId, channelType, &trafficStats);
}

void ServerIpcGrantPermissionTest(const uint8_t *data, size_t size)
{
    int uid = *(reinterpret_cast<const int *>(data));
    int pid = *(reinterpret_cast<const int *>(data));
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));

    (void)ServerIpcGrantPermission(uid, pid, sessionName);
    (void)ServerIpcGrantPermission(uid, pid, nullptr);
}

void ServerIpcRemovePermissionTest(const uint8_t *data, size_t size)
{
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));

    (void)ServerIpcRemovePermission(sessionName);
    (void)ServerIpcRemovePermission(nullptr);
}

void ServerIpcEvaluateQosTest(const uint8_t *data, size_t size)
{
    char *peerNetworkId = const_cast<char *>(reinterpret_cast<const char *>(data));
    TransDataType dataType = *(reinterpret_cast<const TransDataType *>(data));
    QosTV qosTv = {
        .qos = *(reinterpret_cast<const QosType *>(data)),
        .value = *(reinterpret_cast<const int32_t *>(data)),
    };
    uint32_t qosCount = 1;

    (void)ServerIpcEvaluateQos(peerNetworkId, dataType, &qosTv, qosCount);
    (void)ServerIpcEvaluateQos(nullptr, dataType, &qosTv, qosCount);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }

    static OHOS::TransServerProxyExternTestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    uint8_t *dataWithEndCharacter = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (dataWithEndCharacter == nullptr) {
        return 0;
    }

    if (memcpy_s(dataWithEndCharacter, size, data, size) != EOK) {
        SoftBusFree(dataWithEndCharacter);
        return 0;
    }

    /* Run your code on data */
    OHOS::TransServerProxyDeInitTest(data, size);
    OHOS::ServerIpcCreateSessionServerTest(dataWithEndCharacter, size);
    OHOS::ServerIpcRemoveSessionServerTest(dataWithEndCharacter, size);
    OHOS::ServerIpcOpenSessionTest(dataWithEndCharacter, size);
    OHOS::ServerIpcOpenAuthSessionTest(dataWithEndCharacter, size);
    OHOS::ServerIpcCloseChannelTest(dataWithEndCharacter, size);
    OHOS::ServerIpcCloseChannelWithStatisticsTest(data, size);
    OHOS::ServerIpcReleaseResourcesTest(data, size);
    OHOS::ServerIpcSendMessageTest(data, size);
    OHOS::ServerIpcQosReportTest(data, size);
    OHOS::ServerIpcStreamStatsTest(data, size);
    OHOS::ServerIpcRippleStatsTest(data, size);
    OHOS::ServerIpcGrantPermissionTest(dataWithEndCharacter, size);
    OHOS::ServerIpcRemovePermissionTest(dataWithEndCharacter, size);
    OHOS::ServerIpcEvaluateQosTest(dataWithEndCharacter, size);
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    SoftBusFree(dataWithEndCharacter);
    return 0;
}
