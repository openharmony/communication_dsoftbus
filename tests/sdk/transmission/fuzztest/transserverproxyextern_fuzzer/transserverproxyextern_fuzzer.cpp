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

#include "fuzz_data_generator.h"
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

    bool IsInited(void) const
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

static uint8_t *TestDataSwitch(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return nullptr;
    }
    uint8_t *dataWithEndCharacter = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (dataWithEndCharacter == nullptr) {
        return nullptr;
    }
    if (memcpy_s(dataWithEndCharacter, size, data, size) != EOK) {
        SoftBusFree(dataWithEndCharacter);
        return nullptr;
    }
    return dataWithEndCharacter;
}

void ServerIpcCreateSessionServerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    (void)ServerIpcCreateSessionServer(pkgName, sessionName);
    (void)ServerIpcCreateSessionServer(nullptr, sessionName);
    (void)ServerIpcCreateSessionServer(pkgName, nullptr);
    (void)ServerIpcCreateSessionServer(nullptr, nullptr);
    SoftBusFree(dataWithEndCharacter);
}

void ServerIpcRemoveSessionServerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    (void)ServerIpcRemoveSessionServer(pkgName, sessionName);
    (void)ServerIpcRemoveSessionServer(nullptr, sessionName);
    (void)ServerIpcRemoveSessionServer(pkgName, nullptr);
    (void)ServerIpcRemoveSessionServer(nullptr, nullptr);
    SoftBusFree(dataWithEndCharacter);
}

static void InitSessionAttribute(const uint8_t *data, size_t size, SessionAttribute *sessionAttr)
{
    DataGenerator::Write(data, size);
    GenerateInt32(sessionAttr->dataType);
    GenerateInt32(sessionAttr->attr.streamAttr.streamType);
    DataGenerator::Clear();
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
    DataGenerator::Write(data, size);
    sessionParam->sessionId = 0;
    GenerateInt32(sessionParam->sessionId);
    DataGenerator::Clear();
    sessionParam->isQosLane = boolParam;
    sessionParam->isAsync = boolParam;
}

void ServerIpcOpenSessionTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    DataGenerator::Write(data, size);
    TransInfo transInfo = { 0 };
    GenerateInt32(transInfo.channelId);
    GenerateInt32(transInfo.channelType);
    DataGenerator::Clear();

    SessionAttribute sessionAttr = { 0 };
    InitSessionAttribute(dataWithEndCharacter, size, &sessionAttr);

    SessionParam sessionParam = { 0 };
    InitSessionParam(dataWithEndCharacter, size, &sessionParam, &sessionAttr);

    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    SoftBusFree(dataWithEndCharacter);
}

void ServerIpcOpenAuthSessionTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    ConnectionAddr connectionAddr;
    connectionAddr.type = CONNECTION_ADDR_SESSION;
    DataGenerator::Write(data, size);
    connectionAddr.info.session.sessionId = 0;
    connectionAddr.info.session.channelId = 0;
    connectionAddr.info.session.type = 0;
    GenerateInt32(connectionAddr.info.session.sessionId);
    GenerateInt32(connectionAddr.info.session.channelId);
    GenerateInt32(connectionAddr.info.session.type);
    (void)ServerIpcOpenAuthSession(sessionName, &connectionAddr);
    (void)ServerIpcOpenAuthSession(nullptr, &connectionAddr);
    (void)ServerIpcOpenAuthSession(sessionName, nullptr);
    (void)ServerIpcOpenAuthSession(nullptr, nullptr);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();
}

void ServerIpcNotifyAuthSuccessTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);

    (void)ServerIpcNotifyAuthSuccess(channelId, channelType);
    DataGenerator::Clear();
}

void ServerIpcCloseChannelTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);

    (void)ServerIpcCloseChannel(sessionName, channelId, channelType);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();
}

void ServerIpcCloseChannelWithStatisticsTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t)) {
        return;
    }

    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    uint64_t laneId = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateUint64(laneId);

    (void)ServerIpcCloseChannelWithStatistics(channelId, channelType, laneId, data, size);
    DataGenerator::Clear();
}

void ServerIpcReleaseResourcesTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    (void)ServerIpcReleaseResources(channelId);
    DataGenerator::Clear();
}

void ServerIpcSendMessageTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t msgType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(msgType);

    (void)ServerIpcSendMessage(channelId, channelType, data, size, msgType);
    DataGenerator::Clear();
}

void ServerIpcQosReportTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t appType = 0;
    int32_t quality = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(appType);
    GenerateInt32(quality);

    (void)ServerIpcQosReport(channelId, channelType, appType, quality);
    DataGenerator::Clear();
}

void ServerIpcStreamStatsTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    StreamSendStats streamSendStats;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateUint32(streamSendStats.costTimeStatsCnt[FRAME_COST_LT10MS]);
    GenerateUint32(streamSendStats.sendBitRateStatsCnt[FRAME_BIT_RATE_LT3M]);
    (void)ServerIpcStreamStats(channelId, channelType, &streamSendStats);
    DataGenerator::Clear();
}

void ServerIpcRippleStatsTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    TrafficStats trafficStats;
    trafficStats.stats[0] = 't';
    trafficStats.stats[1] = 'e';
    (void)ServerIpcRippleStats(channelId, channelType, &trafficStats);
    DataGenerator::Clear();
}

void ServerIpcGrantPermissionTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t uid = 0;
    int32_t pid = 0;
    GenerateInt32(uid);
    GenerateInt32(pid);
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    (void)ServerIpcGrantPermission(uid, pid, sessionName);
    (void)ServerIpcGrantPermission(uid, pid, nullptr);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();
}

void ServerIpcRemovePermissionTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    (void)ServerIpcRemovePermission(sessionName);
    (void)ServerIpcRemovePermission(nullptr);
    SoftBusFree(dataWithEndCharacter);
}

void ServerIpcEvaluateQosTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    char *peerNetworkId = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    TransDataType dataType = *(reinterpret_cast<const TransDataType *>(dataWithEndCharacter));
    QosTV qosTv = {
        .qos = *(reinterpret_cast<const QosType *>(dataWithEndCharacter)),
    };
    DataGenerator::Write(data, size);
    GenerateInt32(qosTv.value);
    uint32_t qosCount = 1;

    (void)ServerIpcEvaluateQos(peerNetworkId, dataType, &qosTv, qosCount);
    (void)ServerIpcEvaluateQos(nullptr, dataType, &qosTv, qosCount);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransServerProxyExternTestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    OHOS::TransServerProxyDeInitTest(data, size);
    OHOS::ServerIpcCreateSessionServerTest(data, size);
    OHOS::ServerIpcRemoveSessionServerTest(data, size);
    OHOS::ServerIpcOpenSessionTest(data, size);
    OHOS::ServerIpcOpenAuthSessionTest(data, size);
    OHOS::ServerIpcCloseChannelTest(data, size);
    OHOS::ServerIpcCloseChannelWithStatisticsTest(data, size);
    OHOS::ServerIpcReleaseResourcesTest(data, size);
    OHOS::ServerIpcSendMessageTest(data, size);
    OHOS::ServerIpcQosReportTest(data, size);
    OHOS::ServerIpcStreamStatsTest(data, size);
    OHOS::ServerIpcRippleStatsTest(data, size);
    OHOS::ServerIpcGrantPermissionTest(data, size);
    OHOS::ServerIpcRemovePermissionTest(data, size);
    OHOS::ServerIpcEvaluateQosTest(data, size);
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}
