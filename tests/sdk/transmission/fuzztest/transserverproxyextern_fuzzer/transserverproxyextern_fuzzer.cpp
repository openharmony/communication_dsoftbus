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
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include "securec.h"

#include "fuzz_data_generator.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
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

void ServerIpcCreateSessionServerTest(FuzzedDataProvider &provider)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }
    TransServerProxyDeInit();
    (void)ServerIpcCreateSessionServer(pkgName, sessionName, 1);
    (void)ServerIpcCreateSessionServer(nullptr, sessionName, 1);
    (void)ServerIpcCreateSessionServer(pkgName, nullptr, 1);
    (void)ServerIpcCreateSessionServer(nullptr, nullptr, 1);
}

void ServerIpcRemoveSessionServerTest(FuzzedDataProvider &provider)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }

    (void)ServerIpcRemoveSessionServer(pkgName, sessionName, 1);
    (void)ServerIpcRemoveSessionServer(nullptr, sessionName, 1);
    (void)ServerIpcRemoveSessionServer(pkgName, nullptr, 1);
    (void)ServerIpcRemoveSessionServer(nullptr, nullptr, 1);
}

void ServerIpcOpenSessionTest(FuzzedDataProvider &provider)
{
    TransInfo transInfo = { 0 };
    SessionAttribute sessionAttr = { 0 };
    SessionParam sessionParam = { 0 };
    transInfo.channelId = provider.ConsumeIntegral<int32_t>();
    transInfo.channelType = provider.ConsumeIntegral<int32_t>();
    sessionAttr.dataType = provider.ConsumeIntegral<int32_t>();
    sessionAttr.attr.streamAttr.streamType = provider.ConsumeIntegral<int32_t>();
    sessionParam.isQosLane = provider.ConsumeBool();
    sessionParam.isAsync = provider.ConsumeBool();
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    sessionParam.sessionName = providerSessionName.c_str();
    std::string providerPeerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    sessionParam.peerSessionName = providerPeerSessionName.c_str();
    std::string providerPeerDeviceId = provider.ConsumeBytesAsString(DEVICE_ID_SIZE_MAX - 1);
    sessionParam.peerDeviceId = providerPeerDeviceId.c_str();
    std::string providerGroupId = provider.ConsumeBytesAsString(GROUP_ID_SIZE_MAX - 1);
    sessionParam.groupId = providerGroupId.c_str();
    sessionParam.attr = &sessionAttr;
    sessionParam.sessionId = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.attr = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.groupId = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.peerDeviceId = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.peerSessionName = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
    sessionParam.sessionName = nullptr;
    (void)ServerIpcOpenSession(&sessionParam, &transInfo);
}

void ServerIpcOpenAuthSessionTest(FuzzedDataProvider &provider)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }
    ConnectionAddr connectionAddr;
    connectionAddr.type = CONNECTION_ADDR_SESSION;
    connectionAddr.info.session.sessionId = provider.ConsumeIntegral<int32_t>();
    connectionAddr.info.session.channelId = provider.ConsumeIntegral<int32_t>();
    connectionAddr.info.session.type = provider.ConsumeIntegral<int32_t>();
    (void)ServerIpcOpenAuthSession(sessionName, &connectionAddr);
    (void)ServerIpcOpenAuthSession(nullptr, &connectionAddr);
    (void)ServerIpcOpenAuthSession(sessionName, nullptr);
    (void)ServerIpcOpenAuthSession(nullptr, nullptr);
}

void ServerIpcCloseChannelTest(FuzzedDataProvider &provider)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcCloseChannel(sessionName, channelId, channelType);
}

void ServerIpcCloseChannelWithStatisticsTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    uint64_t laneId = provider.ConsumeIntegral<uint64_t>();
    uint64_t size = provider.ConsumeIntegral<uint64_t>();
    if (size < 1) {
        return;
    }
    std::string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());

    (void)ServerIpcCloseChannelWithStatistics(channelId, channelType, laneId, data, size);
}

void ServerIpcReleaseResourcesTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcReleaseResources(channelId);
}

void ServerIpcSendMessageTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    int32_t msgType = provider.ConsumeIntegral<int32_t>();
    uint32_t size = provider.ConsumeIntegral<uint32_t>();
    if (size < 1) {
        return;
    }
    std::string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());

    (void)ServerIpcSendMessage(channelId, channelType, data, size, msgType);
}

void ServerIpcQosReportTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    int32_t appType = provider.ConsumeIntegral<int32_t>();
    int32_t quality = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcQosReport(channelId, channelType, appType, quality);
}

void ServerIpcStreamStatsTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    StreamSendStats streamSendStats;
    streamSendStats.costTimeStatsCnt[FRAME_COST_LT10MS] = provider.ConsumeIntegral<uint32_t>();
    streamSendStats.sendBitRateStatsCnt[FRAME_BIT_RATE_LT3M] = provider.ConsumeIntegral<uint32_t>();
    (void)ServerIpcStreamStats(channelId, channelType, &streamSendStats);
}

void ServerIpcRippleStatsTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    TrafficStats trafficStats;
    trafficStats.stats[0] = 't';
    trafficStats.stats[1] = 'e';
    (void)ServerIpcRippleStats(channelId, channelType, &trafficStats);
}

void ServerIpcGrantPermissionTest(FuzzedDataProvider &provider)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcGrantPermission(uid, pid, sessionName);
    (void)ServerIpcGrantPermission(uid, pid, nullptr);
}

void ServerIpcRemovePermissionTest(FuzzedDataProvider &provider)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }

    (void)ServerIpcRemovePermission(sessionName);
    (void)ServerIpcRemovePermission(nullptr);
}

void ServerIpcEvaluateQosTest(FuzzedDataProvider &provider)
{
    char peerNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    QosTV qosTv;
    std::string providerPeerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(peerNetworkId, NETWORK_ID_BUF_LEN - 1, providerPeerNetworkId.c_str()) != EOK) {
        return;
    }
    TransDataType dataType = (TransDataType)provider.ConsumeIntegralInRange<uint32_t>(DATA_TYPE_MESSAGE,
        DATA_TYPE_BUTT);
    qosTv.qos = (QosType)provider.ConsumeIntegralInRange<uint32_t>(QOS_TYPE_MIN_BW, QOS_TYPE_BUTT);
    qosTv.value = provider.ConsumeIntegral<int32_t>();
    uint32_t qosCount = 1;

    (void)ServerIpcEvaluateQos(peerNetworkId, dataType, &qosTv, qosCount);
    (void)ServerIpcEvaluateQos(nullptr, dataType, &qosTv, qosCount);
}

void ServerIpcNotifyAuthSuccessTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();

    (void)ServerIpcNotifyAuthSuccess(channelId, channelType);
}

void ServerIpcPrivilegeCloseChannelTest(FuzzedDataProvider &provider)
{
    uint64_t tokenId = provider.ConsumeIntegral<uint64_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char peerNetworkId[UINT8_MAX] = { 0 };
    if (strcpy_s(peerNetworkId, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    
    (void)ServerIpcPrivilegeCloseChannel(tokenId, pid, peerNetworkId);
    (void)ServerIpcPrivilegeCloseChannel(tokenId, pid, nullptr);
}

void ServerIpcOpenBrProxyTest(FuzzedDataProvider &provider)
{
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char brMac[UINT8_MAX] = { 0 };
    if (strcpy_s(brMac, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char uuid[UINT8_MAX] = { 0 };
    if (strcpy_s(uuid, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    
    (void)ServerIpcOpenBrProxy(brMac, uuid);
    (void)ServerIpcOpenBrProxy(brMac, nullptr);
    (void)ServerIpcOpenBrProxy(nullptr, uuid);
}

void ServerIpcCloseBrProxyTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    
    (void)ServerIpcCloseBrProxy(channelId);
}

void ServerIpcSendBrProxyDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }

    (void)ServerIpcSendBrProxyData(channelId, data, dataLen);
}

void ServerIpcSetListenerStateTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t type = provider.ConsumeIntegral<int32_t>();
    bool cbEnabled = provider.ConsumeBool();

    (void)ServerIpcSetListenerState(channelId, type, cbEnabled);
}

void ServerIpcIsProxyChannelEnabledTest(FuzzedDataProvider &provider)
{
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    bool isEnable = provider.ConsumeBool();

    (void)ServerIpcIsProxyChannelEnabled(uid, &isEnable);
}

void ServerIpcRegisterPushHookTest()
{
    ServerIpcRegisterPushHook();
    TransServerProxyClear();
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
    FuzzedDataProvider provider(data, size);
    OHOS::ServerIpcCreateSessionServerTest(provider);
    OHOS::ServerIpcRemoveSessionServerTest(provider);
    OHOS::ServerIpcOpenSessionTest(provider);
    OHOS::ServerIpcOpenAuthSessionTest(provider);
    OHOS::ServerIpcCloseChannelTest(provider);
    OHOS::ServerIpcCloseChannelWithStatisticsTest(provider);
    OHOS::ServerIpcReleaseResourcesTest(provider);
    OHOS::ServerIpcSendMessageTest(provider);
    OHOS::ServerIpcQosReportTest(provider);
    OHOS::ServerIpcStreamStatsTest(provider);
    OHOS::ServerIpcRippleStatsTest(provider);
    OHOS::ServerIpcGrantPermissionTest(provider);
    OHOS::ServerIpcRemovePermissionTest(provider);
    OHOS::ServerIpcEvaluateQosTest(provider);
    OHOS::ServerIpcNotifyAuthSuccessTest(provider);
    OHOS::ServerIpcPrivilegeCloseChannelTest(provider);
    OHOS::ServerIpcOpenBrProxyTest(provider);
    OHOS::ServerIpcCloseBrProxyTest(provider);
    OHOS::ServerIpcSendBrProxyDataTest(provider);
    OHOS::ServerIpcSetListenerStateTest(provider);
    OHOS::ServerIpcIsProxyChannelEnabledTest(provider);
    OHOS::ServerIpcRegisterPushHookTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_SLEEP_MILLS));
    return 0;
}
