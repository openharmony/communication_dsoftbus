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

#include "softbusproxychannelmanager_fuzzer.h"

#include <chrono>
#include <securec.h>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"

namespace OHOS {
class SoftBusProxyChannelManagerTestEnv {
public:
    SoftBusProxyChannelManagerTestEnv()
    {
        isInited_ = false;
        (void)ConnServerInit();
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~SoftBusProxyChannelManagerTestEnv()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
        ConnServerDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

static void FillAppInfoPart(const uint8_t *data, size_t size, AppInfo *appInfo)
{
    DataGenerator::Write(data, size);
    GenerateInt32(appInfo->fd);
    GenerateInt32(appInfo->fileProtocol);
    GenerateInt32(appInfo->autoCloseTime);
    GenerateInt32(appInfo->myHandleId);
    GenerateInt32(appInfo->peerHandleId);
    GenerateInt32(appInfo->transFlag);
    GenerateInt64(appInfo->authSeq);
    GenerateInt32(appInfo->linkType);
    GenerateInt32(appInfo->connectType);
    GenerateInt32(appInfo->channelType);
    GenerateInt32(appInfo->errorCode);
    GenerateInt64(appInfo->timeStart);
    GenerateInt64(appInfo->connectedStart);
    GenerateUint64(appInfo->callingTokenId);
    GenerateBool(appInfo->isClient);
    GenerateInt32(appInfo->osType);
    GenerateUint32(appInfo->protocol);
    GenerateInt32(appInfo->encrypt);
    GenerateInt32(appInfo->algorithm);
    GenerateInt32(appInfo->crc);
    appInfo->fastTransData = (reinterpret_cast<const uint8_t *>(data));
    appInfo->fastTransDataSize = size;
    DataGenerator::Clear();
}

static void FillAppInfoPart(FuzzedDataProvider &provider, AppInfo *appInfo)
{
    auto dataSize = provider.ConsumeIntegral<uint32_t>();
    auto data = provider.ConsumeBytes<uint8_t>(dataSize);
    appInfo->fd = provider.ConsumeIntegral<int32_t>();
    appInfo->fileProtocol = provider.ConsumeIntegral<int32_t>();
    appInfo->autoCloseTime = provider.ConsumeIntegral<int32_t>();
    appInfo->myHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->peerHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->transFlag = provider.ConsumeIntegral<int32_t>();
    appInfo->authSeq = provider.ConsumeIntegral<int64_t >();
    appInfo->linkType = provider.ConsumeIntegral<int32_t>();
    appInfo->connectType = provider.ConsumeIntegral<int32_t>();
    appInfo->channelType= provider.ConsumeIntegral<int32_t>();
    appInfo->errorCode = provider.ConsumeIntegral<int32_t>();
    appInfo->timeStart = provider.ConsumeIntegral<int64_t >();
    appInfo->connectedStart = provider.ConsumeIntegral<int64_t >();
    appInfo->callingTokenId = provider.ConsumeIntegral<uint64_t>();
    appInfo->isClient = provider.ConsumeBool();
    appInfo->osType = provider.ConsumeIntegral<int32_t>();
    appInfo->protocol = provider.ConsumeIntegral<uint32_t>();
    appInfo->encrypt = provider.ConsumeIntegral<int32_t>();
    appInfo->algorithm = provider.ConsumeIntegral<int32_t>();
    appInfo->crc = provider.ConsumeIntegral<int32_t>();
    appInfo->fastTransData = data.data();
    appInfo->fastTransDataSize = dataSize;
    DataGenerator::Clear();
}

static void FillAppInfo(const uint8_t *data, size_t size, AppInfo *appInfo)
{
    int32_t cnt = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(cnt);
    appInfo->routeType = static_cast<RouteType>(cnt);
    GenerateInt32(cnt);
    appInfo->businessType = static_cast<BusinessType>(cnt);
    GenerateInt32(cnt);
    appInfo->streamType = static_cast<StreamType>(cnt);
    GenerateInt32(cnt);
    appInfo->udpConnType = static_cast<UdpConnType>(cnt);
    GenerateInt32(cnt);
    appInfo->udpChannelOptType = static_cast<UdpChannelOptType>(cnt);
    GenerateInt32(cnt);
    appInfo->appType = static_cast<AppType>(cnt);

    FillAppInfoPart(data, size, appInfo);
    DataGenerator::Clear();
}

static void FillAppInfo(FuzzedDataProvider &provider, AppInfo *appInfo)
{
    appInfo->routeType = static_cast<RouteType>(provider.ConsumeIntegral<int32_t>());
    appInfo->businessType = static_cast<BusinessType>(provider.ConsumeIntegral<int32_t>());
    appInfo->streamType = static_cast<StreamType>(provider.ConsumeIntegral<int32_t>());
    appInfo->udpConnType = static_cast<UdpConnType>(provider.ConsumeIntegral<int32_t>());
    appInfo->udpChannelOptType = static_cast<UdpChannelOptType>(provider.ConsumeIntegral<int32_t>());
    appInfo->appType = static_cast<AppType>(provider.ConsumeIntegral<int32_t>());

    FillAppInfoPart(provider, appInfo);
}

static void FillConnectOption(const uint8_t *data, size_t size, ConnectOption *connInfo)
{
    int32_t cnt = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(cnt);
    connInfo->type = static_cast<ConnectType>(cnt);
    DataGenerator::Clear();
}

static void FillConnectOption(FuzzedDataProvider &provider, ConnectOption *connInfo)
{
    connInfo->type = static_cast<ConnectType>(provider.ConsumeIntegral<int32_t>());
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

static uint8_t *TestDataSwitch(FuzzedDataProvider &provider)
{
    auto dataSize = provider.ConsumeIntegral<uint32_t>();
    auto data = provider.ConsumeBytes<uint8_t>(dataSize);
    uint8_t *dataWithEndCharacter = static_cast<uint8_t *>(SoftBusCalloc(dataSize + 1));
    if (dataWithEndCharacter == nullptr) {
        return nullptr;
    }
    if (memcpy_s(dataWithEndCharacter, dataSize, data.data(), dataSize) != EOK) {
        SoftBusFree(dataWithEndCharacter);
        return nullptr;
    }
    return dataWithEndCharacter;
}

void TransProxyGetNewChanSeqTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    (void)TransProxyGetNewChanSeq(channelId);
    DataGenerator::Clear();
}

void FillAppInfoTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
}

void TransProxyGetNewChanSeqTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyGetNewChanSeq(channelId);
}

void TransProxyOpenProxyChannelTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }

    int32_t channelId;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(data, size, &appInfo);
    ConnectOption connectOption;
    FillConnectOption(data, size, &connectOption);

    (void)TransProxyOpenProxyChannel(&appInfo, &connectOption, &channelId);
}

void TransProxyOpenProxyChannelTest(FuzzedDataProvider &provider)
{
    int32_t channelId;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    ConnectOption connectOption;
    FillConnectOption(provider, &connectOption);

    (void)TransProxyOpenProxyChannel(&appInfo, &connectOption, &channelId);
}

void TransProxyCloseProxyChannelTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    (void)TransProxyCloseProxyChannel(channelId);
    DataGenerator::Clear();
}

void TransProxyCloseProxyChannelTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
 
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
 
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyCloseProxyChannel(channelId);
}

void TransProxyDelByConnIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    uint32_t connId = 0;
    GenerateUint32(connId);

    TransProxyDelByConnId(connId);
    DataGenerator::Clear();
}

void TransProxyDelByConnIdTest(FuzzedDataProvider &provider)
{
    uint32_t connId = provider.ConsumeIntegral<uint32_t>();

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
 
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->connId = connId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    TransProxyDelByConnId(connId);
}

void TransProxyDelChanByReqIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t reqId = 0;
    int32_t errCode = 0;
    GenerateInt32(reqId);
    GenerateInt32(errCode);

    TransProxyDelChanByReqId(reqId, errCode);
    DataGenerator::Clear();
}

void TransProxyDelChanByReqIdTest(FuzzedDataProvider &provider)
{
    int32_t reqId = provider.ConsumeIntegral<int32_t>();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();

    TransProxyDelChanByReqId(reqId, errCode);
}

void TransProxyDelChanByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t chanId = 0;
    GenerateInt32(chanId);

    TransProxyDelChanByChanId(chanId);
    DataGenerator::Clear();
}

void TransProxyDelChanByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t chanId = provider.ConsumeIntegral<int32_t>();

    TransProxyDelChanByChanId(chanId);
}

void TransProxyGetChanByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t chanId = 0;
    GenerateInt32(chanId);
    ProxyChannelInfo chan;

    (void)TransProxyGetChanByChanId(chanId, &chan);
    DataGenerator::Clear();
}

void TransProxyGetChanByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyGetChanByChanId(channelId, proxyChannelInfo);
}

void TransProxyGetChanByReqIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t reqId = 0;
    GenerateInt32(reqId);
    ProxyChannelInfo chan;

    (void)TransProxyGetChanByReqId(reqId, &chan);
    DataGenerator::Clear();
}

void TransProxyGetChanByReqIdTest(FuzzedDataProvider &provider)
{
    int32_t reqId = provider.ConsumeIntegral<int32_t>();

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->reqId = reqId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyGetChanByReqId(reqId, proxyChannelInfo);
}

void TransProxyOpenProxyChannelSuccessTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    TransProxyOpenProxyChannelSuccess(channelId);
    DataGenerator::Clear();
}

void TransProxyOpenProxyChannelSuccessTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->type = CONNECT_BLE;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    TransProxyOpenProxyChannelSuccess(channelId);
}

void TransProxyOpenProxyChannelFailTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t errCode = 0;
    GenerateInt32(channelId);
    GenerateInt32(errCode);
    DataGenerator::Clear();

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(data, size, &appInfo);

    TransProxyOpenProxyChannelFail(channelId, &appInfo, errCode);
}

void TransProxyOpenProxyChannelFailTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    TransProxyOpenProxyChannelFail(channelId, &appInfo, errCode);
}

void TransProxyGetSessionKeyByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;

    (void)TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    DataGenerator::Clear();
}

void TransProxyGetSessionKeyByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->type = CONNECT_BLE;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;

    (void)TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
}

void TransProxyGetSendMsgChanInfoTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    ProxyChannelInfo chan;

    (void)TransProxyGetSendMsgChanInfo(channelId, &chan);
    DataGenerator::Clear();
}

void TransProxyGetSendMsgChanInfoTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyGetSendMsgChanInfo(channelId, proxyChannelInfo);
}

void TransProxyCreateChanInfoTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    DataGenerator::Clear();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(data, size, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    // proxyChannelInfo will be free at function TransProxyDelChanByChanId
    TransProxyDelChanByChanId(channelId);
}

void TransProxyCreateChanInfoTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    // proxyChannelInfo will be free at function TransProxyDelChanByChanId
    TransProxyDelChanByChanId(channelId);
}

void TransProxyChanProcessByReqIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t reqId = 0;
    uint32_t connId = 0;
    int32_t errCode = SOFTBUS_OK;
    GenerateInt32(reqId);
    GenerateUint32(connId);

    TransProxyChanProcessByReqId(reqId, connId, errCode);
    DataGenerator::Clear();
}

void TransProxyChanProcessByReqIdTest(FuzzedDataProvider &provider)
{
    int32_t reqId = provider.ConsumeIntegral<int32_t>();
    uint32_t connId = provider.ConsumeIntegral<int32_t>();
    int32_t errCode = SOFTBUS_OK;

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->reqId = reqId;
    proxyChannelInfo->connId = connId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    TransProxyChanProcessByReqId(reqId, connId, errCode);
}

void TransProxyGetAuthIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    AuthHandle authHandle;

    (void)TransProxyGetAuthId(channelId, &authHandle);
    DataGenerator::Clear();
}

void TransProxyGetAuthIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    AuthHandle authHandle;

    (void)TransProxyGetAuthId(channelId, &authHandle);
}

void TransProxyGetNameByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t chanId = 0;
    uint16_t pkgLen = 0;
    uint16_t sessionLen = 0;
    GenerateInt32(chanId);
    GenerateUint16(pkgLen);
    GenerateUint16(sessionLen);
    char pkgName[MAX_PACKAGE_NAME_LEN];
    char sessionName[SESSION_NAME_SIZE_MAX];

    (void)TransProxyGetNameByChanId(chanId, pkgName, sessionName, pkgLen, sessionLen);
    DataGenerator::Clear();
}

void TransProxyGetNameByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t chanId = provider.ConsumeIntegral<int32_t>();
    uint16_t pkgLen = provider.ConsumeIntegralInRange<uint16_t>(0, MAX_PACKAGE_NAME_LEN);
    uint16_t sessionLen = provider.ConsumeIntegralInRange<uint16_t>(0, SESSION_NAME_SIZE_MAX);
    char pkgName[MAX_PACKAGE_NAME_LEN];
    char sessionName[SESSION_NAME_SIZE_MAX];

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = chanId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, chanId, &appInfo);

    (void)TransProxyGetNameByChanId(chanId, pkgName, sessionName, pkgLen, sessionLen);
}

void TransRefreshProxyTimesNativeTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    (void)TransRefreshProxyTimesNative(channelId);
    DataGenerator::Clear();
}

void TransRefreshProxyTimesNativeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransRefreshProxyTimesNative(channelId);
}

void TransProxyDeathCallbackTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t pid = 0;
    GenerateInt32(pid);
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    TransProxyDeathCallback(pkgName, pid);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();
}

void TransProxyDeathCallbackTest(FuzzedDataProvider &provider)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(provider);
    if (dataWithEndCharacter == nullptr) {
        return;
    }
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    appInfo.myData.pid = pid;

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    TransProxyDeathCallback(pkgName, pid);
    SoftBusFree(dataWithEndCharacter);
}

void TransProxyGetAppInfoByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t chanId = 0;
    GenerateInt32(chanId);
    AppInfo appInfo;

    (void)TransProxyGetAppInfoByChanId(chanId, &appInfo);
    DataGenerator::Clear();
}

void TransProxyGetAppInfoByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t chanId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = chanId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, chanId, &appInfo);

    (void)TransProxyGetAppInfoByChanId(chanId, &appInfo);
    DataGenerator::Clear();
}

void TransProxyGetConnIdByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    int32_t connId;

    (void)TransProxyGetConnIdByChanId(channelId, &connId);
    DataGenerator::Clear();
}

void TransProxyGetConnIdByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);
    int32_t connId;

    (void)TransProxyGetConnIdByChanId(channelId, &connId);
}

void TransProxyGetConnOptionByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    ConnectOption connOpt;

    (void)TransProxyGetConnOptionByChanId(channelId, &connOpt);
    DataGenerator::Clear();
}

void TransProxyGetConnOptionByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);
    ConnectOption connOpt;

    (void)TransProxyGetConnOptionByChanId(channelId, &connOpt);
}

void TransProxyGetAppInfoTypeTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int16_t)) {
        return;
    }

    const char *identity = "test";
    DataGenerator::Write(data, size);
    int16_t myId = 0;
    GenerateInt16(myId);
    AppType appType;

    (void)TransProxyGetAppInfoType(myId, identity, &appType);
    DataGenerator::Clear();
}

void TransProxyGetAppInfoTypeTest(FuzzedDataProvider &provider)
{
    const char *identity = "test";
    int16_t myId = provider.ConsumeIntegral<int16_t>();
    AppType appType;

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    proxyChannelInfo->myId = myId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    (void)TransProxyGetAppInfoType(myId, identity, &appType);
}

static void InitProxyChannelInfo(const uint8_t *data, size_t size, ProxyChannelInfo *proxyChannelInfo)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    GenerateInt32(proxyChannelInfo->channelId);
    DataGenerator::Clear();
}

void TransProxySpecialUpdateChanInfoTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    ProxyChannelInfo proxyChannelInfo;
    InitProxyChannelInfo(data, size, &proxyChannelInfo);

    (void)TransProxySpecialUpdateChanInfo(&proxyChannelInfo);
}

void TransProxySpecialUpdateChanInfoTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.channelId = channelId;

    (void)TransProxySpecialUpdateChanInfo(&proxyChannelInfo);
}

static void InitAuthHandle(const uint8_t *data, size_t size, AuthHandle *authHandle)
{
    DataGenerator::Write(data, size);
    GenerateInt64(authHandle->authId);
    GenerateUint32(authHandle->type);
    DataGenerator::Clear();
}

void TransProxySetAuthHandleByChanIdTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);
    DataGenerator::Clear();

    AuthHandle authHandle;
    InitAuthHandle(data, size, &authHandle);

    (void)TransProxySetAuthHandleByChanId(channelId, authHandle);
}

void TransProxySetAuthHandleByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    AuthHandle authHandle;
    authHandle.authId = provider.ConsumeIntegral<int64_t>();
    authHandle.type = provider.ConsumeIntegral<uint32_t>();

    (void)TransProxySetAuthHandleByChanId(channelId, authHandle);
}

void TransProxyNegoSessionKeySuccTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    GenerateInt32(channelId);

    TransProxyNegoSessionKeySucc(channelId);
    DataGenerator::Clear();
}

void TransProxyNegoSessionKeySuccTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);

    TransProxyNegoSessionKeySucc(channelId);
}

void TransProxyNegoSessionKeyFailTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t errCode = 0;
    GenerateInt32(channelId);
    GenerateInt32(errCode);

    TransProxyNegoSessionKeyFail(channelId, errCode);
    DataGenerator::Clear();
}

void TransProxyNegoSessionKeyFailTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    proxyChannelInfo->channelId = channelId;
    (void)TransProxyCreateChanInfo(proxyChannelInfo, channelId, &appInfo);
    int32_t errCode = provider.ConsumeIntegral<int32_t>();

    TransProxyNegoSessionKeyFail(channelId, errCode);
    DataGenerator::Clear();
}

void ProxyChannelListLockTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    (void)GetProxyChannelMgrHead();
    (void)GetProxyChannelLock();
    (void)ReleaseProxyChannelLock();
}

void ProxyChannelListLockTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)GetProxyChannelMgrHead();
    (void)GetProxyChannelLock();
    (void)ReleaseProxyChannelLock();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::SoftBusProxyChannelManagerTestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::FillAppInfoTest(provider);
    OHOS::TransProxyGetNewChanSeqTest(provider);
    OHOS::TransProxyOpenProxyChannelTest(provider);
    OHOS::TransProxyDelByConnIdTest(provider);
    OHOS::TransProxyDelChanByReqIdTest(provider);
    OHOS::TransProxyDelChanByChanIdTest(provider);
    OHOS::TransProxyGetChanByChanIdTest(provider);
    OHOS::TransProxyGetChanByReqIdTest(provider);
    OHOS::TransProxyOpenProxyChannelSuccessTest(provider);
    OHOS::TransProxyOpenProxyChannelFailTest(provider);
    OHOS::TransProxyGetSessionKeyByChanIdTest(provider);
    OHOS::TransProxyGetSendMsgChanInfoTest(provider);
    OHOS::TransProxyCreateChanInfoTest(provider);
    OHOS::TransProxyChanProcessByReqIdTest(provider);
    OHOS::TransProxyGetAuthIdTest(provider);
    OHOS::TransProxyGetNameByChanIdTest(provider);
    OHOS::TransRefreshProxyTimesNativeTest(provider);
    OHOS::TransProxyDeathCallbackTest(provider);
    OHOS::TransProxyGetAppInfoByChanIdTest(provider);
    OHOS::TransProxyGetConnIdByChanIdTest(provider);
    OHOS::TransProxyGetConnOptionByChanIdTest(provider);
    OHOS::TransProxyGetAppInfoTypeTest(provider);
    OHOS::TransProxySpecialUpdateChanInfoTest(provider);
    OHOS::TransProxySetAuthHandleByChanIdTest(provider);
    OHOS::TransProxyNegoSessionKeySuccTest(provider);
    OHOS::TransProxyNegoSessionKeyFailTest(provider);
    OHOS::ProxyChannelListLockTest(provider);

    return 0;
}
