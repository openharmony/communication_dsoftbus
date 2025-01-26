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

#include "fuzz_data_generator.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_qos.h"

namespace OHOS {
class SoftBusProxyChannelManagerTestEnv {
public:
    SoftBusProxyChannelManagerTestEnv()
    {
        isInited_ = false;
        (void)ConnServerInit();
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        (void)InitQos();
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

static void FillConnectOption(const uint8_t *data, size_t size, ConnectOption *connInfo)
{
    int32_t cnt = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(cnt);
    connInfo->type = static_cast<ConnectType>(cnt);
    DataGenerator::Clear();
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

void ProxyChannelListLockTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
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

    /* Run your code on data */
    OHOS::TransProxyGetNewChanSeqTest(data, size);
    OHOS::TransProxyOpenProxyChannelTest(data, size);
    OHOS::TransProxyCloseProxyChannelTest(data, size);
    OHOS::TransProxyDelByConnIdTest(data, size);
    OHOS::TransProxyDelChanByReqIdTest(data, size);
    OHOS::TransProxyDelChanByChanIdTest(data, size);
    OHOS::TransProxyGetChanByChanIdTest(data, size);
    OHOS::TransProxyGetChanByReqIdTest(data, size);
    OHOS::TransProxyOpenProxyChannelSuccessTest(data, size);
    OHOS::TransProxyOpenProxyChannelFailTest(data, size);
    OHOS::TransProxyGetSessionKeyByChanIdTest(data, size);
    OHOS::TransProxyGetSendMsgChanInfoTest(data, size);
    OHOS::TransProxyCreateChanInfoTest(data, size);
    OHOS::TransProxyChanProcessByReqIdTest(data, size);
    OHOS::TransProxyGetAuthIdTest(data, size);
    OHOS::TransProxyGetNameByChanIdTest(data, size);
    OHOS::TransRefreshProxyTimesNativeTest(data, size);
    OHOS::TransProxyDeathCallbackTest(data, size);
    OHOS::TransProxyGetAppInfoByChanIdTest(data, size);
    OHOS::TransProxyGetConnIdByChanIdTest(data, size);
    OHOS::TransProxyGetConnOptionByChanIdTest(data, size);
    OHOS::TransProxyGetAppInfoTypeTest(data, size);
    OHOS::TransProxySpecialUpdateChanInfoTest(data, size);
    OHOS::TransProxySetAuthHandleByChanIdTest(data, size);
    OHOS::TransProxyNegoSessionKeySuccTest(data, size);
    OHOS::TransProxyNegoSessionKeyFailTest(data, size);
    OHOS::ProxyChannelListLockTest(data, size);

    return 0;
}
