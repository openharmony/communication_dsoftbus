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
#include "softbus_proxychannel_manager.h"

namespace OHOS {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
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
    appInfo->fileProtocol = *(reinterpret_cast<const int32_t *>(data));
    appInfo->autoCloseTime = *(reinterpret_cast<const int32_t *>(data));
    appInfo->myHandleId = *(reinterpret_cast<const int32_t *>(data));
    appInfo->peerHandleId = *(reinterpret_cast<const int32_t *>(data));
    appInfo->transFlag = *(reinterpret_cast<const int32_t *>(data));
    appInfo->authSeq = *(reinterpret_cast<const int64_t *>(data));
    appInfo->linkType = *(reinterpret_cast<const int32_t *>(data));
    appInfo->connectType = *(reinterpret_cast<const int32_t *>(data));
    appInfo->channelType = *(reinterpret_cast<const int32_t *>(data));
    appInfo->errorCode = *(reinterpret_cast<const int32_t *>(data));
    appInfo->timeStart = *(reinterpret_cast<const int64_t *>(data));
    appInfo->connectedStart = *(reinterpret_cast<const int64_t *>(data));
    appInfo->fastTransData = (reinterpret_cast<const uint8_t *>(data));
    appInfo->fastTransDataSize = *(reinterpret_cast<const uint16_t *>(data));
    appInfo->callingTokenId = *(reinterpret_cast<const uint32_t *>(data));
    appInfo->isClient = *(reinterpret_cast<const bool *>(data));
    appInfo->osType = *(reinterpret_cast<const int32_t *>(data));
}

static void FillAppInfo(const uint8_t *data, size_t size, AppInfo *appInfo)
{
    appInfo->routeType = static_cast<RouteType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->businessType = static_cast<BusinessType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->streamType = static_cast<StreamType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->udpConnType = static_cast<UdpConnType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->udpChannelOptType = static_cast<UdpChannelOptType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->fd = *(reinterpret_cast<const int32_t *>(data));
    appInfo->appType = static_cast<AppType>(*(reinterpret_cast<const int32_t *>(data)));
    appInfo->myData = *(reinterpret_cast<const AppInfoData *>(data));
    appInfo->peerData = *(reinterpret_cast<const AppInfoData *>(data));
    appInfo->protocol = *(reinterpret_cast<const int32_t *>(data));
    appInfo->encrypt = *(reinterpret_cast<const int32_t *>(data));
    appInfo->algorithm = *(reinterpret_cast<const int32_t *>(data));
    appInfo->crc = *(reinterpret_cast<const int32_t *>(data));
    FillAppInfoPart(data, size, appInfo);
}

static void FillConnectOption(const uint8_t *data, size_t size, ConnectOption *connInfo)
{
    connInfo->type = static_cast<ConnectType>(*(reinterpret_cast<const int32_t *>(data)));
}

void TransProxyGetNewChanSeqTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    TransProxyGetNewChanSeq(channelId);
}

void TransProxyOpenProxyChannelTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(AppInfo))) {
        return;
    }
    int32_t channelId;
    AppInfo appInfo;
    FillAppInfo(data, size, &appInfo);
    ConnectOption connectOption;
    FillConnectOption(data, size, &connectOption);
    TransProxyOpenProxyChannel(&appInfo, &connectOption, &channelId);
}

void TransProxyCloseProxyChannelTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    TransProxyCloseProxyChannel(channelId);
}

void TransProxyDelByConnIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    uint32_t connId = *(reinterpret_cast<const uint32_t *>(data));
    TransProxyDelByConnId(connId);
}

void TransProxyDelChanByReqIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t reqId = *(reinterpret_cast<const int32_t *>(data));
    int32_t errCode = *(reinterpret_cast<const int32_t *>(data));
    TransProxyDelChanByReqId(reqId, errCode);
}

void TransProxyDelChanByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t chanId = *(reinterpret_cast<const int32_t *>(data));
    TransProxyDelChanByChanId(chanId);
}

void TransProxyGetChanByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t chanId = *(reinterpret_cast<const int32_t *>(data));
    ProxyChannelInfo chan;
    TransProxyGetChanByChanId(chanId, &chan);
}

void TransProxyGetChanByReqIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t reqId = *(reinterpret_cast<const int32_t *>(data));
    ProxyChannelInfo chan;
    TransProxyGetChanByReqId(reqId, &chan);
}

void TransProxyOpenProxyChannelSuccessTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    TransProxyOpenProxyChannelSuccess(channelId);
}

void TransProxyOpenProxyChannelFailTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(AppInfo))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t errCode = *(reinterpret_cast<const int32_t *>(data));
    AppInfo appInfo;
    FillAppInfo(data, size, &appInfo);
    TransProxyOpenProxyChannelFail(channelId, &appInfo, errCode);
}

void TransProxyGetSessionKeyByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;
    TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
}

void TransProxyGetSendMsgChanInfoTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    ProxyChannelInfo chan;
    TransProxyGetSendMsgChanInfo(channelId, &chan);
}

void TransProxyCreateChanInfoTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(AppInfo))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    AppInfo appInfo;
    FillAppInfo(data, size, &appInfo);
    ProxyChannelInfo chan;
    TransProxyCreateChanInfo(&chan, channelId, &appInfo);
}

void TransProxyChanProcessByReqIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t reqId = *(reinterpret_cast<const int32_t *>(data));
    uint32_t connId = *(reinterpret_cast<const uint32_t *>(data));
    TransProxyChanProcessByReqId(reqId, connId);
}

void TransProxyGetAuthIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    AuthHandle authHandle;
    TransProxyGetAuthId(channelId, &authHandle);
}

void TransProxyGetNameByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t chanId = *(reinterpret_cast<const int32_t *>(data));
    uint16_t pkgLen = *(reinterpret_cast<const uint16_t *>(data));
    uint16_t sessionLen = *(reinterpret_cast<const uint16_t *>(data));
    char pkgName[MAX_PACKAGE_NAME_LEN];
    char sessionName[SESSION_NAME_SIZE_MAX];
    TransProxyGetNameByChanId(chanId, pkgName, sessionName, pkgLen, sessionLen);
}

void TransRefreshProxyTimesNativeTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    TransRefreshProxyTimesNative(channelId);
}

void TransProxyDeathCallbackTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(data));
    int32_t pid = *(reinterpret_cast<const int32_t *>(data));
    TransProxyDeathCallback(pkgName, pid);
}

void TransProxyGetAppInfoByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t chanId = *(reinterpret_cast<const int32_t *>(data));
    AppInfo appInfo;
    TransProxyGetAppInfoByChanId(chanId, &appInfo);
}

void TransProxyGetConnIdByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t connId;
    TransProxyGetConnIdByChanId(channelId, &connId);
}

void TransProxyGetConnOptionByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    ConnectOption connOpt;
    TransProxyGetConnOptionByChanId(channelId, &connOpt);
}

void TransProxyGetAppInfoTypeTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int16_t))) {
        return;
    }
    const char *identity = "test";
    int16_t myId = *(reinterpret_cast<const int16_t *>(data));
    AppType appType;
    TransProxyGetAppInfoType(myId, identity, &appType);
}

void TransProxySpecialUpdateChanInfoTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(ProxyChannelInfo))) {
        return;
    }
    ProxyChannelInfo channelInfo;
    channelInfo.channelId = *(reinterpret_cast<const int32_t *>(data));
    TransProxySpecialUpdateChanInfo(&channelInfo);
}

void TransProxySetAuthHandleByChanIdTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    AuthHandle authHandle;
    authHandle.authId = *(reinterpret_cast<const int64_t *>(data));
    authHandle.type = *(reinterpret_cast<const uint32_t *>(data));
    TransProxySetAuthHandleByChanId(channelId, authHandle);
}

void TransProxyNegoSessionKeySuccTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    TransProxyNegoSessionKeySucc(channelId);
}

void TransProxyNegoSessionKeyFailTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t errCode = *(reinterpret_cast<const int32_t *>(data));
    TransProxyNegoSessionKeyFail(channelId, errCode);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TestEnv env;
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
    return 0;
}