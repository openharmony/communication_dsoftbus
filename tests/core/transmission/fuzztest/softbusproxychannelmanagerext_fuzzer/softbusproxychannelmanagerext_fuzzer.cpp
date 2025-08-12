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

#include "softbusproxychannelmanagerext_fuzzer.h"

#include <chrono>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <thread>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "softbus_proxychannel_transceiver.h"

namespace OHOS {
class SoftBusProxyChannelManagerExt {
public:
    SoftBusProxyChannelManagerExt()
    {
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~SoftBusProxyChannelManagerExt()
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

static void FillAppInfo(FuzzedDataProvider &provider, AppInfo *appInfo)
{
    appInfo->fd = provider.ConsumeIntegral<int32_t>();
    appInfo->fileProtocol = provider.ConsumeIntegral<int32_t>();
    appInfo->autoCloseTime = provider.ConsumeIntegral<int32_t>();
    appInfo->myHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->peerHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->transFlag = provider.ConsumeIntegral<int32_t>();
    appInfo->authSeq = provider.ConsumeIntegral<int64_t>();
    appInfo->linkType = provider.ConsumeIntegral<int32_t>();
    appInfo->connectType = provider.ConsumeIntegral<int32_t>();
    appInfo->channelType = provider.ConsumeIntegral<int32_t>();
    appInfo->errorCode = provider.ConsumeIntegral<int32_t>();
    appInfo->timeStart = provider.ConsumeIntegral<int64_t>();
    appInfo->connectedStart = provider.ConsumeIntegral<int64_t>();
    appInfo->callingTokenId = provider.ConsumeIntegral<uint64_t>();
    appInfo->isClient = provider.ConsumeBool();
    appInfo->osType = provider.ConsumeIntegral<int32_t>();
    appInfo->protocol = provider.ConsumeIntegral<uint32_t>();
    appInfo->encrypt = provider.ConsumeIntegral<int32_t>();
    appInfo->algorithm = provider.ConsumeIntegral<int32_t>();
    appInfo->crc = provider.ConsumeIntegral<int32_t>();
}

static void FillProxyMessage(FuzzedDataProvider &provider, ProxyMessage *msg)
{
    msg->dataLen = provider.ConsumeIntegral<int32_t>();
    msg->data = (char *)SoftBusCalloc(msg->dataLen);
    if (msg->data == nullptr) {
        return;
    }
    (void)memset_s(msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    msg->connId = provider.ConsumeIntegral<uint32_t>();
    msg->keyIndex = provider.ConsumeIntegral<int32_t>();
    msg->msgHead.cipher = provider.ConsumeIntegral<uint8_t>();
    msg->msgHead.type = static_cast<MsgType>(
        provider.ConsumeIntegralInRange<int16_t>(PROXYCHANNEL_MSG_TYPE_NORMAL, PROXYCHANNEL_MSG_TYPE_MAX));
    msg->msgHead.myId = provider.ConsumeIntegral<int16_t>();
    msg->msgHead.peerId = provider.ConsumeIntegral<int16_t>();
    msg->msgHead.reserved = provider.ConsumeIntegral<int16_t>();
    msg->authHandle.authId = provider.ConsumeIntegral<int64_t>();
    msg->authHandle.type = provider.ConsumeIntegral<uint32_t>();
}

void ChanIsEqualTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)ReleaseChannelInfo(info);
    ProxyChannelInfo a;
    ProxyChannelInfo b;
    (void)memset_s(&a, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)memset_s(&b, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int8_t status = provider.ConsumeIntegral<int8_t>();
    a.myId = provider.ConsumeIntegral<int16_t>();
    a.peerId = provider.ConsumeIntegral<int16_t>();
    b.myId = provider.ConsumeIntegral<int16_t>();
    b.peerId = provider.ConsumeIntegral<int16_t>();
    (void)ChanIsEqual(&a, &b);
    (void)ResetChanIsEqual(status, &a, &b);
    (void)GetProxyChannelMgrHead();
    (void)GetProxyChannelLock();
    (void)ReleaseProxyChannelLock();
}

void TransProxyGetAppInfoTypeTest(FuzzedDataProvider &provider)
{
    int16_t myId = provider.ConsumeIntegral<int16_t>();
    char identity[IDENTITY_LEN] = { 0 };
    std::string providerData = provider.ConsumeBytesAsString(IDENTITY_LEN -1);
    if (strcpy_s(identity, IDENTITY_LEN, providerData.c_str()) != EOK) {
        return;
    }
    AppType appType = static_cast<AppType>(
        provider.ConsumeIntegralInRange<int16_t>(APP_TYPE_NOT_CARE, APP_TYPE_INNER));
    (void)TransProxyGetAppInfoType(myId, identity, &appType);
}

void TransPagingUpdatePagingChannelInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransPagingUpdatePagingChannelInfo(info);
    (void)TransProxyDelByChannelId(info->channelId, info);
}

void TransPagingUpdatePidAndDataTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t reqId = provider.ConsumeIntegral<int32_t>();
    char data[EXTRA_DATA_MAX_LEN] = { 0 };
    std::string providerData = provider.ConsumeBytesAsString(EXTRA_DATA_MAX_LEN);
    if (strcpy_s(data, EXTRA_DATA_MAX_LEN - 1, providerData.c_str()) != EOK) {
        return;
    }
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    (void)TransPagingUpdatePidAndData(channelId, pid, data, len);
    (void)TransUpdateAuthSeqByChannelId(channelId, reqId);
    (void)TransPagingUpdatePidAndData(info->channelId, pid, data, len);
    (void)TransUpdateAuthSeqByChannelId(info->channelId, reqId);
    (void)TransProxyDelByChannelId(info->channelId, info);
}

void TransPagingBadKeyRetryTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransPagingBadKeyRetry(channelId);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyUpdateAckInfo(info);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransProxyUpdateAckInfo(info);
    (void)TransPagingBadKeyRetry(info->channelId);
    (void)TransProxyDelByChannelId(info->channelId, info);
}

void TransRefreshProxyTimesNativeTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransRefreshProxyTimesNative(info->channelId);
    (void)TransProxySpecialUpdateChanInfo(info);
    (void)TransProxyGetChanByChanId(info->channelId, info);
    (void)TransProxyGetChanByReqId(info->reqId, info);
    AccessInfo accessInfo;
    (void)memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    (void)TransProxyUpdateSinkAccessInfo(info->channelId, &accessInfo);
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    int32_t reqId = provider.ConsumeIntegral<int32_t>();

    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransRefreshProxyTimesNative(info->channelId);
    (void)TransProxySpecialUpdateChanInfo(info);
    (void)TransProxyGetChanByChanId(info->channelId, info);
    (void)TransProxyGetChanByReqId(info->reqId, info);
    (void)TransProxyUpdateSinkAccessInfo(info->channelId, &accessInfo);
    (void)TransProxyDelChanByReqId(reqId, errCode);
    (void)TransProxyDelChanByReqId(info->reqId, errCode);
    (void)TransProxyDelByChannelId(info->channelId, info);
}

void TransProxyDelChanByChanIdTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    info->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    info->reqId = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyDelChanByChanId(channelId);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    uint32_t connId = provider.ConsumeIntegral<uint32_t>();
    (void)TransProxyChanProcessByReqId(0, connId, errCode);
    (void)TransProxyDelByConnId(info->connId);
}

void TransProxyGetSendMsgChanInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info1 = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ProxyChannelInfo info2;
    if (info1 == nullptr) {
        return;
    }
    int32_t channelId1 = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    info1->appInfo.waitOpenReplyCnt = LOOPER_REPLY_CNT_MAX;
    (void)TransProxyCreateChanInfo(info1, channelId1, &appInfo);
    AuthHandle authHandle;
    uint32_t channelCapability;
    int32_t reqId;
    int8_t status;
    AppInfo appInfoTemp;
    (void)memset_s(&appInfoTemp, sizeof(AppInfo), 0, sizeof(AppInfo));
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    (void)TransProxyGetSendMsgChanInfo(-1, &info2);
    (void)TransProxyGetNewChanSeq(-1);
    (void)TransProxyGetAuthId(-1, &authHandle);
    (void)TransProxyGetChannelCapaByChanId(-1, &channelCapability);
    (void)TransProxyGetSessionKeyByChanId(-1, sessionKey, SESSION_KEY_LENGTH);
    (void)TransProxyGetAppInfoById(-1, &appInfoTemp);
    (void)TransProxyGetReqIdAndStatus(-1, &reqId, &status);
    (void)TransProxyUpdateReplyCnt(-1);
    int32_t curCount;
    (void)TransCheckProxyChannelOpenStatus(-1, &curCount);
    (void)TransAsyncProxyChannelTask(-1);
    char peerNetworkId[DEVICE_ID_SIZE_MAX];
    (void)TransGetRemoteDeviceIdByReqId(-1, peerNetworkId);

    (void)TransGetRemoteDeviceIdByReqId(info1->reqId, peerNetworkId);
    (void)TransCheckProxyChannelOpenStatus(info1->channelId, &curCount);
    (void)TransProxyUpdateReplyCnt(info1->channelId);
    (void)TransProxyGetReqIdAndStatus(info1->myId, &reqId, &status);
    (void)TransProxyGetAppInfoById(info1->channelId, &appInfoTemp);
    (void)TransProxyGetSessionKeyByChanId(info1->channelId, sessionKey, SESSION_KEY_LENGTH);
    (void)TransProxyGetChannelCapaByChanId(info1->channelId, &channelCapability);
    (void)TransProxyGetAuthId(info1->channelId, &authHandle);
    (void)TransProxyGetNewChanSeq(info1->channelId);
    (void)TransProxyGetSendMsgChanInfo(info1->channelId, &info2);
    (void)TransProxyDelChanByChanId(info1->channelId);
}

void TransProxyProcessErrMsgTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    info->appInfo.appType = APP_TYPE_NORMAL;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    appInfo.appType = APP_TYPE_NORMAL;
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyProcessErrMsg(info, errCode);
    (void)TransProxyDelChanByChanId(info->channelId);
}

void TransPagingHandshakeUnPackErrMsgTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    FillProxyMessage(provider, &msg);
    int32_t errCode;
    (void)TransPagingHandshakeUnPackErrMsg(info, &msg, &errCode);
    if (msg.data != nullptr) {
        SoftBusFree(msg.data);
    }
    (void)TransProxyDelChanByChanId(info->channelId);
}

void SelectRouteTypeTest(FuzzedDataProvider &provider)
{
    ConnectType type = static_cast<ConnectType>(
        provider.ConsumeIntegralInRange<int16_t>(CONNECT_TCP, CONNECT_TYPE_MAX));
    RouteType routeType;
    (void)SelectRouteType(type, &routeType);
}

void CheckAndGenerateSinkSessionKeyTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    FillProxyMessage(provider, &msg);
    uint32_t connId = provider.ConsumeIntegral<uint32_t>();
    int32_t retCode = provider.ConsumeIntegral<int32_t>();
    (void)CheckAndGenerateSinkSessionKey(info);
    (void)TransProxyFastDataRecv(info);
    (void)TransProxyFillChannelInfo(&msg, info);
    (void)TransProxySendHandShakeMsgWhenInner(connId, info, retCode);
    (void)TransProxyDelChanByChanId(info->channelId);
    if (msg.data != nullptr) {
        SoftBusFree(msg.data);
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::SoftBusProxyChannelManagerExt testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::ChanIsEqualTest(provider);
    OHOS::TransProxyGetAppInfoTypeTest(provider);
    OHOS::TransPagingUpdatePagingChannelInfoTest(provider);
    OHOS::TransPagingUpdatePidAndDataTest(provider);
    OHOS::TransPagingBadKeyRetryTest(provider);
    OHOS::TransRefreshProxyTimesNativeTest(provider);
    OHOS::TransProxyDelChanByChanIdTest(provider);
    OHOS::TransProxyGetSendMsgChanInfoTest(provider);
    OHOS::TransProxyProcessErrMsgTest(provider);
    OHOS::TransPagingHandshakeUnPackErrMsgTest(provider);
    OHOS::SelectRouteTypeTest(provider);
    OHOS::CheckAndGenerateSinkSessionKeyTest(provider);
    return 0;
}
