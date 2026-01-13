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
#include "softbus_proxychannel_transceiver.c"

namespace OHOS {
class SoftBusProxyChannelManagerExt {
public:
    SoftBusProxyChannelManagerExt()
    {
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        (void)LooperInit();
        (void)TransProxyLoopInit();
        (void)TransChannelResultLoopInit();
        (void)TransChannelInit();
        isInited_ = true;
    }

    ~SoftBusProxyChannelManagerExt()
    {
        isInited_ = false;
        (void)LooperDeinit();
        (void)TransProxyManagerDeinit();
        (void)TransChannelDeinit();
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
#define MAX_LEN 100
    msg->dataLen = provider.ConsumeIntegral<int32_t>() % MAX_LEN;
    msg->data = (char *)SoftBusCalloc(msg->dataLen);
    if (msg->data == nullptr) {
        return;
    }
    std::string providerData = provider.ConsumeBytesAsString(msg->dataLen - 1);
    if (strcpy_s(msg->data, msg->dataLen - 1, providerData.c_str()) != EOK) {
        return;
    }
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
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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
    std::string providerData = provider.ConsumeBytesAsString(IDENTITY_LEN - 1);
    if (strcpy_s(identity, IDENTITY_LEN, providerData.c_str()) != EOK) {
        return;
    }
    AppType appType = static_cast<AppType>(
        provider.ConsumeIntegralInRange<int16_t>(APP_TYPE_NOT_CARE, APP_TYPE_INNER));
    (void)TransProxyGetAppInfoType(myId, identity, &appType);
}

void TransPagingUpdatePagingChannelInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransPagingUpdatePagingChannelInfo(info);
    ProxyChannelInfo tmpInfo;
    (void)memset_s(&tmpInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)TransProxyDelByChannelId(channelId, &tmpInfo);
}

void TransPagingUpdatePidAndDataTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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
    (void)TransPagingUpdatePidAndData(channelId, pid, data, 0);
    (void)TransUpdateAuthSeqByChannelId(channelId, reqId);
    (void)TransPagingUpdatePidAndData(info->channelId, pid, data, EXTRA_DATA_MAX_LEN);
    (void)TransUpdateAuthSeqByChannelId(info->channelId, reqId);
    ProxyChannelInfo tmpInfo;
    (void)memset_s(&tmpInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)TransProxyDelByChannelId(channelId, &tmpInfo);
}

void TransPagingBadKeyRetryTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyUpdateAckInfo(info);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransProxyUpdateAckInfo(info);
    (void)TransPagingBadKeyRetry(info->channelId);
    ProxyChannelInfo tmpInfo;
    (void)memset_s(&tmpInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)TransProxyDelByChannelId(channelId, &tmpInfo);
}

void TransRefreshProxyTimesNativeTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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
    accessInfo.localTokenId = provider.ConsumeIntegral<uint64_t>();
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
    ProxyChannelInfo tmpInfo;
    (void)memset_s(&tmpInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)TransProxyDelByChannelId(channelId, &tmpInfo);
}

void TransProxyDelChanByChanIdTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    info->status = PROXY_CHANNEL_STATUS_PYH_CONNECTED;
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
    ProxyChannelInfo *info1 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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
    (void)TransProxyGetSendMsgChanInfo(info1->channelId, &info2);
    (void)TransProxyDelChanByChanId(info1->channelId);
}

void TransProxyProcessErrMsgTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    appInfo.appType = APP_TYPE_NOT_CARE;
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyProcessErrMsg(info, errCode);
    (void)TransProxyDelChanByChanId(info->channelId);
}

void TransPagingHandshakeUnPackErrMsgTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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
    (void)TransPagingHandshakeUnPackErrMsg(info, &msg, nullptr);
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
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
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

void TransHandleProxyChannelOpenedTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    info->channelId = provider.ConsumeIntegral<int32_t>();
    info->appInfo.myData.pid = provider.ConsumeIntegral<int32_t>();
    info->isD2D = provider.ConsumeBool();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    AccessInfo accessInfo;
    (void)memset_s(&accessInfo, sizeof(AccessInfo), 0, sizeof(AccessInfo));
    accessInfo.userId = provider.ConsumeIntegral<int32_t>();
    accessInfo.localTokenId = provider.ConsumeIntegral<uint64_t>();
    char businessAccountId[ACCOUNT_UID_LEN_MAX] = { 0 };
    char extraAccessInfo[EXTRA_ACCESS_INFO_LEN_MAX] = { 0 };
    std::string providerData = provider.ConsumeBytesAsString(ACCOUNT_UID_LEN_MAX);
    if (strcpy_s(businessAccountId, ACCOUNT_UID_LEN_MAX - 1, providerData.c_str()) != EOK) {
        return;
    }
    accessInfo.businessAccountId = businessAccountId;
    providerData = provider.ConsumeBytesAsString(EXTRA_ACCESS_INFO_LEN_MAX);
    if (strcpy_s(extraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX - 1, providerData.c_str()) != EOK) {
        return;
    }
    accessInfo.extraAccessInfo = extraAccessInfo;
    int32_t openResult = provider.ConsumeIntegral<int32_t>();
    (void)TransHandleProxyChannelOpened(info->channelId, info, &accessInfo);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, pid);
    (void)TransProxyDelChanByChanId(channelId);
}

void TransProxyUpdateBlePriorityTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t connId = provider.ConsumeIntegral<uint32_t>();
    BlePriority priority = static_cast<BlePriority>(
        provider.ConsumeIntegralInRange<int16_t>(BLE_PRIORITY_DEFAULT, BLE_PRIORITY_MAX));
    (void)TransProxyUpdateBlePriority(channelId, connId, priority);
    priority = static_cast<BlePriority>(
        provider.ConsumeIntegralInRange<int16_t>(BLE_PRIORITY_BALANCED, BLE_PRIORITY_LOW_POWER));
    (void)TransProxyUpdateBlePriority(channelId, connId, priority);
    (void)TransProxyTimerProc();
}

void TransWifiStateChangeTest(FuzzedDataProvider &provider)
{
    LnnEventBasicInfo info;
    info.event = static_cast<LnnEventType>(
        provider.ConsumeIntegralInRange<int16_t>(LNN_EVENT_IP_ADDR_CHANGED, LNN_EVENT_TYPE_MAX));
    LnnOnlineStateEventInfo lnnOnlineStateEventInfo;
    lnnOnlineStateEventInfo.basic = info;
    lnnOnlineStateEventInfo.isOnline = provider.ConsumeBool();
    char uuid[UUID_BUF_LEN] = { 0 };
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    char udid[UDID_BUF_LEN] = { 0 };
    std::string providerData = provider.ConsumeBytesAsString(UUID_BUF_LEN);
    if (strcpy_s(uuid, UUID_BUF_LEN - 1, providerData.c_str()) != EOK) {
        return;
    }
    providerData = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN - 1, providerData.c_str()) != EOK) {
        return;
    }
    providerData = provider.ConsumeBytesAsString(UDID_BUF_LEN);
    if (strcpy_s(udid, UDID_BUF_LEN - 1, providerData.c_str()) != EOK) {
        return;
    }
    lnnOnlineStateEventInfo.uuid = uuid;
    lnnOnlineStateEventInfo.networkId = networkId;
    lnnOnlineStateEventInfo.udid = udid;
    (void)TransWifiStateChange(reinterpret_cast<LnnEventBasicInfo *>(&lnnOnlineStateEventInfo));
    (void)TransNotifyOffLine(reinterpret_cast<LnnEventBasicInfo *>(&lnnOnlineStateEventInfo));
    LnnSingleNetworkOffLineEvent lnnSingleNetworkOffLineEvent;
    lnnSingleNetworkOffLineEvent.basic = info;
    lnnSingleNetworkOffLineEvent.networkId = networkId;
    lnnSingleNetworkOffLineEvent.udid = udid;
    lnnSingleNetworkOffLineEvent.uuid = uuid;
    lnnSingleNetworkOffLineEvent.type = static_cast<ConnectionAddrType>(
        provider.ConsumeIntegralInRange<int16_t>(CONNECTION_ADDR_WLAN, CONNECTION_ADDR_MAX));
    (void)TransNotifySingleNetworkOffLine(reinterpret_cast<LnnEventBasicInfo *>(&lnnSingleNetworkOffLineEvent));
    LnnMonitorHbStateChangedEvent lnnMonitorHbStateChangedEvent;
    lnnMonitorHbStateChangedEvent.basic = info;
    lnnMonitorHbStateChangedEvent.status = static_cast<SoftBusUserSwitchState>(
        provider.ConsumeIntegralInRange<int16_t>(SOFTBUS_USER_SWITCHED, SOFTBUS_USER_SWITCH_UNKNOWN));
    (void)TransNotifyUserSwitch(reinterpret_cast<LnnEventBasicInfo *>(&lnnMonitorHbStateChangedEvent));
}

void TransProxyGetNameByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t chanId = provider.ConsumeIntegral<int32_t>();
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerData1 = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerData1.c_str()) != EOK) {
        return;
    }
    std::string providerData2 = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerData2.c_str()) != EOK) {
        return;
    }
    (void)TransProxyGetNameByChanId(chanId, pkgName, sessionName, PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
}

void TransProxyCloseChannelByRequestIdTest(FuzzedDataProvider &provider)
{
    int32_t connId;
    ProxyChannelInfo info1;
    int32_t channelId;
    AuthHandle authHandle;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    authHandle.authId = provider.ConsumeIntegral<int64_t>();
    authHandle.type = provider.ConsumeIntegral<uint32_t>();
    uint32_t reqId = provider.ConsumeIntegral<uint32_t>();
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    info->channelId = provider.ConsumeIntegral<int32_t>();
    info->appInfo.myData.pid = provider.ConsumeIntegral<int32_t>();
    info->isD2D = provider.ConsumeBool();
    info->status = static_cast<ProxyChannelStatus>(
        provider.ConsumeIntegralInRange<int16_t>(PROXY_CHANNEL_STATUS_PYH_CONNECTED, PROXY_CHANNEL_STATUS_COMPLETED));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    (void)TransProxyGetAppInfoByChanId(info->channelId, &appInfo);
    (void)TransProxyGetConnIdByChanId(info->channelId, &connId);
    (void)TransProxyGetProxyChannelInfoByChannelId(info->channelId, &info1);
    (void)TransProxyGetProxyChannelIdByAuthReq(reqId, &channelId);
    (void)TransProxySetAuthHandleByChanId(info->channelId, authHandle);
    PagingListenCheckInfo checkInfo;
    checkInfo.businessFlag = provider.ConsumeIntegral<uint32_t>();
    checkInfo.channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyGetChannelByCheckInfo(&checkInfo, &info1, info->appInfo.isClient);
    (void)TransProxyGetPrivilegeCloseList(&privilegeCloseList, info->appInfo.callingTokenId, info->appInfo.myData.pid);
    (void)TransProxyResetReplyCnt(info->channelId);
    channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyResetReplyCnt(channelId);
    (void)TransProxyCloseChannelByRequestId(-1);
    (void)TransProxyCloseChannelByRequestId(info->reqId);
}

void TransDealProxyCheckCollabResultTest(FuzzedDataProvider &provider)
{
    (void)TransSessionMgrInit();
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    if (newNode == nullptr) {
        return;
    }
    if (strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), DMS_SESSIONNAME) != EOK) {
        SoftBusFree(newNode);
        return;
    }
    newNode->uid = provider.ConsumeIntegral<int32_t>();
    newNode->pid = provider.ConsumeIntegral<int32_t>();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t checkResult = provider.ConsumeIntegral<int32_t>();
    (void)TransSessionServerAddItem(newNode);
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        SoftBusFree(newNode);
        return;
    }
    info->channelId = channelId;
    info->appInfo.myData.pid = newNode->pid;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    (void)TransDealProxyCheckCollabResult(channelId, checkResult, newNode->pid);
    (void)TransSessionServerDelItem(DMS_SESSIONNAME);
    (void)TransProxyDelChanByChanId(channelId);
    (void)TransSessionMgrDeinit();
}

void TransProxyTimerItemProcTest(FuzzedDataProvider &provider)
{
    ListNode proxyProcList;
    ListInit(&proxyProcList);
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    uint16_t maxDataSize = 100;
    info->appInfo.fastTransDataSize = provider.ConsumeIntegral<uint16_t>() % maxDataSize;
    uint8_t *tmp = reinterpret_cast<uint8_t *>(SoftBusCalloc(info->appInfo.fastTransDataSize));
    if (tmp == nullptr) {
        SoftBusFree(info);
        return;
    }
    info->appInfo.fastTransData = tmp;
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->channelId = channelId;
    info->status = static_cast<ProxyChannelStatus>(
        provider.ConsumeIntegralInRange<int16_t>(PROXY_CHANNEL_STATUS_PYH_CONNECTED, PROXY_CHANNEL_STATUS_COMPLETED));
    ListAdd(&proxyProcList, &(info->node));
    (void)TransProxyTimerItemProc(&proxyProcList);
    (void)TransProxyDelChanByChanId(channelId);
}

void TransOnGenSuccessTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
#define MAX_LEN 100
    info->appInfo.fastTransDataSize = provider.ConsumeIntegral<uint16_t>() % MAX_LEN;
    uint8_t *tmp = reinterpret_cast<uint8_t *>(SoftBusCalloc(info->appInfo.fastTransDataSize));
    if (tmp == nullptr) {
        SoftBusFree(info);
        return;
    }
    info->appInfo.fastTransData = tmp;
    info->authReqId = provider.ConsumeIntegral<uint32_t>();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->channelId = channelId;
    info->status = static_cast<ProxyChannelStatus>(
        provider.ConsumeIntegralInRange<int16_t>(PROXY_CHANNEL_STATUS_PYH_CONNECTED, PROXY_CHANNEL_STATUS_COMPLETED));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    uint8_t applyKey[MAX_LEN] = { 0 };
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    (void)TransOnGenSuccess(info->authReqId, applyKey, MAX_LEN);
    (void)TransOnGenFailed(info->authReqId, 0);
    (void)TransProxyDelChanByChanId(channelId);
}

void TransPagingResetChanTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->channelId = channelId;
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    ProxyChannelInfo chanInfo;
    (void)memset_s(&chanInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    chanInfo.myId = info->myId;
    chanInfo.peerId = info->peerId;
    (void)TransPagingResetChan(&chanInfo);
    (void)TransProxyDelChanByChanId(channelId);
}

void TransProxyResetChanTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->channelId = channelId;
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    info->status = static_cast<ProxyChannelStatus>(
        provider.ConsumeIntegralInRange<int16_t>(PROXY_CHANNEL_STATUS_PYH_CONNECTED, PROXY_CHANNEL_STATUS_COMPLETED));
    std::string providerData = provider.ConsumeBytesAsString(IDENTITY_LEN -1);
    if (strcpy_s(info->identity, IDENTITY_LEN, providerData.c_str()) != EOK) {
        SoftBusFree(info);
        return;
    }
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    ProxyChannelInfo chanInfo;
    (void)memset_s(&chanInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    chanInfo.myId = info->myId;
    chanInfo.peerId = info->peerId;
    if (strcpy_s(chanInfo.identity, IDENTITY_LEN, providerData.c_str()) != EOK) {
        SoftBusFree(info);
        return;
    }
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    (void)TransProxyResetChan(&chanInfo);
    (void)TransProxyDelChanByChanId(channelId);
}

void TransProxyGetRecvMsgChanInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->channelId = channelId;
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    info->status = static_cast<ProxyChannelStatus>(
        provider.ConsumeIntegralInRange<int16_t>(PROXY_CHANNEL_STATUS_PYH_CONNECTED, PROXY_CHANNEL_STATUS_COMPLETED));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    ProxyChannelInfo chanInfo;
    (void)memset_s(&chanInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    chanInfo.myId = info->myId;
    chanInfo.peerId = info->peerId;
    (void)TransProxyCreateChanInfo(info, info->channelId, &appInfo);
    (void)TransProxyGetRecvMsgChanInfo(chanInfo.myId, chanInfo.peerId, &chanInfo);
    (void)TransProxyKeepAliveChan(&chanInfo);
    (void)TransProxyDelChanByChanId(channelId);
}

void FindConfigTypeTest(FuzzedDataProvider &provider)
{
    int32_t channelType = static_cast<int32_t>(
        provider.ConsumeIntegralInRange<int16_t>(CHANNEL_TYPE_PROXY, CHANNEL_TYPE_AUTH));
    int32_t businessType = static_cast<int32_t>(
        provider.ConsumeIntegralInRange<int16_t>(BUSINESS_TYPE_MESSAGE, BUSINESS_TYPE_D2D_VOICE));
    uint32_t len;
    (void)FindConfigType(channelType, businessType);
    (void)TransGetLocalConfig(channelType, businessType, &len);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    appInfo.businessType = static_cast<BusinessType>(
        provider.ConsumeIntegralInRange<int16_t>(BUSINESS_TYPE_MESSAGE, BUSINESS_TYPE_D2D_VOICE));
    (void)TransProxyProcessDataConfig(&appInfo);
}

void TransProxyHandshakeUnpackErrMsgTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    FillProxyMessage(provider, &msg);
    msg.msgHead.myId = info->myId;
    msg.msgHead.peerId = info->peerId;
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
#define MAX_LEN 100
    info->appInfo.fastTransDataSize = provider.ConsumeIntegral<uint16_t>() % MAX_LEN;
    uint8_t *tmp = reinterpret_cast<uint8_t *>(SoftBusCalloc(info->appInfo.fastTransDataSize));
    if (tmp == nullptr) {
        SoftBusFree(info);
        return;
    }
    info->appInfo.fastTransData = tmp;
    uint16_t fastDataSize = info->appInfo.fastTransDataSize;
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransProxyProcessHandshakeAckMsg(&msg);
    (void)TransProxyHandshakeUnpackRightMsg(info, &msg, errCode, nullptr);
    (void)TransProxyHandshakeUnpackRightMsg(info, &msg, errCode, &fastDataSize);
    (void)TransProxyHandshakeUnpackErrMsg(info, &msg, nullptr);
    (void)TransProxyHandshakeUnpackErrMsg(info, &msg, &errCode);
    (void)TransProxyDelChanByChanId(channelId);
    if (msg.data != nullptr) {
        SoftBusFree(msg.data);
    }
}

void TransProxyGetLocalInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->appInfo.appType = static_cast<AppType>(
        provider.ConsumeIntegralInRange<int16_t>(APP_TYPE_NOT_CARE, APP_TYPE_INNER));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    appInfo.appType = info->appInfo.appType;
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    ProxyChannelInfo chan;
    (void)memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    (void)TransProxyGetLocalInfo(&chan);
    ProxyMessageHead msgHead;
    (void)memset_s(&msgHead, sizeof(ProxyMessageHead), 0, sizeof(ProxyMessageHead));
    (void)CheckAppTypeAndMsgHead(&msgHead, &appInfo);
    (void)TransProxyDelChanByChanId(channelId);
}

void ConstructProxyChannelInfoTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo chan;
    (void)memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    int16_t newChanId = provider.ConsumeIntegral<int16_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = static_cast<AppType>(
        provider.ConsumeIntegralInRange<int16_t>(APP_TYPE_NOT_CARE, APP_TYPE_INNER));
    appInfo.businessType = static_cast<BusinessType>(
        provider.ConsumeIntegralInRange<int16_t>(BUSINESS_TYPE_MESSAGE, BUSINESS_TYPE_D2D_VOICE));
    appInfo.peerData.dataConfig = provider.ConsumeIntegral<uint32_t>();
    (void)ConstructProxyChannelInfo(&chan, &msg, newChanId, &info);
    (void)TransProxyFillDataConfig(&appInfo);
}

void TransProxyProcessHandshakeAuthMsgTest(FuzzedDataProvider &provider)
{
    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    FillProxyMessage(provider, &msg);
    msg.msgHead.myId = provider.ConsumeIntegral<int16_t>();
    msg.msgHead.peerId = provider.ConsumeIntegral<int16_t>();
    (void)TransProxyProcessHandshakeAuthMsg(&msg);
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    info->myId = provider.ConsumeIntegral<int16_t>();
    info->peerId = provider.ConsumeIntegral<int16_t>();
    info->connId = provider.ConsumeIntegral<uint32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    char tmpSocketName[SESSION_NAME_SIZE_MAX] = { 0 };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    TransEventExtra extra = { 0 };
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    FillProxyHandshakeExtra(&extra, info, tmpSocketName, &nodeInfo);
    info->appInfo.appType = APP_TYPE_INNER;
    int32_t retCode = provider.ConsumeIntegral<int32_t>();
    (void)TransProxySendHandShakeMsgWhenInner(info->connId, info, retCode);
    (void)TransProxyProcessHandshakeMsg(&msg);
    (void)TransProxyDelChanByChanId(channelId);
    if (msg.data != nullptr) {
        SoftBusFree(msg.data);
    }
}

void TransDisableConnBrIdleCheckTest(FuzzedDataProvider &provider)
{
    ProxyChannelInfo *info = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    if (info == nullptr) {
        return;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    FillAppInfo(provider, &appInfo);
    (void)TransProxyCreateChanInfo(info, channelId, &appInfo);
    (void)TransDisableConnBrIdleCheck(channelId);
    (void)TransProxyDelByConnId(info->connId);
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
    OHOS::TransHandleProxyChannelOpenedTest(provider);
    OHOS::TransProxyUpdateBlePriorityTest(provider);
    OHOS::TransWifiStateChangeTest(provider);
    OHOS::TransProxyGetNameByChanIdTest(provider);
    OHOS::TransProxyCloseChannelByRequestIdTest(provider);
    OHOS::TransDealProxyCheckCollabResultTest(provider);
    OHOS::TransProxyTimerItemProcTest(provider);
    OHOS::TransOnGenSuccessTest(provider);
    OHOS::TransPagingResetChanTest(provider);
    OHOS::TransProxyResetChanTest(provider);
    OHOS::TransProxyGetRecvMsgChanInfoTest(provider);
    OHOS::FindConfigTypeTest(provider);
    OHOS::TransProxyHandshakeUnpackErrMsgTest(provider);
    OHOS::TransProxyGetLocalInfoTest(provider);
    OHOS::ConstructProxyChannelInfoTest(provider);
    OHOS::TransProxyProcessHandshakeAuthMsgTest(provider);
    OHOS::TransDisableConnBrIdleCheckTest(provider);
    return 0;
}
