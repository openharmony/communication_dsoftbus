/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "trans_server_proxy.h"
#include "trans_server_proxy_standard.h"

#include <malloc.h>
#include <mutex>

#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_log.h"

using namespace OHOS;

namespace {
sptr<TransServerProxy> g_serverProxy = nullptr;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
constexpr int32_t MIN_CHANNEL_ID = 0; // UDP channelId minmum value
constexpr int32_t MAX_CHANNEL_ID = 19; // UDP channelId maxmum value
uint32_t g_getSystemAbilityId = 2;
std::mutex g_mutex;
constexpr uint32_t RETRY_COUNT = 10;    // retry count of getting proxy object
constexpr uint32_t RETRY_INTERVAL = 50; // retry interval(ms)
}

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN), nullptr, TRANS_SDK, "write samgr interface token failed");

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    TRANS_CHECK_AND_RETURN_RET_LOGE(samgr != nullptr, nullptr, TRANS_SDK, "Get samgr failed");

    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    TRANS_CHECK_AND_RETURN_RET_LOGE(err == 0, nullptr, TRANS_SDK, "Get samgr failed");

    return reply.ReadRemoteObject();
}

static sptr<TransServerProxy> GetProxy()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy != nullptr) {
        return g_serverProxy;
    }

    sptr<IRemoteObject> object = GetSystemAbility();
    TRANS_CHECK_AND_RETURN_RET_LOGE(object != nullptr, nullptr, TRANS_SDK, "Get remote softbus object failed");

    g_serverProxy = new (std::nothrow) TransServerProxy(object);
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_serverProxy != nullptr, nullptr, TRANS_SDK, "Create trans server proxy failed");

    return g_serverProxy;
}

static sptr<TransServerProxy> RetryGetProxy()
{
    // retry 'RETRY_COUNT' times with an interval of 'RETRY_INTERVAL' ms
    sptr<TransServerProxy> proxy = nullptr;
    for (uint32_t count = 0; count < RETRY_COUNT; ++count) {
        proxy = GetProxy();
        if (proxy != nullptr) {
            return proxy;
        }
        TRANS_LOGD(TRANS_SDK, "softbus server g_serverProxy is nullptr, retry %{public}" PRIu32 "th time", count);
        SoftBusSleepMs(RETRY_INTERVAL);
    }
    TRANS_LOGE(TRANS_SDK, "Failed to get softbus server g_serverProxy");
    return nullptr;
}

int32_t TransServerProxyInit(void)
{
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_ENABLE);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        GetProxy() != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "Failed to initialize the server proxy");

    TRANS_LOGI(TRANS_SDK, "Init success");
    return SOFTBUS_OK;
}

void TransServerProxyDeInit(void)
{
    TRANS_LOGI(TRANS_SDK, "enter");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_serverProxy.clear();
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    sptr<TransServerProxy> proxy = RetryGetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->CreateSessionServer(pkgName, sessionName);
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    return proxy->RemoveSessionServer(pkgName, sessionName);
}

int32_t ServerIpcOpenSession(const SessionParam *param, TransInfo *info)
{
    sptr<TransServerProxy> proxy = RetryGetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if ((param->sessionName == nullptr) || (param->peerSessionName == nullptr) ||
        (param->peerDeviceId == nullptr) || (param->groupId == nullptr) || (param->attr == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "parameter is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = proxy->OpenSession(param, info);
    if (ret < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenSession failed! ret=%{public}d.", ret);
    }

    return ret;
}

int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    sptr<TransServerProxy> proxy = RetryGetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if ((sessionName == nullptr) || (addrInfo == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "parameter is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }

    int channelId = proxy->OpenAuthSession(sessionName, addrInfo);
    if (channelId < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenAuthSession failed!");
        return SOFTBUS_NO_INIT;
    }
    return channelId;
}

int32_t ServerIpcNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    return proxy->NotifyAuthSuccess(channelId, channelType);
}

int32_t ServerIpcCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if (channelId < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid channel Id!");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->CloseChannel(sessionName, channelId, channelType);
}

int32_t ServerIpcCloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    if (dataInfo == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if (channelId < MIN_CHANNEL_ID) {
        TRANS_LOGE(TRANS_SDK, "invalid channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->CloseChannelWithStatistics(channelId, channelType, laneId, dataInfo, len);
}

int32_t ServerIpcReleaseResources(int32_t channelId)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if ((channelId < MIN_CHANNEL_ID) || (channelId > MAX_CHANNEL_ID)) {
        TRANS_LOGE(TRANS_SDK, "channelId=%{public}d is invalid.", channelId);
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    return proxy->ReleaseResources(channelId);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    return g_serverProxy->SendMessage(channelId, channelType, data, len, msgType);
}

int32_t ServerIpcQosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    return proxy->QosReport(channelId, chanType, appType, quality);
}

int32_t ServerIpcStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    return proxy->StreamStats(channelId, channelType, data);
}

int32_t ServerIpcRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    return proxy->RippleStats(channelId, channelType, data);
}

int32_t ServerIpcGrantPermission(int uid, int pid, const char *sessionName)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if (sessionName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "sessionName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->GrantPermission(uid, pid, sessionName);
}

int32_t ServerIpcRemovePermission(const char *sessionName)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if (sessionName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "sessionName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->RemovePermission(sessionName);
}

int32_t ServerIpcEvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");

    if (peerNetworkId == NULL || dataType >= DATA_TYPE_BUTT || qosCount > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->EvaluateQos(peerNetworkId, dataType, qos, qosCount);
}

int32_t ServerIpcProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");
    if (eventType >= EVENT_TYPE_BUTT || eventType < EVENT_TYPE_CHANNEL_OPENED || buf == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return proxy->ProcessInnerEvent(eventType, buf, len);
}

int32_t ServerIpcPrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    if (peerNetworkId == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransServerProxy> proxy = GetProxy();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        proxy != nullptr, SOFTBUS_NO_INIT, TRANS_SDK, "softbus server g_serverProxy is nullptr");
    return proxy->PrivilegeCloseChannel(tokenId, pid, peerNetworkId);
}