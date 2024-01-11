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

#include <mutex>
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_log.h"

using namespace OHOS;

namespace {
sptr<TransServerProxy> g_serverProxy = nullptr;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
uint32_t g_getSystemAbilityId = 2;
std::mutex g_mutex;
}

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        return nullptr;
    }

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        TRANS_LOGE(TRANS_SDK, "Get samgr failed!");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        TRANS_LOGE(TRANS_SDK, "Get GetSystemAbility failed!");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t TransServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy != nullptr) {
        TRANS_LOGI(TRANS_SDK, "Init success");
        return SOFTBUS_OK;
    }

    sptr<IRemoteObject> object = GetSystemAbility();
    if (object == nullptr) {
        TRANS_LOGE(TRANS_SDK, "Get remote softbus object failed!");
        return SOFTBUS_ERR;
    }
    g_serverProxy = new (std::nothrow) TransServerProxy(object);
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "Create trans server proxy failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransServerProxyDeInit(void)
{
    TRANS_LOGI(TRANS_SDK, "enter");
    g_serverProxy.clear();
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName is nullptr!");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->CreateSessionServer(pkgName, sessionName);
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName is nullptr!");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->RemoveSessionServer(pkgName, sessionName);
}

int32_t ServerIpcOpenSession(const SessionParam *param, TransInfo *info)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_NO_INIT;
    }
    if ((param->sessionName == nullptr) || (param->peerSessionName == nullptr) ||
        (param->peerDeviceId == nullptr) || (param->groupId == nullptr) || (param->attr == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "parameter is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = g_serverProxy->OpenSession(param, info);
    if (ret < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenSession failed! ret=%{public}d.", ret);
        return ret;
    }
    return ret;
}

int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    if ((sessionName == nullptr) || (addrInfo == nullptr)) {
        TRANS_LOGE(TRANS_SDK, "parameter is nullptr!");
        return SOFTBUS_ERR;
    }
    int channelId = g_serverProxy->OpenAuthSession(sessionName, addrInfo);
    if (channelId < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenAuthSession failed!");
        return SOFTBUS_ERR;
    }
    return channelId;
}

int32_t ServerIpcNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    return g_serverProxy->NotifyAuthSuccess(channelId, channelType);
}

int32_t ServerIpcCloseChannel(int32_t channelId, int32_t channelType)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    if (channelId < SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid channel Id!");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->CloseChannel(channelId, channelType);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }

    return g_serverProxy->SendMessage(channelId, channelType, data, len, msgType);
}

int32_t ServerIpcQosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_QOS, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->QosReport(channelId, chanType, appType, quality);
}

int32_t ServerIpcStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "softbus server g_serverProxy is nullptr");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->StreamStats(channelId, channelType, data);
}

int32_t ServerIpcRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->RippleStats(channelId, channelType, data);
}

int32_t ServerIpcGrantPermission(int uid, int pid, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        if (TransServerProxyInit() != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "grant permission g_serverProxy is nullptr!");
            return SOFTBUS_ERR;
        }
    }
    if (sessionName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "sessionName is nullptr");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->GrantPermission(uid, pid, sessionName);
}

int32_t ServerIpcRemovePermission(const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    if (sessionName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "sessionName is nullptr");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->RemovePermission(sessionName);
}

int32_t ServerIpcEvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    if (g_serverProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus server g_serverProxy is nullptr!");
        return SOFTBUS_NO_INIT;
    }

    if (peerNetworkId == NULL || dataType >= DATA_TYPE_BUTT || qosCount > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return g_serverProxy->EvaluateQos(peerNetworkId, dataType, qos, qosCount);
}

void TransBroadCastReInit(void)
{
    TRANS_LOGI(TRANS_SDK, "server died, try to ReRegistereventLisenter");
    TransBroadCastInit();
}
