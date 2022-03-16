/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "disc_server_proxy.h"
#include "disc_server_proxy_standard.h"

#include <mutex>
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

using namespace OHOS;

namespace {
sptr<DiscServerProxy> g_serverProxy = nullptr;
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
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t DiscServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    sptr<IRemoteObject> object = GetSystemAbility();
    if (object == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get remote softbus object failed!\n");
        return SOFTBUS_ERR;
    }
    g_serverProxy = new (std::nothrow) DiscServerProxy(object);
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Create disc server proxy failed!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DiscServerProxyDeInit(void)
{
    delete g_serverProxy;
    g_serverProxy = nullptr;
}

int32_t ServerIpcPublishService(const char *pkgName, const PublishInfo *info)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->PublishService(pkgName, info);
}

int32_t ServerIpcUnPublishService(const char *pkgName, int32_t publishId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->UnPublishService(pkgName, publishId);
    return ret;
}

int32_t ServerIpcStartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->StartDiscovery(pkgName, info);
}

int32_t ServerIpcStopDiscovery(const char *pkgName, int32_t subscribeId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->StopDiscovery(pkgName, subscribeId);
}
