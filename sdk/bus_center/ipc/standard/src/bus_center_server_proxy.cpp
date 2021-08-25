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

#include "bus_center_server_proxy.h"
#include "bus_center_server_proxy_standard.h"

#include <mutex>
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "system_ability_definition.h"

using namespace OHOS;

namespace {
sptr<BusCenterServerProxy> g_serverProxy = nullptr;
uint32_t g_getSystemAbilityId = 2;
std::mutex g_mutex;
}

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;
    data.WriteInt32(SOFTBUS_SERVER_SA_ID);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    sptr<IRemoteObject> object = GetSystemAbility();
    g_serverProxy = new (std::nothrow) BusCenterServerProxy(object);
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get remote softbus object failed!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetAllOnlineNodeInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->GetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetAllOnlineNodeInfo get all online info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetLocalDeviceInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->GetLocalDeviceInfo(pkgName, info, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetLocalDeviceInfo get local device info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetNodeKeyInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->GetNodeKeyInfo(pkgName, networkId, key, buf, len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetNodeKeyInfo get node key info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, unsigned int addrTypeLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->JoinLNN(pkgName, addr, addrTypeLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinLNN failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->LeaveLNN(pkgName, networkId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveLNN failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStartTimeSync g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->StartTimeSync(pkgName, targetNetworkId, accuracy, period);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStartTimeSync failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopTimeSync g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->StopTimeSync(pkgName, targetNetworkId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopTimeSync failed!");
        return ret;
    }
    return SOFTBUS_OK;
}