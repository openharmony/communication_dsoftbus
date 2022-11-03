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
#include "softbus_ipc_def.h"
#include "softbus_log.h"

using namespace OHOS;

namespace {
sptr<BusCenterServerProxy> g_serverProxy = nullptr;
uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    sptr<IRemoteObject> object = GetSystemAbility();
    if (object == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get remote softbus object failed!\n");
        return SOFTBUS_ERR;
    }
    g_serverProxy = new (std::nothrow) BusCenterServerProxy(object);
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Create bus center server proxy failed!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    return SOFTBUS_OK;
}

void BusCenterServerProxyDeInit(void)
{
    delete g_serverProxy;
    g_serverProxy = nullptr;
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetAllOnlineNodeInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
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
        return SOFTBUS_SERVER_NOT_INIT;
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
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->GetNodeKeyInfo(pkgName, networkId, key, buf, len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetNodeKeyInfo get node key info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcSetNodeDataChangeFlag g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->SetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcSetNodeDataChangeFlag get node key info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, unsigned int addrTypeLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->JoinLNN(pkgName, addr, addrTypeLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinLNN failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcJoinMetaNode(const char *pkgName, void *addr, CustomData *customData, unsigned int addrTypeLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinMetaNode g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->JoinMetaNode(pkgName, addr, customData, addrTypeLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcJoinMetaNode failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->LeaveLNN(pkgName, networkId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveLNN failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcLeaveMetaNode(const char *pkgName, const char *networkId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveMetaNode g_serverProxy is nullptr!\n");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->LeaveMetaNode(pkgName, networkId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcLeaveMetaNode failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStartTimeSync g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
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
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->StopTimeSync(pkgName, targetNetworkId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopTimeSync failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcPublishLNN(const char *pkgName, const void *info, uint32_t infoLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcPublishLNN g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->PublishLNN(pkgName, info, infoLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcPublishLNN failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopPublishLNN g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->StopPublishLNN(pkgName, publishId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopPublishLNN failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcRefreshLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcRefreshLNN g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->RefreshLNN(pkgName, info, infoTypeLen);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcRefreshLNN failed!");
    }
    return ret;
}

int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopRefreshLNN g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->StopRefreshLNN(pkgName, refreshId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcStopRefreshLNN failed!");
    }
    return ret;
}

int32_t ServerIpcActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)pkgName;
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcActiveMetaNode g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->ActiveMetaNode(info, metaNodeId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcActiveMetaNode failed!");
    }
    return ret;
}

int32_t ServerIpcDeactiveMetaNode(const char *pkgName, const char *metaNodeId)
{
    (void)pkgName;
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcDeactiveMetaNode g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->DeactiveMetaNode(metaNodeId);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcDeactiveMetaNode failed!");
    }
    return ret;
}

int32_t ServerIpcGetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    (void)pkgName;
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetAllMetaNodeInfo g_serverProxy is nullptr!");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    int ret = g_serverProxy->GetAllMetaNodeInfo(infos, infoNum);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcGetAllMetaNodeInfo failed!");
    }
    return ret;
}

int32_t ServerIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcShiftLNNGear g_serverProxy is nullptr!");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ServerIpcShiftLNNGear failed!");
    }
    return ret;
}
