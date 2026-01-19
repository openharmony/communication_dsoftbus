/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "comm_log.h"
#include "g_enhance_sdk_func.h"
#include "ipc_skeleton.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "g_enhance_sdk_func.h"

using namespace OHOS;

namespace {
sptr<BusCenterServerProxy> g_serverProxy = nullptr;
sptr<IRemoteObject> g_oldServerProxy = nullptr;
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
    if (!data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER)) {
        LNN_LOGE(LNN_EVENT, "write SOFTBUS_SERVER_SA_ID_INNER failed");
        return nullptr;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "Get samgr failed");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        LNN_LOGE(LNN_EVENT, "Get GetSystemAbility failed=%{public}d", err);
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy != nullptr) {
        LNN_LOGI(LNN_INIT, "Init success");
        return SOFTBUS_OK;
    }
    sptr<IRemoteObject> object = GetSystemAbility();
    if (object == nullptr) {
        LNN_LOGE(LNN_EVENT, "Get remote softbus object failed");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    if (object == g_oldServerProxy) {
        LNN_LOGW(LNN_EVENT, "no need update");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    g_serverProxy = new (std::nothrow) BusCenterServerProxy(object);
    if (g_serverProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "Create bus center server proxy failed");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    g_oldServerProxy = object;
    int32_t ret = g_serverProxy->BusCenterServerProxyStandardInit();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "Create bus center server proxy standard failed");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    return SOFTBUS_OK;
}

static int32_t CheckAndInitBusCenterServerProxyInit(void)
{
    if (g_serverProxy == nullptr) {
        int32_t ret = BusCenterServerProxyInit();
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "BusCenterServerProxyInit failed, ret=%{public}d", ret);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t ClientCheckFuncPointer(void *func)
{
    if (func == NULL) {
        LNN_LOGE(LNN_EVENT, "enhance func not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

static void BusCenterExProxyDeInitPacked(void)
{
    ClientEnhanceFuncList *pfnClientEnhanceFuncList = ClientEnhanceFuncListGet();
    ClientRegisterEnhanceFuncCheck((void *)pfnClientEnhanceFuncList->busCenterExProxyDeInit);
    if (ClientCheckFuncPointer((void *)pfnClientEnhanceFuncList->busCenterExProxyDeInit) != SOFTBUS_OK) {
        return;
    }
    return pfnClientEnhanceFuncList->busCenterExProxyDeInit();
}

void BusCenterServerProxyDeInit(void)
{
    BusCenterExProxyDeInitPacked();
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "g_serverProxy is nullptr");
        return;
    }
    g_serverProxy->BusCenterServerProxyStandardDeInit();
    g_serverProxy.clear();
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->GetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->GetLocalDeviceInfo(pkgName, info, infoTypeLen);
    return ret;
}

int32_t ServerIpcGetNodeKeyInfo(
    const char *pkgName, const char *networkId, int32_t key, unsigned char *buf, uint32_t len)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->GetNodeKeyInfo(pkgName, networkId, key, buf, len);
    return ret;
}

int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->SetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    return ret;
}

int32_t ServerIpcRegDataLevelChangeCb(const char *pkgName)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->RegDataLevelChangeCb(pkgName);
    return ret;
}

int32_t ServerIpcUnregDataLevelChangeCb(const char *pkgName)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->UnregDataLevelChangeCb(pkgName);
    return ret;
}

int32_t ServerIpcSetDataLevel(const DataLevel *dataLevel)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->SetDataLevel(dataLevel);
    return ret;
}

int32_t ServerIpcRegRangeCbForMsdp(const char *pkgName)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->RegisterRangeCallbackForMsdp(pkgName);
    return ret;
}

int32_t ServerIpcUnregRangeCbForMsdp(const char *pkgName)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->UnregisterRangeCallbackForMsdp(pkgName);
    return ret;
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen, bool isForceJoin)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->JoinLNN(pkgName, addr, addrTypeLen, isForceJoin);
    return ret;
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->LeaveLNN(pkgName, networkId);
    return ret;
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->StartTimeSync(pkgName, targetNetworkId, accuracy, period);
    return ret;
}

int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->StopTimeSync(pkgName, targetNetworkId);
    return ret;
}

int32_t ServerIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->PublishLNN(pkgName, info);
    return ret;
}

int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->StopPublishLNN(pkgName, publishId);
    return ret;
}

int32_t ServerIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->RefreshLNN(pkgName, info);
    return ret;
}

int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->StopRefreshLNN(pkgName, refreshId);
    return ret;
}

int32_t ServerIpcActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)pkgName;
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->ActiveMetaNode(info, metaNodeId);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "active failed");
    }
    return ret;
}

int32_t ServerIpcDeactiveMetaNode(const char *pkgName, const char *metaNodeId)
{
    (void)pkgName;
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->DeactiveMetaNode(metaNodeId);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "deactive failed");
    }
    return ret;
}

int32_t ServerIpcGetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    (void)pkgName;
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->GetAllMetaNodeInfo(infos, infoNum);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "get info failed");
    }
    return ret;
}

int32_t ServerIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "shift failed");
    }
    return ret;
}

int32_t ServerIpcTriggerRangeForMsdp(const char *pkgName, const RangeConfig *config)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->TriggerRangeForMsdp(pkgName, config);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "trigger failed");
    }
    return ret;
}

int32_t ServerIpcStopRangeForMsdp(const char *pkgName, const RangeConfig *config)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->StopRangeForMsdp(pkgName, config);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "stop failed, error = %{public}d", ret);
    }
    return ret;
}

int32_t ServerIpcSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->SyncTrustedRelationShip(pkgName, msg, msgLen);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "sync failed");
    }
    return ret;
}

int32_t ServerIpcSetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    LNN_LOGI(LNN_EVENT, "enter");
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->SetDisplayName(pkgName, nameData, len);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "set failed");
    }
    return ret;
}

int32_t ServerIpcCreateGroupOwner(const char *pkgName, const struct GroupOwnerConfig *config,
    struct GroupOwnerResult *result)
{
    LNN_LOGI(LNN_EVENT, "enter");
    LNN_CHECK_AND_RETURN_RET_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, SOFTBUS_SERVER_NOT_INIT,
        LNN_EVENT, "server not init");
    int32_t ret = g_serverProxy->CreateGroupOwner(pkgName, config, result);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "create failed");
    }
    return ret;
}

void ServerIpcDestroyGroupOwner(const char *pkgName)
{
    LNN_LOGI(LNN_EVENT, "enter");
    LNN_CHECK_AND_RETURN_LOGE(CheckAndInitBusCenterServerProxyInit() == SOFTBUS_OK, LNN_EVENT, "server not init");
    g_serverProxy->DestroyGroupOwner(pkgName);
}