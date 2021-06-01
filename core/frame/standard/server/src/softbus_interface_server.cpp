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

#include "softbus_interface.h"

#include <mutex>
#include <unistd.h>
#include "if_softbus_server.h"
#include "ipc_skeleton.h"
#include "softbus_client_death_recipient.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "system_ability_definition.h"

using namespace OHOS;

namespace {
sptr<ISoftBusServer> g_serverProxy = nullptr;
sptr<IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
std::mutex g_mutex;
uint32_t g_waitServerInterval = 2;
uint32_t g_getSystemAbilityId = 2;
}

static int ServerIpcStartDiscovery(const char *pkgName, const void *info)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->StartDiscovery(pkgName, info);
    return ret;
}

static int ServerIpcStopDiscovery(const char *pkgName, int subscribeId)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->StopDiscovery(pkgName, subscribeId);
    return ret;
}

static int ServerIpcPublishService(const char *pkgName, const void *info)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->PublishService(pkgName, info);
    return ret;
}

static int ServerIpcUnPublishService(const char *pkgName, int publishId)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->UnPublishService(pkgName, publishId);
    return ret;
}

static int ServerIpcRegisterService(const char *name, const void *info)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->SoftbusRegisterService(name, nullptr);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcRegisterService failed!\n");
        return ret;
    }
    LOG_INFO("softbus server register service success!\n");
    return SOFTBUS_OK;
}

static int ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        return SOFTBUS_ERR;
    }

    int ret = g_serverProxy->CreateSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("CreateSessionServer failed!\n");
        return ret;
    }
    LOG_INFO("softbus server create session server success!\n");
    return SOFTBUS_OK;
}

static int ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        return SOFTBUS_ERR;
    }

    int ret = g_serverProxy->RemoveSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("RemoveSessionServer failed!\n");
        return ret;
    }
    LOG_INFO("softbus server remove session server success!\n");
    return SOFTBUS_OK;
}

static int ServerIpcOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((mySessionName == nullptr) || (peerSessionName == nullptr) ||
        (peerDeviceId == nullptr) || (groupId == nullptr)) {
        return SOFTBUS_ERR;
    }

    int channelId = g_serverProxy->OpenSession(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
    if (channelId < SOFTBUS_OK) {
        LOG_ERR("OpenSession failed!\n");
        return SOFTBUS_ERR;
    }
    LOG_INFO("softbus server open session success!\n");
    return channelId;
}

static int ServerIpcSendMessage(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }

    int ret = g_serverProxy->SendMessage(channelId, data, len, msgType);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("OpenSession failed!\n");
        return ret;
    }
    LOG_INFO("softbus server open session success!\n");
    return SOFTBUS_OK;
}

static int ServerIpcJoinLNN(void *addr, unsigned int addrTypeLen)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("ServerIpcJoinLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("SoftbusJoinLNN get client name failed!");
        return ret;
    }
    ret = g_serverProxy->JoinLNN(clientName, addr, addrTypeLen);
    if (ret != 0) {
        LOG_ERR("ServerIpcJoinLNN failed!\n");
        return ret;
    }
    return ret;
}

static int ServerIpcLeaveLNN(const char *networkId)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("ServerIpcLeaveLNN g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcLeaveLNN get client name failed!");
        return ret;
    }
    ret = g_serverProxy->LeaveLNN(clientName, networkId);
    if (ret != 0) {
        LOG_ERR("ServerIpcLeaveLNN failed!\n");
        return ret;
    }
    return ret;
}

static int ServerIpcGetAllOnlineNodeInfo(void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("ServerIpcGetAllOnlineNodeInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetAllOnlineNodeInfo get client name failed!");
        return ret;
    }
    ret = g_serverProxy->GetAllOnlineNodeInfo(clientName, info, infoTypeLen, infoNum);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetAllOnlineNodeInfo get all online info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ServerIpcGetLocalDeviceInfo(void *info, uint32_t infoTypeLen)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("ServerIpcGetLocalDeviceInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetLocalDeviceInfo get client name failed!");
        return ret;
    }
    ret = g_serverProxy->GetLocalDeviceInfo(clientName, info, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetLocalDeviceInfo get local device info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ServerIpcGetNodeKeyInfo(const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    if (g_serverProxy == nullptr) {
        LOG_ERR("ServerIpcGetNodeKeyInfo g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetNodeKeyInfo get client name failed!");
        return ret;
    }

    ret = g_serverProxy->GetNodeKeyInfo(clientName, networkId, key, buf, len);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerIpcGetNodeKeyInfo get node key info failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

static struct ServerProvideInterface g_serverProvideInterface = {
    .startDiscovery = ServerIpcStartDiscovery,
    .createSessionServer = ServerIpcCreateSessionServer,
    .removeSessionServer = ServerIpcRemoveSessionServer,
    .openSession = ServerIpcOpenSession,
    .sendMessage = ServerIpcSendMessage,
    .stopDiscovery = ServerIpcStopDiscovery,
    .publishService = ServerIpcPublishService,
    .unPublishService = ServerIpcUnPublishService,
    .joinLNN = ServerIpcJoinLNN,
    .leaveLNN = ServerIpcLeaveLNN,
    .getAllOnlineNodeInfo = ServerIpcGetAllOnlineNodeInfo,
    .getLocalDeviceInfo = ServerIpcGetLocalDeviceInfo,
    .getNodeKeyInfo = ServerIpcGetNodeKeyInfo,
};

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;
    data.WriteInt32(SOFTBUS_SERVER_SA_ID);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        LOG_ERR("Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int ServerProvideInterfaceInit(void)
{
    if (g_serverProxy == nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_serverProxy == nullptr) {
            sptr<IRemoteObject> object = GetSystemAbility();
            g_serverProxy = iface_cast<ISoftBusServer>(object);
            if (g_serverProxy == nullptr || g_serverProxy->AsObject() == nullptr) {
                LOG_ERR("Get remote softbus object failed!\n");
                return SOFTBUS_ERR;
            }
            g_clientDeath = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) SoftBusClientDeathRecipient());
            if (g_clientDeath == nullptr) {
                LOG_ERR("DeathRecipient object is nullptr\n");
                return SOFTBUS_ERR;
            }
            if (!g_serverProxy->AsObject()->AddDeathRecipient(g_clientDeath)) {
                LOG_ERR("AddDeathRecipient failed\n");
                return SOFTBUS_ERR;
            }
        }
    }
    return SOFTBUS_OK;
}

struct ServerProvideInterface *GetServerProvideInterface(void)
{
    return &g_serverProvideInterface;
}

int ClientProvideInterfaceImplInit(void)
{
    char clientName[PKG_NAME_SIZE_MAX] = {0};
    int ret = GetSoftBusClientName(clientName, sizeof(clientName));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get client name failed");
        return ret;
    }
    ret = ServerIpcRegisterService(clientName, nullptr);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("server register service failed!\n");
        return ret;
    }
    return SOFTBUS_OK;
}

void ClientDeathProcTask(void)
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_serverProxy->AsObject() != nullptr && g_clientDeath != nullptr) {
            g_serverProxy->AsObject()->RemoveDeathRecipient(g_clientDeath);
        }
        g_serverProxy = nullptr;
    }

    while (g_serverProxy == nullptr) {
        sleep(g_waitServerInterval);
        ServerProvideInterfaceInit();
        if (g_serverProxy != nullptr) {
            break;
        }
    }
    ClientProvideInterfaceImplInit();
}
