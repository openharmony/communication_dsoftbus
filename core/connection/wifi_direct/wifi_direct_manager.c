/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_manager.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "lnn_distributed_net_ledger.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_role_option.h"
#include "command/wifi_direct_connect_command.h"
#include "command/wifi_direct_disconnect_command.h"
#include "command/wifi_direct_command_manager.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_perf_recorder.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WD] Manager: "

/* public interface implement */
static int32_t GetRequestId(void)
{
    int32_t *requestId = &GetWifiDirectManager()->requestId;
    if (*requestId < 0) {
        *requestId = 0;
    }
    return (*requestId)++;
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo && callback, SOFTBUS_INVALID_PARAM, "invalid parameters");
    char uuid[UUID_BUF_LEN] = {0};
    (void)connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, uuid, sizeof(uuid));
    int32_t ret = GetWifiDirectRoleOption()->getExpectedRole(connectInfo->remoteNetworkId, connectInfo->connectType,
                                                             &connectInfo->expectApiRole, &connectInfo->isStrict);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get expected role failed");
    CLOGI(LOG_LABEL "requestId=%d pid=%d type=%d expectRole=0x%x remoteMac=%s uuid=%s",
          connectInfo->requestId, connectInfo->pid, connectInfo->connectType, connectInfo->expectApiRole,
          WifiDirectAnonymizeMac(connectInfo->remoteMac), AnonymizesUUID(uuid));

    GetWifiDirectPerfRecorder()->clear();
    GetWifiDirectPerfRecorder()->setPid(connectInfo->pid);
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_START);
    struct WifiDirectCommand *command = WifiDirectConnectCommandNew(connectInfo, callback);
    CONN_CHECK_AND_RETURN_RET_LOG(command, SOFTBUS_MALLOC_ERR, "alloc connect command failed");

    GetWifiDirectCommandManager()->enqueueCommand(command);
    ret = GetWifiDirectNegotiator()->processNextCommand();
    return ret;
}

static int32_t DisconnectDevice(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo && callback, SOFTBUS_INVALID_PARAM, "invalid parameters");
    char uuid[UUID_BUF_LEN] = {0};
    if (connectInfo->negoChannel) {
        (void)connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, uuid, sizeof(uuid));
    }
    CLOGI(LOG_LABEL "requestId=%d pid=%d type=%d remoteMac=%s linkId=%d uuid=%s",
          connectInfo->requestId, connectInfo->pid, connectInfo->connectType,
          WifiDirectAnonymizeMac(connectInfo->remoteMac), connectInfo->linkId, AnonymizesUUID(uuid));

    struct WifiDirectCommand *command = WifiDirectDisconnectCommandNew(connectInfo, callback);
    CONN_CHECK_AND_RETURN_RET_LOG(command, SOFTBUS_MALLOC_ERR, "alloc disconnect command failed");

    GetWifiDirectCommandManager()->enqueueCommand(command);
    return GetWifiDirectNegotiator()->processNextCommand();
}

static void RegisterStatusListener(struct WifiDirectStatusListener *listener)
{
    CONN_CHECK_AND_RETURN_LOG(listener, "listener is null");
    GetWifiDirectManager()->listener = *listener;
}

static int32_t GetRemoteUuidByIp(const char *ipString, char *uuid, int32_t uuidSize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(ipString, SOFTBUS_INVALID_PARAM, LOG_LABEL "ip is null");
    CONN_CHECK_AND_RETURN_RET_LOG(uuid, SOFTBUS_INVALID_PARAM, LOG_LABEL "uuid is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByIp(ipString, true);
    if (innerLink == NULL) {
        CLOGE(LOG_LABEL "not find inner link");
        return SOFTBUS_ERR;
    }

    int32_t ret = strcpy_s(uuid, uuidSize, innerLink->getString(innerLink, IL_KEY_DEVICE_ID, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy remote mac failed");
    return SOFTBUS_OK;
}

static bool IsDeviceOnline(const char *remoteMac)
{
    CONN_CHECK_AND_RETURN_RET_LOG(remoteMac, false, LOG_LABEL "remote mac is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByDevice(remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, false, LOG_LABEL "inner link is null");

    if (innerLink->getInt(innerLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID) == INNER_LINK_STATE_CONNECTED) {
        CLOGI(LOG_LABEL "online");
        return true;
    }

    CLOGI(LOG_LABEL "not online");
    return false;
}

static int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(remoteIp, SOFTBUS_INVALID_PARAM, LOG_LABEL "remoteIp is null");
    CONN_CHECK_AND_RETURN_RET_LOG(localIp, SOFTBUS_INVALID_PARAM, LOG_LABEL "localIp is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByIp(remoteIp, true);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_ERR, LOG_LABEL "not find inner link");
    return innerLink->getLocalIpString(innerLink, localIp, localIpSize);
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    CONN_CHECK_AND_RETURN_RET_LOG(uuid, SOFTBUS_INVALID_PARAM, LOG_LABEL "uuid is null");
    CONN_CHECK_AND_RETURN_RET_LOG(localIp, SOFTBUS_INVALID_PARAM, LOG_LABEL "localIp is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByUuid(uuid);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_ERR, LOG_LABEL "not find inner link");
    return innerLink->getLocalIpString(innerLink, localIp, localIpSize);
}

static bool PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectConnectType connectType)
{
    return true;
}

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDataReceived(channel, data, len);
}

static void OnNegotiateChannelDisconnected(struct WifiDirectNegotiateChannel *channel)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDisconnected(channel);
}

static void OnRemoteP2pDisable(const char *networkId)
{
    CLOGD(LOG_LABEL "networkId=%s", AnonymizesNetworkID(networkId));
    char uuid[UUID_BUF_LEN] = {0};
    int32_t ret = LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, sizeof(uuid));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "convert %s to uuid failed", AnonymizesNetworkID(networkId));
    GetLinkManager()->clearNegoChannelForLink(uuid, true);
}

/* private method implement */
/* static class method */
static struct WifiDirectManager g_manager = {
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .registerStatusListener = RegisterStatusListener,
    .getRemoteUuidByIp = GetRemoteUuidByIp,
    .isDeviceOnline = IsDeviceOnline,
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    .getLocalIpByUuid = GetLocalIpByUuid,
    .prejudgeAvailability = PrejudgeAvailability,

    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,
    .onRemoteP2pDisable = OnRemoteP2pDisable,

    .requestId = REQUEST_ID_INVALID,
    .myRole = WIFI_DIRECT_ROLE_NONE,
    .localMac[0] = 0,
};

struct WifiDirectManager* GetWifiDirectManager(void)
{
    return &g_manager;
}

static void SetLnnInfo(const char *interface)
{
    struct InnerLink innerLink;
    InnerLinkConstructor(&innerLink);
    struct InterfaceInfo *localInterface = GetResourceManager()->getInterfaceInfo(interface);
    CONN_CHECK_AND_RETURN_LOG(localInterface, "interface info is null");
    char *localMac = localInterface->getString(localInterface, II_KEY_BASE_MAC, "");

    innerLink.putString(&innerLink, IL_KEY_LOCAL_BASE_MAC, localMac);
    innerLink.putString(&innerLink, IL_KEY_LOCAL_INTERFACE, interface);

    GetWifiDirectNegotiator()->syncLnnInfo(&innerLink);
    InnerLinkDestructor(&innerLink);
}

static void OnInterfaceInfoChange(struct InterfaceInfo *info)
{
    char *name = info->getName(info);
    if (strcmp(name, IF_NAME_P2P) != 0 && strcmp(name, IF_NAME_HML) != 0) {
        return;
    }

    struct WifiDirectManager *self = GetWifiDirectManager();
    enum WifiDirectRole newRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CLOGI(LOG_LABEL "oldRole=%d newRole=%d", self->myRole, newRole);
    if (self->myRole != newRole) {
        self->myRole = newRole;
        if (self->listener.onLocalRoleChange) {
            self->listener.onLocalRoleChange(newRole);
        }
        return;
    }

    char *newLocalMac = info->getString(info, II_KEY_BASE_MAC, "");
    CLOGI(LOG_LABEL "newLocalMac=%s oldLocalMac=%s",
          WifiDirectAnonymizeMac(newLocalMac), WifiDirectAnonymizeMac(self->localMac));
    if (strcmp(newLocalMac, self->localMac) != 0) {
        if (strcpy_s(self->localMac, sizeof(self->localMac), newLocalMac) != EOK) {
            CLOGE(LOG_LABEL "copy local mac failed");
        }
        SetLnnInfo(name);
        return;
    }
}

static void OnInnerLinkChange(struct InnerLink *innerLink, bool isStateChange)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    enum InnerLinkState state = innerLink->getInt(innerLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    innerLink->getRemoteIpString(innerLink, remoteIp, sizeof(remoteIp));
    const char *remoteUuid = innerLink->getString(innerLink, IL_KEY_DEVICE_ID, "");

    if (!isStateChange) {
        return;
    }

    if (state == INNER_LINK_STATE_CONNECTED) {
        CLOGI(LOG_LABEL "remoteMac=%s remoteUuid=%s online", WifiDirectAnonymizeMac(remoteMac),
              AnonymizesUUID(remoteUuid));
        if (self->listener.onDeviceOnLine) {
            self->listener.onDeviceOnLine(remoteMac, remoteIp, remoteUuid);
        }
    } else if (state == INNER_LINK_STATE_DISCONNECTED) {
        CLOGI(LOG_LABEL "remoteMac=%s remoteUuid=%s offline", WifiDirectAnonymizeMac(remoteMac),
              AnonymizesUUID(remoteUuid));
        if (self->listener.onDeviceOffLine) {
            self->listener.onDeviceOffLine(remoteMac, remoteIp, remoteUuid);
        }
    } else {
        CLOGD(LOG_LABEL "other state");
    }
}

int32_t WifiDirectManagerInit(void)
{
    struct ResourceManagerListener resourceManagerListener = {
        .onInterfaceInfoChange = OnInterfaceInfoChange,
    };
    GetResourceManager()->registerListener(&resourceManagerListener);

    struct LinkManagerListener linkManagerListener = {
        .onInnerLinkChange = OnInnerLinkChange,
    };
    GetLinkManager()->registerListener(&linkManagerListener);

    ListInit(&g_manager.callbackList);
    SetLnnInfo(IF_NAME_P2P);
    SetLnnInfo(IF_NAME_HML);

    return SOFTBUS_OK;
}