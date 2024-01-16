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
#include "softbus_hidumper_conn.h"
#include "bus_center_manager.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_role_option.h"
#include "command/wifi_direct_connect_command.h"
#include "command/wifi_direct_disconnect_command.h"
#include "command/wifi_direct_command_manager.h"
#include "conn_log.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_perf_recorder.h"
#include "utils/wifi_direct_anonymous.h"
#include "conn_event.h"
#include "wifi_direct_statistic.h"

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
    CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo && callback, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "invalid param");
    ConnEventExtra extra = {
        .requestId = connectInfo->requestId,
        .linkType = connectInfo->connectType,
        .expectRole = (int32_t)connectInfo->expectApiRole,
        .peerIp = connectInfo->remoteMac
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_START, extra);

    char uuid[UUID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(connectInfo->remoteNetworkId, STRING_KEY_UUID, uuid, sizeof(uuid));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get uuid failed");
    ret = GetWifiDirectRoleOption()->getExpectedRole(connectInfo->remoteNetworkId, connectInfo->connectType,
                                                     &connectInfo->expectApiRole, &connectInfo->isStrict);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get expected role failed");
    CONN_LOGI(CONN_WIFI_DIRECT,
        "requestId=%{public}d, pid=%{public}d, type=%{public}d, expectRole=0x%{public}x, remoteMac=%{public}s, "
        "uuid=%{public}s",
        connectInfo->requestId, connectInfo->pid, connectInfo->connectType, connectInfo->expectApiRole,
        WifiDirectAnonymizeMac(connectInfo->remoteMac), WifiDirectAnonymizeDeviceId(uuid));

    GetWifiDirectPerfRecorder()->clear();
    GetWifiDirectPerfRecorder()->setPid(connectInfo->pid);
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_START);

    struct WifiDirectCommand *command = WifiDirectConnectCommandNew(connectInfo, callback);
    CONN_CHECK_AND_RETURN_RET_LOGW(command, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc connect command failed");

    GetWifiDirectCommandManager()->enqueueCommand(command);
    ret = GetWifiDirectNegotiator()->processNextCommand();

    extra.errcode = ret;
    extra.result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, extra);
    return ret;
}

static int32_t DisconnectDevice(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo != NULL && callback != NULL, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT,
                                   "invalid param");
    char uuid[UUID_BUF_LEN] = {0};
    if (connectInfo->negoChannel) {
        (void)connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, uuid, sizeof(uuid));
    }
    CONN_LOGI(CONN_WIFI_DIRECT,
        "requestId=%{public}d, pid=%{public}d, type=%{public}d, remoteMac=%{public}s, linkId=%{public}d, "
        "uuid=%{public}s",
        connectInfo->requestId, connectInfo->pid, connectInfo->connectType,
        WifiDirectAnonymizeMac(connectInfo->remoteMac), connectInfo->linkId,
        WifiDirectAnonymizeDeviceId(uuid));

    struct WifiDirectCommand *command = WifiDirectDisconnectCommandNew(connectInfo, callback);
    CONN_CHECK_AND_RETURN_RET_LOGW(command, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc disconnect command failed");

    GetWifiDirectCommandManager()->enqueueCommand(command);
    return GetWifiDirectNegotiator()->processNextCommand();
}

static void RegisterStatusListener(struct WifiDirectStatusListener *listener)
{
    CONN_CHECK_AND_RETURN_LOGW(listener, CONN_WIFI_DIRECT, "listener is null");
    GetWifiDirectManager()->listener = *listener;
}

static int32_t GetRemoteUuidByIp(const char *ipString, char *uuid, int32_t uuidSize)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(ipString, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ip is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(uuid, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "uuid is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByIp(ipString, true);
    if (innerLink == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find inner link");
        return SOFTBUS_ERR;
    }

    int32_t ret = strcpy_s(uuid, uuidSize, innerLink->getString(innerLink, IL_KEY_DEVICE_ID, ""));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy remote mac failed");
    return SOFTBUS_OK;
}

static bool IsDeviceOnline(const char *remoteMac)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(remoteMac, false, CONN_WIFI_DIRECT, "remote mac is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByDevice(remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(innerLink, false, CONN_WIFI_DIRECT, "inner link is null");

    if (innerLink->getInt(innerLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID) == INNER_LINK_STATE_CONNECTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "online");
        return true;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "not online");
    return false;
}

#define GET_INNER_LINK_MAX_TIMES 6
#define GET_INNER_LINK_WAIT_INTERVAL 50

static int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(remoteIp, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "remoteIp is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(localIp, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "localIp is null");

    int32_t times = 0;
    do {
        struct InnerLink *innerLink = GetLinkManager()->getLinkByIp(remoteIp, true);
        if (innerLink != NULL) {
            return innerLink->getLocalIpString(innerLink, localIp, localIpSize);
        }

        times++;
        CONN_LOGI(CONN_WIFI_DIRECT, "not find inner link, retry times=%{public}d", times);
        SoftBusSleepMs(GET_INNER_LINK_WAIT_INTERVAL);
    } while (times < GET_INNER_LINK_MAX_TIMES);

    CONN_LOGE(CONN_WIFI_DIRECT, "not find inner link");
    return SOFTBUS_ERR;
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(uuid, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "uuid is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(localIp, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "localIp is null");

    int32_t times = 0;
    do {
        for (enum WifiDirectLinkType linkType = 0; linkType < WIFI_DIRECT_LINK_TYPE_MAX; linkType++) {
            struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndUuid(linkType, uuid);
            if (innerLink != NULL && innerLink->getInt(innerLink, IL_KEY_STATE, -1) == INNER_LINK_STATE_CONNECTED) {
                return innerLink->getLocalIpString(innerLink, localIp, localIpSize);
            }
        }

        times++;
        CONN_LOGI(CONN_WIFI_DIRECT, "not find inner link, retry times=%{public}d", times);
        SoftBusSleepMs(GET_INNER_LINK_WAIT_INTERVAL);
    } while (times < GET_INNER_LINK_MAX_TIMES);

    CONN_LOGE(CONN_WIFI_DIRECT, "not find inner link");
    return SOFTBUS_ERR;
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    return GetWifiDirectNegotiator()->prejudgeAvailability(remoteNetworkId, connectType);
}

static int32_t GetInterfaceNameByLocalIp(const char *localIp, char *interfaceName, size_t interfaceNameSize)
{
    struct InnerLink *link = GetLinkManager()->getLinkByIp(localIp, false);
    CONN_CHECK_AND_RETURN_RET_LOGE(link != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "WifiDirectAnonymizeIp not found. WifiDirectAnonymizeIp=%{public}s", WifiDirectAnonymizeIp(localIp));

    int32_t ret = strcpy_s(interfaceName, interfaceNameSize, link->getString(link, IL_KEY_LOCAL_INTERFACE, ""));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface name failed");
    return SOFTBUS_OK;
}

static int32_t GetLocalAndRemoteMacByLocalIp(const char *localIp,  char *localMac, size_t localMacSize,
                                             char *remoteMac, size_t remoteMacSize)
{
    struct InnerLink *link = GetLinkManager()->getLinkByIp(localIp, false);
    CONN_CHECK_AND_RETURN_RET_LOGE(link != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "WifiDirectAnonymizeIp not found. WifiDirectAnonymizeIp=%{public}s", WifiDirectAnonymizeIp(localIp));

    int32_t ret = strcpy_s(localMac, localMacSize, link->getString(link, IL_KEY_LOCAL_BASE_MAC, ""));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy local mac failed");
    ret = strcpy_s(remoteMac, remoteMacSize, link->getString(link, IL_KEY_REMOTE_BASE_MAC, ""));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy remote mac failed");
    return SOFTBUS_OK;
}

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDataReceived(channel, data, len);
}

static void OnNegotiateChannelDisconnected(struct WifiDirectNegotiateChannel *channel)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDisconnected(channel);
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
    .getInterfaceNameByLocalIp = GetInterfaceNameByLocalIp,
    .getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIp,

    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,

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
    CONN_CHECK_AND_RETURN_LOGW(localInterface, CONN_WIFI_DIRECT, "interface info is null");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "oldRole=%{public}d, newRole=%{public}d", self->myRole, newRole);
    if (self->myRole != newRole) {
        self->myRole = newRole;
        if (self->listener.onLocalRoleChange) {
            self->listener.onLocalRoleChange(newRole);
        }
        return;
    }

    char *newLocalMac = info->getString(info, II_KEY_BASE_MAC, "");
    CONN_LOGI(CONN_WIFI_DIRECT, "newLocalMac=%{public}s, oldLocalMac=%{public}s",
          WifiDirectAnonymizeMac(newLocalMac), WifiDirectAnonymizeMac(self->localMac));
    if (strcmp(newLocalMac, self->localMac) != 0) {
        if (strcpy_s(self->localMac, sizeof(self->localMac), newLocalMac) != EOK) {
            CONN_LOGW(CONN_WIFI_DIRECT, "copy local mac failed");
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
        CONN_LOGI(CONN_WIFI_DIRECT,
            "online. remoteMac=%{public}s, remoteUuid=%{public}s", WifiDirectAnonymizeMac(remoteMac),
            WifiDirectAnonymizeDeviceId(remoteUuid));
        if (self->listener.onDeviceOnLine) {
            self->listener.onDeviceOnLine(remoteMac, remoteIp, remoteUuid);
        }
    } else if (state == INNER_LINK_STATE_DISCONNECTED) {
        CONN_LOGI(CONN_WIFI_DIRECT,
            "offline. remoteMac=%{public}s, remoteUuid=%{public}s", WifiDirectAnonymizeMac(remoteMac),
            WifiDirectAnonymizeDeviceId(remoteUuid));
        if (self->listener.onDeviceOffLine) {
            self->listener.onDeviceOffLine(remoteMac, remoteIp, remoteUuid);
        }
    } else {
        CONN_LOGD(CONN_WIFI_DIRECT, "other state");
    }
}

static int32_t WifiDirectDumperCallbackForShow(int32_t fd)
{
    GetResourceManager()->dump(fd);
    GetLinkManager()->dump(fd);
    return SOFTBUS_OK;
}

static int32_t WifiDirectDumperCallbackForSetFeature(int32_t fd)
{
    g_manager.feature = true;
    dprintf(fd, "setFeature=%d\n", g_manager.feature);
    return SOFTBUS_OK;
}

static int32_t WifiDirectDumperCallbackForClearFeature(int32_t fd)
{
    g_manager.feature = false;
    dprintf(fd, "setFeature=%d\n", g_manager.feature);
    return SOFTBUS_OK;
}

int32_t WifiDirectManagerInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
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

    if (SoftBusRegConnVarDump("WifiDirectShow", WifiDirectDumperCallbackForShow) != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "add dumper callback failed");
    }
    if (SoftBusRegConnVarDump("WifiDirectSet", WifiDirectDumperCallbackForSetFeature) != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "add dumper callback failed");
    }
    if (SoftBusRegConnVarDump("WifiDirectClear", WifiDirectDumperCallbackForClearFeature) != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "add dumper callback failed");
    }
    if (InitStatisticMutexLock() != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "init statistic lock fail");
    }

    return SOFTBUS_OK;
}