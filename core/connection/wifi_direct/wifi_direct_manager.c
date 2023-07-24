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
#include "softbus_adapter_mem.h"
#include "softbus_hisysevt_connreporter.h"
#include "wifi_direct_command_manager.h"
#include "wifi_direct_negotiator.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_timer_list.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_perf_recorder.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WifiDirect] WifiDirectManager: "

/* inner class */
struct ConnectCallbackNode {
    ListNode node;
    int32_t requestId;
    struct WifiDirectConnectCallback connectCallback;
};

enum ConnectCallbackType {
    CALLBACK_TYPE_CONNECT_SUCCESS = 0,
    CALLBACK_TYPE_CONNECT_FAILURE = 1,
    CALLBACK_TYPE_DISCONNECT_SUCCESS = 2,
    CALLBACK_TYPE_DISCONNECT_FAILURE = 3,
};

struct ConnectResultStruct {
    enum ConnectCallbackType type;
    int32_t requestId;
    int32_t reason;
    struct WifiDirectLink link;
};

/* forward declare private member method */
static int32_t SetupCommandAndCallback(struct WifiDirectCommand *command, struct WifiDirectConnectInfo *connectInfo,
                                       struct WifiDirectConnectCallback *callback);
static int32_t AddConnectCallbackNode(int32_t requestId, const struct WifiDirectConnectCallback *callback);
static struct ConnectCallbackNode* FetchConnectCallbackNode(int32_t requestId);
static void CommandTimeoutHandler(void *data);

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
    CLOGI(LOG_LABEL "requestId=%d pid=%d connectType=%d expectRole=%d remoteMac=%s uuid=%s",
          connectInfo->requestId, connectInfo->pid, connectInfo->connectType, connectInfo->expectRole,
          WifiDirectAnonymizeMac(connectInfo->remoteMac), AnonymizesUUID(uuid));

    GetWifiDirectPerfRecorder()->clear();
    GetWifiDirectPerfRecorder()->setPid(connectInfo->pid);
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_START);
    struct WifiDirectCommand *command = GenerateWifiDirectConnectCommand(connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(command, SOFTBUS_MALLOC_ERR, "alloc connect command failed");

    int32_t ret = SetupCommandAndCallback(command, connectInfo, callback);
    if (ret != SOFTBUS_OK) {
        FreeWifiDirectCommand(command);
        return ret;
    }

    ret = GetWifiDirectNegotiator()->processNewCommand();
    return ret;
}

static int32_t DisconnectDevice(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo && callback, SOFTBUS_INVALID_PARAM, "invalid parameters");
    char uuid[UUID_BUF_LEN] = {0};
    if (connectInfo->negoChannel) {
        (void)connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, uuid, sizeof(uuid));
    }
    CLOGI(LOG_LABEL "requestId=%d pid=%d connectType=%d remoteMac=%s linkId=%d uuid=%s",
          connectInfo->requestId, connectInfo->pid, connectInfo->connectType,
          WifiDirectAnonymizeMac(connectInfo->remoteMac), connectInfo->linkId, AnonymizesUUID(uuid));

    struct WifiDirectCommand *command = GenerateWifiDirectDisconnectCommand(connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(command, SOFTBUS_MALLOC_ERR, "alloc disconnect command failed");

    int32_t ret = SetupCommandAndCallback(command, connectInfo, callback);
    if (ret != SOFTBUS_OK) {
        FreeWifiDirectCommand(command);
    } else {
        ret = GetWifiDirectNegotiator()->processNewCommand();
    }
    return ret;
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

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDataReceived(channel, data, len);
}

static void OnNegotiateChannelDisconnected(struct WifiDirectNegotiateChannel *channel)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDisconnected(channel);
}

static void ConnectCallbackAsyncHandler(void *data)
{
    struct ConnectResultStruct *connectResult = data;
    struct ConnectCallbackNode *callbackNode = FetchConnectCallbackNode(connectResult->requestId);
    if (callbackNode) {
        switch (connectResult->type) {
            case CALLBACK_TYPE_CONNECT_SUCCESS:
                if (callbackNode->connectCallback.onConnectSuccess) {
                    callbackNode->connectCallback.onConnectSuccess(connectResult->requestId, &connectResult->link);
                }
                break;
            case CALLBACK_TYPE_CONNECT_FAILURE:
                if (callbackNode->connectCallback.onConnectFailure) {
                    callbackNode->connectCallback.onConnectFailure(connectResult->requestId, connectResult->reason);
                }
                break;
            case CALLBACK_TYPE_DISCONNECT_SUCCESS:
                if (callbackNode->connectCallback.onDisconnectSuccess) {
                    callbackNode->connectCallback.onDisconnectSuccess(connectResult->requestId);
                }
                break;
            case CALLBACK_TYPE_DISCONNECT_FAILURE:
                if (callbackNode->connectCallback.onDisconnectFailure) {
                    callbackNode->connectCallback.onDisconnectFailure(connectResult->requestId, connectResult->reason);
                }
                break;
            default:
                CLOGE(LOG_LABEL "invalid type");
                break;
        }
    }

    SoftBusFree(callbackNode);
}

static void ReportPerfData(enum WifiDirectErrorCode reason)
{
    struct WifiDirectPerfRecorder *recorder = GetWifiDirectPerfRecorder();
    recorder->calculate();
    ProcessStepTime time;
    time.totalTime = recorder->getTime(TC_TOTAL);
    time.groupCreateTime = recorder->getTime(TC_CREATE_GROUP);
    time.connGroupTime = recorder->getTime(TC_CONNECT_GROUP);
    time.negotiationTime = recorder->getTime(TC_NEGOTIATE);
    SoftbusRecordProccessDuration(recorder->getPid(), SOFTBUS_HISYSEVT_CONN_TYPE_P2P, SOFTBUS_EVT_CONN_SUCC,
                                  &time, reason);
    recorder->clear();
}

static void OnConnectSuccess(int32_t requestId, const struct WifiDirectLink *link)
{
    CLOGI(LOG_LABEL "requestId=%d localIp=%s remoteIp=%s",
          requestId, WifiDirectAnonymizeIp(link->localIp), WifiDirectAnonymizeIp(link->remoteIp));
    struct ConnectResultStruct *connectResult = SoftBusCalloc(sizeof(*connectResult));
    CONN_CHECK_AND_RETURN_LOG(connectResult, LOG_LABEL "malloc connect result failed");

    connectResult->type = CALLBACK_TYPE_CONNECT_SUCCESS;
    connectResult->requestId = requestId;
    if (memcpy_s(&connectResult->link, sizeof(connectResult->link), link, sizeof(struct WifiDirectLink)) != EOK) {
        CLOGE(LOG_LABEL "memcpy_s failed");
        SoftBusFree(connectResult);
        connectResult = NULL;
        return;
    }

    if (CallMethodAsync(ConnectCallbackAsyncHandler, connectResult, 0) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "async fail");
        SoftBusFree(connectResult);
        connectResult = NULL;
    }
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_END);
    ReportPerfData(OK);
}

static void OnConnectFailure(int32_t requestId, enum WifiDirectErrorCode reason)
{
    CLOGE(LOG_LABEL "requestId=%d reason=%d", requestId, reason);
    struct ConnectResultStruct *connectResult = SoftBusCalloc(sizeof(*connectResult));
    CONN_CHECK_AND_RETURN_LOG(connectResult, LOG_LABEL "malloc connect result failed");

    connectResult->type = CALLBACK_TYPE_CONNECT_FAILURE;
    connectResult->requestId = requestId;
    connectResult->reason = reason;

    if (CallMethodAsync(ConnectCallbackAsyncHandler, connectResult, 0) != SOFTBUS_OK) {
        SoftBusFree(connectResult);
        connectResult = NULL;
    }
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_END);
    ReportPerfData(reason);
}

static void OnDisconnectSuccess(int32_t requestId)
{
    CLOGI(LOG_LABEL "requestId=%d", requestId);
    struct ConnectResultStruct *connectResult = SoftBusCalloc(sizeof(*connectResult));
    CONN_CHECK_AND_RETURN_LOG(connectResult, LOG_LABEL "malloc connect result failed");

    connectResult->type = CALLBACK_TYPE_DISCONNECT_SUCCESS;
    connectResult->requestId = requestId;

    if (CallMethodAsync(ConnectCallbackAsyncHandler, connectResult, 0) != SOFTBUS_OK) {
        SoftBusFree(connectResult);
        connectResult = NULL;
    }
}

static void OnDisconnectFailure(int32_t requestId, enum WifiDirectErrorCode reason)
{
    CLOGE(LOG_LABEL "requestId=%d reason=%d", requestId, reason);
    struct ConnectResultStruct *connectResult = SoftBusCalloc(sizeof(*connectResult));
    CONN_CHECK_AND_RETURN_LOG(connectResult, LOG_LABEL "malloc connect result failed");

    connectResult->type = CALLBACK_TYPE_DISCONNECT_FAILURE;
    connectResult->requestId = requestId;
    connectResult->reason = reason;

    if (CallMethodAsync(ConnectCallbackAsyncHandler, connectResult, 0) != SOFTBUS_OK) {
        SoftBusFree(connectResult);
        connectResult = NULL;
    }
}

/* private method implement */
static int32_t SetupCommandAndCallback(struct WifiDirectCommand *command, struct WifiDirectConnectInfo *connectInfo,
                                       struct WifiDirectConnectCallback *callback)
{
    command->timerId = GetWifiDirectTimerList()->startTimer(CommandTimeoutHandler, TIMEOUT_COMMAND_WAIT_MS,
                                                            TIMER_FLAG_ONE_SHOOT, command);
    if (command->timerId < 0) {
        CLOGE("start timer failed");
        return SOFTBUS_MALLOC_ERR;
    }

    if (AddConnectCallbackNode(connectInfo->requestId, callback) != SOFTBUS_OK) {
        CLOGE("add connect callback failed");
        return SOFTBUS_MALLOC_ERR;
    }

    GetWifiDirectCommandManager()->enqueueCommand(command);
    return SOFTBUS_OK;
}

static int32_t AddConnectCallbackNode(int32_t requestId, const struct WifiDirectConnectCallback *callback)
{
    struct ConnectCallbackNode *callbackNode = (struct ConnectCallbackNode*)SoftBusCalloc(sizeof(*callbackNode));
    CONN_CHECK_AND_RETURN_RET_LOG(callbackNode, SOFTBUS_MALLOC_ERR, "malloc callback node failed");
    callbackNode->requestId = requestId;
    ListInit(&callbackNode->node);
    callbackNode->connectCallback = *callback;
    ListAdd(&GetWifiDirectManager()->callbackList, &callbackNode->node);
    return SOFTBUS_OK;
}

static struct ConnectCallbackNode* FetchConnectCallbackNode(int32_t requestId)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    struct ConnectCallbackNode *callbackNode = NULL;
    LIST_FOR_EACH_ENTRY(callbackNode, &self->callbackList, struct ConnectCallbackNode, node) {
        if (callbackNode->requestId == requestId) {
            ListDelete(&callbackNode->node);
            return callbackNode;
        }
    }
    return NULL;
}

static void CommandTimeoutHandler(void *data)
{
    struct WifiDirectCommand *command = data;
    CLOGE("type=%d requestId=%d", command->type, command->connectInfo.requestId);
    GetWifiDirectCommandManager()->removeCommand(command);

    if (command->type == COMMAND_TYPE_CONNECT) {
        GetWifiDirectManager()->onConnectFailure(command->connectInfo.requestId,
                                                 ERROR_WIFI_DIRECT_COMMAND_WAIT_TIMEOUT);
    } else {
        GetWifiDirectManager()->onDisconnectFailure(command->connectInfo.requestId,
                                                    ERROR_WIFI_DIRECT_COMMAND_WAIT_TIMEOUT);
    }

    FreeWifiDirectCommand(command);
}

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

    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,

    .onConnectSuccess = OnConnectSuccess,
    .onConnectFailure = OnConnectFailure,
    .onDisconnectSuccess = OnDisconnectSuccess,
    .onDisconnectFailure = OnDisconnectFailure,

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