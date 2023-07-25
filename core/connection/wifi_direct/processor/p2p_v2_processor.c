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

#include "p2p_v2_processor.h"
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_negotiate_channel.h"
#include "channel/default_negotiate_channel.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "data/link_info.h"
#include "data/negotiate_message.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"
#include "entity/wifi_direct_entity_factory.h"
#include "utils/wifi_direct_perf_recorder.h"

#define LOG_LABEL "[WifiDirect] P2pV2Processor: "
#define NOTIFY_BUFFER_LEN 256

/* private method forward declare */
// process request1
static int32_t ProcessConnectRequest1(struct NegotiateMessage *msg);
static int32_t ProcessConnectRequest1ToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectRequest1ToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectRequest1AsNoneToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectRequest1AsGoToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectRequest1AsNoneToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectRequest1AsGcToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink);

// process request2
static int32_t ProcessConnectRequest2(struct NegotiateMessage *msg);
static int32_t ProcessConnectRequest2AsNone(struct NegotiateMessage *msg);
static int32_t ProcessConnectRequest2AsGo(struct NegotiateMessage *msg);
static int32_t ProcessConnectRequest2AsGc(struct NegotiateMessage *msg);

// process request3
static int32_t ProcessConnectRequest3(struct NegotiateMessage *msg);

// process response1
static int32_t ProcessConnectResponse1(struct NegotiateMessage *msg);
static int32_t ProcessConnectResponse1AsNone(struct NegotiateMessage *msg);
static int32_t ProcessConnectResponse1AsGo(struct NegotiateMessage *msg);
static int32_t ProcessConnectResponse1AsGc(struct NegotiateMessage *msg);

// process response2
static int32_t ProcessConnectResponse2(struct NegotiateMessage *msg);
static int32_t ProcessConnectResponse2AsNone(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectResponse2AsGo(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static int32_t ProcessConnectResponse2AsGc(struct NegotiateMessage *msg);

// process response3
static int32_t ProcessConnectResponse3(struct NegotiateMessage *msg);

// process disconnect request
static int32_t ProcessDisconnectRequest(struct NegotiateMessage *msg);

// build package
static struct NegotiateMessage* BuildConnectRequest1(int32_t requestId, struct WifiDirectNegotiateChannel *channel,
                                                     struct WifiDirectConnectInfo *connectInfo);
static struct NegotiateMessage* BuildConnectRequest2(struct NegotiateMessage *msg);
static struct NegotiateMessage* BuildConnectRequest3(int32_t requestId, struct WifiDirectNegotiateChannel *channel,
                                                     struct InnerLink *innerLink);
static struct NegotiateMessage* BuildDisconnectRequest(int32_t requestId, struct InnerLink *innerLink,
                                                       struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildConnectResponse1(struct NegotiateMessage *msg);
static struct NegotiateMessage* BuildConnectResponse2(struct NegotiateMessage *msg);
static struct NegotiateMessage* BuildConnectResponse3(struct NegotiateMessage *msg, struct LinkInfo *linkInfo,
                                                      int32_t result);
// group related
static int32_t CreateGroup(struct NegotiateMessage *msg);
static int32_t DestroyGroup(void);
static int32_t ConnectGroup(struct LinkInfo *linkInfo);
static int32_t Reuse(const char *localInterface);
static int32_t Disconnect(const char *localInterface);

static int32_t OnCreateGroupComplete(void);
static int32_t OnConnectGroupComplete(void);
static int32_t OnRemoveGroupComplete(void);

// auth related
static void StartListening(const char *localInterface, const char *localIp);
static void OpenAuthConnection(struct WifiDirectNegotiateChannel *channel, struct InnerLink *link, int32_t remotePort);

// misc helper
static int32_t BuildNotifyInfo(struct LinkInfo *linkInfo, char *string, size_t size);
static int32_t HandleFailureResponse(struct NegotiateMessage *msg, struct LinkInfo *linkInfo, int result);
static void NotifyNewClient(int requestId, char *localInterface, char *remoteMac);
static int32_t ReturnConnectResult(struct LinkInfo *linkInfo, struct InterfaceInfo *interfaceInfo);
static int32_t SaveCurrentMessage(struct NegotiateMessage *msg);
static void SetInnerLinkDeviceId(struct NegotiateMessage *msg, struct InnerLink *innerLink);

/* public interface */
static int32_t CreateLink(struct WifiDirectConnectInfo *connectInfo)
{
    CLOGI(LOG_LABEL "requestId=%d", connectInfo->requestId);
    if (GetWifiDirectP2pAdapter()->isThreeVapConflict()) {
        CLOGE(LOG_LABEL "wifi connected and wifi ap switch on");
        return ERROR_LOCAL_THREE_VAP_CONFLICT;
    }

    struct NegotiateMessage *request;
    request = BuildConnectRequest1(connectInfo->requestId, connectInfo->negoChannel, connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build connect request1 failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(request);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "send connect request1 failed");
    return SOFTBUS_OK;
}

static int32_t ReuseLink(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink)
{
    CLOGI(LOG_LABEL "requestId=%d", connectInfo->requestId);
    struct NegotiateMessage *request =
        BuildConnectRequest3(connectInfo->requestId, connectInfo->negoChannel, innerLink);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build request3 failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(request);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "send connect request3 failed");
    return SOFTBUS_OK;
}

static int32_t DisconnectLink(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink)
{
    CLOGI(LOG_LABEL "requestId=%d", connectInfo->requestId);
    struct NegotiateMessage *request =
        BuildDisconnectRequest(connectInfo->requestId, innerLink, connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build disconnect request failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(request);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "send disconnect request failed");
    }

    struct P2pV2Processor *self = GetP2pV2Processor();
    bool isBeingUsedByRemote = innerLink->getBoolean(innerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, false);
    if (isBeingUsedByRemote) {
        CLOGI(LOG_LABEL "isBeingUsedByRemote=true, no need to disconnect link");
        self->currentState = PROCESSOR_STATE_AVAILABLE;
        GetWifiDirectNegotiator()->handleSuccess(NULL);
        return ret;
    }

    char *localInterface = innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, ERROR_SOURCE_NO_INTERFACE_INFO, LOG_LABEL "interface info is null");

    self->currentRequestId = connectInfo->requestId;
    if (Disconnect(localInterface) != SOFTBUS_OK) {
        CLOGE("disconnect failed");
        return SOFTBUS_ERR;
    }
    int32_t reuseCount = interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, 0);
    CLOGI(LOG_LABEL "reuseCount=%d", reuseCount);
    if (reuseCount > 0) {
        self->currentState = PROCESSOR_STATE_AVAILABLE;
        GetWifiDirectNegotiator()->handleSuccess(NULL);
    }
    CLOGI(LOG_LABEL "wait removing group to be done");
    self->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return SOFTBUS_OK;
}

static int32_t ProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    switch (cmd) {
        case CMD_CONN_V2_REQ_1:
            return ProcessConnectRequest1(msg);
        case CMD_CONN_V2_REQ_2:
            return ProcessConnectRequest2(msg);
        case CMD_CONN_V2_REQ_3:
            return ProcessConnectRequest3(msg);
        case CMD_CONN_V2_RESP_1:
            return ProcessConnectResponse1(msg);
        case CMD_CONN_V2_RESP_2:
            return ProcessConnectResponse2(msg);
        case CMD_CONN_V2_RESP_3:
            return ProcessConnectResponse3(msg);
        case CMD_DISCONNECT_V2_REQ:
            return ProcessDisconnectRequest(msg);
        default:
            CLOGE("ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG");
            return HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG);
    }
}

static int32_t OnOperationEvent(int32_t requestId, int32_t result)
{
    CLOGI(LOG_LABEL "requestId=%d result=%d", requestId, result);
    struct P2pV2Processor *self = GetP2pV2Processor();
    if (!self->currentMsg) {
        CLOGE(LOG_LABEL "current msg is null");
        return SOFTBUS_ERR;
    }
    if (self->currentRequestId != requestId) {
        CLOGE(LOG_LABEL "mismatched request id, currentRequestId=%d requestId=%d", self->currentRequestId, requestId);
        return SOFTBUS_ERR;
    }
    if (result != OK) {
        return HandleFailureResponse(self->currentMsg, NULL, result);
    }

    int32_t ret = SOFTBUS_ERR;
    switch (self->currentState) {
        case PROCESSOR_STATE_WAITING_CREATE_GROUP:
            ret = OnCreateGroupComplete();
            break;
        case PROCESSOR_STATE_WAITING_CONNECT_GROUP:
            ret = OnConnectGroupComplete();
            break;
        case PROCESSOR_STATE_WAITING_REMOVE_GROUP:
            ret = OnRemoveGroupComplete();
            break;
        default:
            CLOGE(LOG_LABEL "available state does not handle any operation event");
            return SOFTBUS_ERR;
    }

    self->currentState = PROCESSOR_STATE_AVAILABLE;
    if (ret != SOFTBUS_OK) {
        return HandleFailureResponse(self->currentMsg, NULL, ret);
    }
    return SOFTBUS_OK;
}

static void ProcessUnhandledRequest(struct NegotiateMessage *msg, int32_t reason)
{
    CLOGE(LOG_LABEL "reason=%d", reason);
    if (reason != ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE) {
        reason = ERROR_MANAGER_BUSY;
    }

    struct NegotiateMessage *response = BuildConnectResponse3(msg, NULL, reason);
    if (response) {
        GetWifiDirectNegotiator()->postData(response);
        NegotiateMessageDelete(response);
    }
}

static void OnReversal(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    GetWifiDirectNegotiator()->handleFailureWithoutChangeState(ERROR_WIFI_DIRECT_BIDIRECTIONAL_SIMULTANEOUS_REQ);
}

/* private method implement */
static int32_t ProcessConnectRequest1(struct NegotiateMessage *msg)
{
    CLOGI(LOG_LABEL "requestId=%d", msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    GetP2pV2Processor()->needReply = true;
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    if (linkInfo == NULL) {
        CLOGE(LOG_LABEL "ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED");
        return HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED);
    }

    if (GetWifiDirectP2pAdapter()->isThreeVapConflict()) {
        CLOGE(LOG_LABEL "wifi connected and wifi ap switch on");
        return HandleFailureResponse(msg, NULL, ERROR_PEER_THREE_VAP_CONFLICT);
    }

    enum WifiDirectApiRole localMode =
        (enum WifiDirectApiRole)(linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE));
    enum WifiDirectApiRole remoteMode =
        (enum WifiDirectApiRole)linkInfo->getInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE);
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    CLOGI(LOG_LABEL "localMode=%d remoteMode=%d remoteMac=%s", localMode, remoteMode,
          WifiDirectAnonymizeMac(remoteMac));

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteInterface = linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, "");

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, false, localInterface, remoteMac);
    SetInnerLinkDeviceId(msg, &innerLink);
    innerLink.putInt(&innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTING);
    innerLink.putString(&innerLink, IL_KEY_REMOTE_INTERFACE, remoteInterface);
    innerLink.putBoolean(&innerLink, IL_KEY_IS_SOURCE, false);
    innerLink.putBoolean(&innerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, true);

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    if (interfaceInfo) {
        char *localMac = interfaceInfo->get(interfaceInfo, II_KEY_BASE_MAC, NULL, NULL);
        innerLink.putString(&innerLink, IL_KEY_LOCAL_BASE_MAC, localMac);
    }

    if (localMode == WIFI_DIRECT_API_ROLE_GO) {
        innerLink.putBoolean(&innerLink, IL_KEY_IS_CLIENT, false);
        return ProcessConnectRequest1ToBeGo(msg, &innerLink);
    }
    if (localMode == WIFI_DIRECT_API_ROLE_GC) {
        innerLink.putBoolean(&innerLink, IL_KEY_IS_CLIENT, true);
        return ProcessConnectRequest1ToBeGc(msg, &innerLink);
    }

    return HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED);
}

static int32_t ProcessConnectRequest1ToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    char *interface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    if (info == NULL) {
        CLOGE(LOG_LABEL "interface info is null");
        return HandleFailureResponse(msg, NULL, ERROR_SINK_NO_INTERFACE_INFO);
    }

    char notify[NOTIFY_BUFFER_LEN] = {0};
    int32_t ret = BuildNotifyInfo(linkInfo, notify, sizeof(notify));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "build notify string failed");
    GetWifiDirectP2pAdapter()->setConnectNotify(notify);

    enum WifiDirectApiRole myRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    if (myRole == WIFI_DIRECT_API_ROLE_NONE) {
        return ProcessConnectRequest1AsNoneToBeGo(msg, innerLink);
    }

    if (myRole == WIFI_DIRECT_API_ROLE_GO) {
        return ProcessConnectRequest1AsGoToBeGo(msg, innerLink);
    }

    return HandleFailureResponse(msg, NULL, ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE);
}

static int32_t ProcessConnectRequest1AsNoneToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    self->currentRequestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;

    innerLink->dump(innerLink);
    GetLinkManager()->notifyLinkChange(innerLink);

    CLOGI(LOG_LABEL "create group");
    if (CreateGroup(msg) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "ERROR_P2P_CREATE_GROUP_FAILED");
        return HandleFailureResponse(msg, NULL, ERROR_P2P_CREATE_GROUP_FAILED);
    }

    CLOGI(LOG_LABEL "wait creating group to be done");
    SaveCurrentMessage(msg);
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectRequest1AsGoToBeGo(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");

    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    if (ret != SOFTBUS_OK) {
        return HandleFailureResponse(msg, NULL, ERROR_P2P_APPLY_GC_IP_FAIL);
    }

    ret = Reuse(localInterface);
    if (ret != SOFTBUS_OK) {
        return HandleFailureResponse(msg, NULL, ret);
    }

    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    NotifyNewClient(requestId, localInterface, remoteMac);

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    struct WifiDirectIpv4Info *localIpv4 = interfaceInfo->getRawData(interfaceInfo, II_KEY_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(localIpv4, SOFTBUS_ERR, LOG_LABEL "local ipv4 is null");

    innerLink->putRawData(innerLink, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    innerLink->putRemoteIpString(innerLink, remoteIp);
    GetLinkManager()->notifyLinkChange(innerLink);

    struct NegotiateMessage *response = BuildConnectResponse1(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build response1 failed");
    ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(response);
    GetP2pV2Processor()->needReply = false;
    return ret;
}

static int32_t ProcessConnectRequest1ToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    if (info == NULL) {
        CLOGE(LOG_LABEL "interface info is null");
        return HandleFailureResponse(msg, NULL, ERROR_SINK_NO_INTERFACE_INFO);
    }

    enum WifiDirectApiRole myRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    if (myRole == WIFI_DIRECT_API_ROLE_NONE) {
        return ProcessConnectRequest1AsNoneToBeGc(msg, innerLink);
    }
    if (myRole == WIFI_DIRECT_API_ROLE_GC) {
        return ProcessConnectRequest1AsGcToBeGc(msg, innerLink);
    }
    CLOGI(LOG_LABEL "ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE");
    return HandleFailureResponse(msg, NULL, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
}

static int32_t ProcessConnectRequest1AsNoneToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    GetLinkManager()->notifyLinkChange(innerLink);

    struct NegotiateMessage *response = BuildConnectResponse2(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build response2 failed");
    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_WAITING_CONNECT_REQUEST);
    NegotiateMessageDelete(response);
    GetP2pV2Processor()->needReply = false;
    return ret;
}

static int32_t ProcessConnectRequest1AsGcToBeGc(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    CLOGI(LOG_LABEL "requestId=%d", requestId);

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "get deviceId failed");
        HandleFailureResponse(msg, NULL, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
        return SOFTBUS_OK;
    }

    ListNode *linkList = &GetLinkManager()->linkLists[WIFI_DIRECT_CONNECT_TYPE_P2P];
    struct InnerLink *link = NULL;
    LIST_FOR_EACH_ENTRY(link, linkList, struct InnerLink, node) {
        char *remoteDeviceIdOfLink = link->getString(link, IL_KEY_DEVICE_ID, "");
        if (strlen(remoteDeviceIdOfLink) == 0 || strcmp(remoteDeviceId, remoteDeviceIdOfLink) != 0) {
            continue;
        }
        CLOGI(LOG_LABEL "fix the obsolete link");
        GetP2pV2Processor()->currentRequestId = requestId;
        (void)DestroyGroup();
        GetP2pV2Processor()->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
        HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED);
        return SOFTBUS_OK;
    }

    HandleFailureResponse(msg, NULL, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectRequest2(struct NegotiateMessage *msg)
{
    GetP2pV2Processor()->needReply = true;
    struct LinkInfo *linkInfo = msg->get(msg, NM_KEY_LINK_INFO, NULL, NULL);
    if (linkInfo == NULL) {
        CLOGE(LOG_LABEL "link info is null");
        return HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED);
    }

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    if (interfaceInfo == NULL) {
        CLOGE(LOG_LABEL "interface info is null");
        return HandleFailureResponse(msg, NULL, ERROR_SINK_NO_INTERFACE_INFO);
    }
    interfaceInfo->dump(interfaceInfo);

    char notify[NOTIFY_BUFFER_LEN] = {0};
    int32_t ret = BuildNotifyInfo(linkInfo, notify, sizeof(notify));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "build notify string failed");
    GetWifiDirectP2pAdapter()->setConnectNotify(notify);

    enum WifiDirectApiRole myRole = (enum WifiDirectApiRole)interfaceInfo->getInt(
        interfaceInfo, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    CLOGI(LOG_LABEL "myRole=%d", myRole);
    if (myRole == WIFI_DIRECT_API_ROLE_NONE) {
        ret = ProcessConnectRequest2AsNone(msg);
    } else if (myRole == WIFI_DIRECT_API_ROLE_GO) {
        ret = ProcessConnectRequest2AsGo(msg);
    } else {
        ret =  ProcessConnectRequest2AsGc(msg);
    }

    if (ret != SOFTBUS_OK) {
        return HandleFailureResponse(msg, NULL, ret);
    }
    return SOFTBUS_OK;
}

static int32_t ProcessConnectRequest2AsNone(struct NegotiateMessage *msg)
{
    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    CLOGI(LOG_LABEL "requestId=%d", requestId);
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct WifiDirectIpv4Info *localIpv4 = linkInfo->get(linkInfo, LI_KEY_LOCAL_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(localIpv4, SOFTBUS_ERR, LOG_LABEL "local ipv4 is null");
    struct WifiDirectIpv4Info *remoteIpv4 = linkInfo->get(linkInfo, LI_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(remoteIpv4, SOFTBUS_ERR, LOG_LABEL "remote ipv4 is null");
    int32_t freq = linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, 0);

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, true, localInterface, remoteMac);
    SetInnerLinkDeviceId(msg, &innerLink);
    innerLink.putRawData(&innerLink, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    innerLink.putRawData(&innerLink, IL_KEY_REMOTE_IPV4, remoteIpv4, sizeof(*remoteIpv4));
    innerLink.putInt(&innerLink, IL_KEY_FREQUENCY, freq);
    innerLink.putInt(&innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTING);
    GetLinkManager()->notifyLinkChange(&innerLink);
    InnerLinkDestructor(&innerLink);

    struct P2pV2Processor *self = GetP2pV2Processor();
    self->currentRequestId = requestId;
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    self->needReply = true;
    SaveCurrentMessage(msg);

    int32_t ret = ConnectGroup(linkInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "connect group failed");
    CLOGI(LOG_LABEL "wait connecting group to be done");

    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectRequest2AsGo(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "ERROR_P2P_BOTH_GO");
    return ERROR_P2P_BOTH_GO;
}

static int32_t ProcessConnectRequest2AsGc(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static int32_t ProcessConnectRequest3(struct NegotiateMessage *msg)
{
    GetP2pV2Processor()->needReply = true;
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    if (linkInfo == NULL) {
        CLOGE(LOG_LABEL "link info is null");
        return HandleFailureResponse(msg, NULL, ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED);
    }

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteInterface = linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, "");
    bool isClient = linkInfo->getBoolean(linkInfo, LI_KEY_IS_CLIENT, false);
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    if (innerLink == NULL) {
        CLOGE(LOG_LABEL "inner link is null");
        return HandleFailureResponse(msg, NULL, ERROR_SINK_NO_LINK);
    }

    struct InnerLink newInnerLink;
    InnerLinkConstructorWithArgs(&newInnerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, isClient, localInterface, remoteMac);
    newInnerLink.putBoolean(&newInnerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    GetLinkManager()->notifyLinkChange(&newInnerLink);
    InnerLinkDestructor(&newInnerLink);

    enum WifiDirectApiRole localRole = isClient ? WIFI_DIRECT_API_ROLE_GC : WIFI_DIRECT_API_ROLE_GO;
    enum WifiDirectApiRole remoteRole = isClient ? WIFI_DIRECT_API_ROLE_GO : WIFI_DIRECT_API_ROLE_GC;
    struct LinkInfo respLinkInfo;
    LinkInfoConstructorWithNameAndMode(&respLinkInfo, remoteInterface, localInterface, remoteRole, localRole);
    respLinkInfo.putBoolean(&respLinkInfo, LI_KEY_IS_CLIENT, !isClient);
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    if (interfaceInfo) {
        char *localMac = interfaceInfo->get(interfaceInfo, II_KEY_BASE_MAC, NULL, NULL);
        respLinkInfo.putString(&respLinkInfo, LI_KEY_REMOTE_BASE_MAC, localMac);
    }

    struct NegotiateMessage *response = BuildConnectResponse3(msg, &respLinkInfo, OK);
    LinkInfoDestructor(&respLinkInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build response3 failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(response);
    GetP2pV2Processor()->needReply = false;
    return ret;
}

static int32_t ProcessConnectResponse1(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, ERROR_SOURCE_NO_INTERFACE_INFO, LOG_LABEL "interface info is null");

    size_t remoteConfigSize = 0;
    uint8_t *remoteConfig = msg->getRawData(msg, NM_KEY_WIFI_CFG_INFO, &remoteConfigSize, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(remoteConfig, SOFTBUS_ERR, LOG_LABEL "remote wifi config is null");
    int32_t ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfoV2(remoteConfig, remoteConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "set peer wifi config failed");

    enum WifiDirectApiRole myRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    if (myRole == WIFI_DIRECT_API_ROLE_NONE) {
        return ProcessConnectResponse1AsNone(msg);
    }
    if (myRole == WIFI_DIRECT_API_ROLE_GO) {
        return ProcessConnectResponse1AsGo(msg);
    }

    return ProcessConnectResponse1AsGc(msg);
}

static int32_t ProcessConnectResponse1AsNone(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");

    char *localInterface = linkInfo->get(linkInfo, LI_KEY_LOCAL_INTERFACE, NULL, NULL);
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    char notify[NOTIFY_BUFFER_LEN] = {0};
    int32_t ret = BuildNotifyInfo(linkInfo, notify, sizeof(notify));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "build notify string failed");
    GetWifiDirectP2pAdapter()->setConnectNotify(notify);

    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    char *remoteInterface = linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, "");
    char *localMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");
    struct WifiDirectIpv4Info *localIpv4 = linkInfo->get(linkInfo, LI_KEY_LOCAL_IPV4, NULL, NULL);
    struct WifiDirectIpv4Info *remoteIpv4 = linkInfo->get(linkInfo, LI_KEY_REMOTE_IPV4, NULL, NULL);

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, true, localInterface, remoteMac);
    innerLink.putString(&innerLink, IL_KEY_REMOTE_INTERFACE, remoteInterface);
    innerLink.putString(&innerLink, IL_KEY_LOCAL_BASE_MAC, localMac);
    innerLink.putRawData(&innerLink, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    innerLink.putRawData(&innerLink, IL_KEY_REMOTE_IPV4, remoteIpv4, sizeof(*remoteIpv4));
    innerLink.putInt(&innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTING);
    innerLink.putInt(&innerLink, IL_KEY_FREQUENCY, linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, 0));
    innerLink.putBoolean(&innerLink, IL_KEY_IS_SOURCE, true);
    GetLinkManager()->notifyLinkChange(&innerLink);
    InnerLinkDestructor(&innerLink);

    struct P2pV2Processor *self = GetP2pV2Processor();
    self->currentRequestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    self->needReply = false;
    SaveCurrentMessage(msg);

    ret = ConnectGroup(linkInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "connect group failed");
    CLOGI(LOG_LABEL "wait connect group to be done");

    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);

    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponse1AsGo(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "WIFI_DIRECT_ERROR_BOTH_GO");
    return ERROR_P2P_BOTH_GO;
}

static int32_t ProcessConnectResponse1AsGc(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "WIFI_DIRECT_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static int32_t ProcessConnectResponse2(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    char notify[NOTIFY_BUFFER_LEN] = {0};
    int32_t ret = BuildNotifyInfo(linkInfo, notify, sizeof(notify));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "build notify info failed");
    GetWifiDirectP2pAdapter()->setConnectNotify(notify);

    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    char *remoteInterface = linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, "");
    char *localMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");
    size_t remoteConfigSize = 0;
    uint8_t *remoteConfig = msg->getRawData(msg, NM_KEY_WIFI_CFG_INFO, &remoteConfigSize, NULL);
    ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfoV2(remoteConfig, remoteConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "set peer wifi config failed");

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, false, localInterface, remoteMac);
    innerLink.putString(&innerLink, IL_KEY_REMOTE_INTERFACE, remoteInterface);
    innerLink.putString(&innerLink, IL_KEY_LOCAL_BASE_MAC, localMac);
    innerLink.putInt(&innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTING);
    innerLink.putBoolean(&innerLink, IL_KEY_IS_SOURCE, true);

    enum WifiDirectApiRole myRole = (enum WifiDirectApiRole)(
        interfaceInfo->getInt(interfaceInfo, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CLOGI(LOG_LABEL "myRole=%d", myRole);
    if (myRole == WIFI_DIRECT_API_ROLE_NONE) {
        ret = ProcessConnectResponse2AsNone(msg, &innerLink);
    } else if (myRole == WIFI_DIRECT_API_ROLE_GO) {
        ret = ProcessConnectResponse2AsGo(msg, &innerLink);
    } else {
        ret = ProcessConnectResponse2AsGc(msg);
    }

    InnerLinkDestructor(&innerLink);
    return ret;
}

static int32_t ProcessConnectResponse2AsNone(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    innerLink->dump(innerLink);
    GetLinkManager()->notifyLinkChange(innerLink);
    struct P2pV2Processor *self = GetP2pV2Processor();
    self->currentRequestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    self->needReply = false;

    CLOGI(LOG_LABEL "create group");
    int32_t ret = CreateGroup(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "create group failed");

    CLOGI(LOG_LABEL "wait creating group to be done");
    SaveCurrentMessage(msg);
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponse2AsGo(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "apply gc ip failed");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    ret = Reuse(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "reuse interface failed");

    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    NotifyNewClient(requestId, localInterface, remoteMac);

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    innerLink->putRawData(innerLink, IL_KEY_LOCAL_IPV4,
                          interfaceInfo->getRawData(interfaceInfo, IL_KEY_LOCAL_IPV4, NULL, NULL),
                          sizeof(struct WifiDirectIpv4Info));
    innerLink->putRemoteIpString(innerLink, remoteIp);
    GetLinkManager()->notifyLinkChange(innerLink);

    struct NegotiateMessage *request = BuildConnectRequest2(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build request2 failed");
    ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(request);
    return ret;
}

static int32_t ProcessConnectResponse2AsGc(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static int32_t ProcessConnectResponse3(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");
    int32_t resultCode = msg->getInt(msg, NM_KEY_RESULT_CODE, OK);
    CONN_CHECK_AND_RETURN_RET_LOG(resultCode == OK, resultCode, LOG_LABEL "resultCode=%d", resultCode);

    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_ERR, LOG_LABEL "inner link is null");

    bool isClient = linkInfo->getBoolean(linkInfo, LI_KEY_IS_CLIENT, false);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    int32_t freq = interfaceInfo->getInt(interfaceInfo, II_KEY_CENTER_20M, -1);

    struct InnerLink newInnerLink;
    InnerLinkConstructorWithArgs(&newInnerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, isClient, localInterface, remoteMac);
    SetInnerLinkDeviceId(msg, &newInnerLink);
    newInnerLink.putInt(&newInnerLink, IL_KEY_FREQUENCY, freq);
    newInnerLink.putInt(&newInnerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
    struct WifiDirectIpv4Info *localIpv4 = interfaceInfo->getRawData(interfaceInfo, II_KEY_IPV4, NULL, NULL);
    newInnerLink.putRawData(&newInnerLink, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    struct WifiDirectIpv4Info *remoteIpv4 = linkInfo->getRawData(linkInfo, LI_KEY_REMOTE_IPV4, NULL, NULL);
    newInnerLink.putRawData(&newInnerLink, IL_KEY_REMOTE_IPV4, remoteIpv4, sizeof(*localIpv4));
    GetLinkManager()->notifyLinkChange(&newInnerLink);
    InnerLinkDestructor(&newInnerLink);

    innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    struct NegotiateMessage output;
    NegotiateMessageConstructor(&output);
    output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    GetWifiDirectNegotiator()->handleSuccess(&output);
    NegotiateMessageDestructor(&output);
    return SOFTBUS_OK;
}

static int32_t ProcessDisconnectRequest(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");
    bool isClient = linkInfo->getBoolean(linkInfo, LI_KEY_IS_CLIENT, false);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_ERR, LOG_LABEL "inner link is null");
    bool isBeingUsedByLocal = innerLink->getBoolean(innerLink, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    CLOGI(LOG_LABEL "isBeingUsedByLocal=%d", isBeingUsedByLocal);

    struct InnerLink newInnerLink;
    InnerLinkConstructor(&newInnerLink);
    newInnerLink.putInt(&newInnerLink, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_P2P);
    newInnerLink.putBoolean(&newInnerLink, IL_KEY_IS_CLIENT, isClient);
    newInnerLink.putString(&newInnerLink, IL_KEY_LOCAL_INTERFACE, localInterface);
    newInnerLink.putString(&newInnerLink, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    newInnerLink.putBoolean(&newInnerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, false);
    GetLinkManager()->notifyLinkChange(&newInnerLink);

    if (!isBeingUsedByLocal) {
        GetP2pV2Processor()->currentRequestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
        return Disconnect(localInterface);
    }

    InnerLinkDestructor(&newInnerLink);
    return SOFTBUS_OK;
}

// build package
static struct NegotiateMessage* BuildConnectRequest1(int32_t requestId, struct WifiDirectNegotiateChannel *channel,
                                                     struct WifiDirectConnectInfo *connectInfo)
{
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_START);
    int32_t ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(selfWifiConfig, &selfWifiConfigSize);
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_END);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get self wifi cfg failed");

    if (selfWifiConfigSize != 0) {
        struct InterfaceInfo info;
        InterfaceInfoConstructorWithName(&info, IF_NAME_WLAN);
        info.putRawData(&info, II_KEY_WIFI_CFG_INFO, selfWifiConfig, selfWifiConfigSize);
        GetResourceManager()->notifyInterfaceInfoChange(&info);
        InterfaceInfoDestructor(&info);
    }

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    struct InterfaceInfo *infoArray = NULL;
    int32_t infoArraySize = 0;
    ret = GetResourceManager()->getAllInterfacesSimpleInfo(&infoArray, &infoArraySize);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "get all interfaces info failed");
        NegotiateMessageDelete(request);
        return NULL;
    }

    request->putInt(request, NM_KEY_MSG_TYPE, CMD_CONN_V2_REQ_1);
    request->putInt(request, NM_KEY_SESSION_ID, requestId);
    request->putRawData(request, NM_KEY_WIFI_CFG_INFO, selfWifiConfig, selfWifiConfigSize);
    request->putInt(request, NM_KEY_PREFER_LINK_MODE,
                    GetWifiDirectUtils()->transferRoleToPreferLinkMode(connectInfo->expectRole));
    request->putBoolean(request, NM_KEY_IS_MODE_STRICT, false);
    request->putBoolean(request, NM_KEY_IS_PROXY_ENABLE, connectInfo->isNetworkDelegate);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    request->putContainerArray(request, NM_KEY_INTERFACE_INFO_ARRAY, (struct InfoContainer *)infoArray,
                               infoArraySize, sizeof(struct InterfaceInfo));

    InterfaceInfoDeleteArray(infoArray, infoArraySize);
    return request;
}

static struct NegotiateMessage* BuildConnectRequest2(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, NULL, LOG_LABEL "link info is null");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");

    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, NULL, LOG_LABEL "inner link is null");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    struct LinkInfo reqLinkInfo;
    LinkInfoConstructorWithNameAndMode(&reqLinkInfo, linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, ""),
                                       localInterface,
                                       linkInfo->getInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE),
                                       linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE));
    reqLinkInfo.putInt(&reqLinkInfo, LI_KEY_CENTER_20M, info->getInt(info, II_KEY_CENTER_20M, -1));
    reqLinkInfo.putInt(&reqLinkInfo, LI_KEY_CENTER_FREQUENCY1, info->getInt(info, II_KEY_CENTER_FREQUENCY1, -1));
    reqLinkInfo.putInt(&reqLinkInfo, LI_KEY_CENTER_FREQUENCY2, info->getInt(info, II_KEY_CENTER_FREQUENCY2, -1));
    reqLinkInfo.putInt(&reqLinkInfo, LI_KEY_BANDWIDTH, info->getInt(info, II_KEY_BANDWIDTH, -1));
    reqLinkInfo.putString(&reqLinkInfo, LI_KEY_SSID, info->getString(info, II_KEY_SSID, ""));
    reqLinkInfo.putString(&reqLinkInfo, LI_KEY_BSSID, info->getString(info, II_KEY_DYNAMIC_MAC, ""));
    reqLinkInfo.putString(&reqLinkInfo, LI_KEY_PSK, info->getString(info, II_KEY_PSK, ""));
    reqLinkInfo.putRawData(&reqLinkInfo, LI_KEY_LOCAL_IPV4,
        innerLink->getRawData(innerLink, IL_KEY_REMOTE_IPV4, NULL, NULL), sizeof(struct WifiDirectIpv4Info));
    reqLinkInfo.putRawData(&reqLinkInfo, LI_KEY_REMOTE_IPV4,
        info->getRawData(info, II_KEY_IPV4, NULL, NULL), sizeof(struct WifiDirectIpv4Info));
    reqLinkInfo.putString(&reqLinkInfo, LI_KEY_REMOTE_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    reqLinkInfo.putBoolean(&reqLinkInfo, LI_KEY_IS_CLIENT, true);

    request->putInt(request, NM_KEY_MSG_TYPE, CMD_CONN_V2_REQ_2);
    request->putInt(request, NM_KEY_SESSION_ID, msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    request->putInt(request, NM_KEY_GO_PORT, info->getInt(info, II_KEY_PORT, -1));
    request->putContainer(request, NM_KEY_LINK_INFO, (struct InfoContainer *)&reqLinkInfo, sizeof(reqLinkInfo));
    request->putContainer(request, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    request->putBoolean(request, NM_KEY_IS_PROXY_ENABLE, msg->getBoolean(msg, NM_KEY_IS_PROXY_ENABLE, false));

    LinkInfoDestructor(&reqLinkInfo);
    return request;
}

static struct NegotiateMessage* BuildConnectRequest3(int32_t requestId, struct WifiDirectNegotiateChannel *channel,
                                                     struct InnerLink *innerLink)
{
    struct InterfaceInfo *info =
        GetResourceManager()->getInterfaceInfo(innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    enum WifiDirectApiRole localRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    enum WifiDirectApiRole remoteRole =
        localRole == WIFI_DIRECT_API_ROLE_GO ? WIFI_DIRECT_API_ROLE_GC : WIFI_DIRECT_API_ROLE_GO;

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    struct LinkInfo linkInfo;
    LinkInfoConstructor(&linkInfo);
    linkInfo.putString(&linkInfo, LI_KEY_LOCAL_INTERFACE, innerLink->getString(innerLink, IL_KEY_REMOTE_INTERFACE, ""));
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_INTERFACE, innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, ""));
    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, remoteRole);
    linkInfo.putInt(&linkInfo, LI_KEY_REMOTE_LINK_MODE, localRole);
    linkInfo.putBoolean(&linkInfo, LI_KEY_IS_CLIENT, !innerLink->getBoolean(innerLink, IL_KEY_IS_CLIENT, false));
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));

    request->putInt(request, NM_KEY_MSG_TYPE, CMD_CONN_V2_REQ_3);
    request->putInt(request, NM_KEY_SESSION_ID, requestId);
    request->putContainer(request, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    request->putContainer(request, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    LinkInfoDestructor(&linkInfo);
    return request;
}

static struct NegotiateMessage* BuildDisconnectRequest(int32_t requestId, struct InnerLink *innerLink,
                                                       struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info =
        GetResourceManager()->getInterfaceInfo(innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    enum WifiDirectApiRole localRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    enum WifiDirectApiRole remoteRole =
        localRole == WIFI_DIRECT_API_ROLE_GO ? WIFI_DIRECT_API_ROLE_GC : WIFI_DIRECT_API_ROLE_GO;

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    struct LinkInfo linkInfo;
    LinkInfoConstructor(&linkInfo);
    linkInfo.putString(&linkInfo, LI_KEY_LOCAL_INTERFACE, innerLink->getString(innerLink, IL_KEY_REMOTE_INTERFACE, ""));
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_INTERFACE, innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, ""));
    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, remoteRole);
    linkInfo.putInt(&linkInfo, LI_KEY_REMOTE_LINK_MODE, localRole);
    linkInfo.putBoolean(&linkInfo, LI_KEY_IS_CLIENT, !innerLink->getBoolean(innerLink, IL_KEY_IS_CLIENT, false));
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));

    request->putInt(request, NM_KEY_MSG_TYPE, CMD_DISCONNECT_V2_REQ);
    request->putInt(request, NM_KEY_SESSION_ID, requestId);
    request->putContainer(request, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    request->putContainer(request, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    LinkInfoDestructor(&linkInfo);
    return request;
}

static struct NegotiateMessage* BuildConnectResponse1(struct NegotiateMessage *msg)
{
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *respInnerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(respInnerLink, NULL, LOG_LABEL "inner link is null");

    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_START);
    int32_t ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(selfWifiConfig, &selfWifiConfigSize);
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_END);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get self wifi config failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    struct LinkInfo respLinkInfo;
    LinkInfoConstructorWithNameAndMode(&respLinkInfo, linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, ""),
                                       localInterface,
                                       linkInfo->getInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE),
                                       linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_20M, info->getInt(info, II_KEY_CENTER_20M, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_FREQUENCY1, info->getInt(info, II_KEY_CENTER_FREQUENCY1, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_FREQUENCY2, info->getInt(info, II_KEY_CENTER_FREQUENCY2, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_BANDWIDTH, info->getInt(info, II_KEY_BANDWIDTH, -1));
    respLinkInfo.putString(&respLinkInfo, LI_KEY_SSID, info->getString(info, II_KEY_SSID, ""));
    respLinkInfo.putString(&respLinkInfo, LI_KEY_BSSID, info->getString(info, II_KEY_DYNAMIC_MAC, ""));
    respLinkInfo.putString(&respLinkInfo, LI_KEY_PSK, info->getString(info, II_KEY_PSK, ""));

    respLinkInfo.putRawData(&respLinkInfo, LI_KEY_LOCAL_IPV4,
                            respInnerLink->getRawData(respInnerLink, IL_KEY_REMOTE_IPV4, NULL, NULL),
                            sizeof(struct WifiDirectIpv4Info));
    respLinkInfo.putRawData(&respLinkInfo, LI_KEY_REMOTE_IPV4,
                            respInnerLink->getRawData(respInnerLink, IL_KEY_LOCAL_IPV4, NULL, NULL),
                            sizeof(struct WifiDirectIpv4Info));
    respLinkInfo.putString(&respLinkInfo, LI_KEY_REMOTE_BASE_MAC,
                           respInnerLink->getString(respInnerLink, IL_KEY_LOCAL_BASE_MAC, ""));
    respLinkInfo.putBoolean(&respLinkInfo, LI_KEY_IS_CLIENT, true);

    response->putInt(response, NM_KEY_MSG_TYPE, CMD_CONN_V2_RESP_1);
    response->putInt(response, NM_KEY_SESSION_ID, msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    response->putInt(response, NM_KEY_GO_PORT, info->getInt(info, II_KEY_PORT, -1));
    response->putRawData(response, NM_KEY_WIFI_CFG_INFO, selfWifiConfig, selfWifiConfigSize);
    response->putContainer(response, NM_KEY_LINK_INFO, (struct InfoContainer *)&respLinkInfo, sizeof(respLinkInfo));
    response->putContainer(response, NM_KEY_INNER_LINK, (struct InfoContainer *)respInnerLink, sizeof(*respInnerLink));
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    response->putBoolean(response, NM_KEY_IS_PROXY_ENABLE, msg->getBoolean(msg, NM_KEY_IS_PROXY_ENABLE, false));
    LinkInfoDestructor(&respLinkInfo);
    return response;
}

static struct NegotiateMessage* BuildConnectResponse2(struct NegotiateMessage *msg)
{
    CLOGI(LOG_LABEL "requestId=%d", msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, NULL, LOG_LABEL "link info is null");

    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, NULL, LOG_LABEL "inner link is null");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");

    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_START);
    int32_t ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(selfWifiConfig, &selfWifiConfigSize);
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_END);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get self wifi config failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    struct LinkInfo respLinkInfo;
    LinkInfoConstructorWithNameAndMode(&respLinkInfo, linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, ""),
                                       localInterface,
                                       linkInfo->getInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE),
                                       linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_20M, linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_FREQUENCY1,
                        linkInfo->getInt(linkInfo, LI_KEY_CENTER_FREQUENCY1, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_CENTER_FREQUENCY2,
                       linkInfo->getInt(linkInfo, LI_KEY_CENTER_FREQUENCY2, -1));
    respLinkInfo.putInt(&respLinkInfo, LI_KEY_BANDWIDTH, linkInfo->getInt(linkInfo, LI_KEY_BANDWIDTH, -1));
    respLinkInfo.putString(&respLinkInfo, LI_KEY_REMOTE_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));

    response->putInt(response, NM_KEY_MSG_TYPE, CMD_CONN_V2_RESP_2);
    response->putInt(response, NM_KEY_SESSION_ID, msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    response->putRawData(response, NM_KEY_WIFI_CFG_INFO, selfWifiConfig, selfWifiConfigSize);
    response->putContainer(response, NM_KEY_LINK_INFO, (struct InfoContainer *)&respLinkInfo, sizeof(respLinkInfo));
    response->putContainer(response, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    response->putBoolean(response, NM_KEY_IS_PROXY_ENABLE, msg->getBoolean(msg, NM_KEY_IS_PROXY_ENABLE, false));
    LinkInfoDestructor(&respLinkInfo);
    return response;
}

static struct NegotiateMessage* BuildConnectResponse3(struct NegotiateMessage *msg, struct LinkInfo *linkInfo,
                                                      int32_t result)
{
    CLOGI(LOG_LABEL "result=%d", result);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, NULL, LOG_LABEL "channel is null");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    response->putInt(response, NM_KEY_MSG_TYPE, CMD_CONN_V2_RESP_3);
    response->putInt(response, NM_KEY_SESSION_ID, msg->getInt(msg, NM_KEY_SESSION_ID, -1));

    if (linkInfo) {
        struct LinkInfo *localLinkInfo = msg->get(msg, NM_KEY_LINK_INFO, NULL, NULL);
        CONN_CHECK_AND_RETURN_RET_LOG(localLinkInfo, NULL, LOG_LABEL "local link info is null");
        char *remoteMac = localLinkInfo->getString(localLinkInfo, LI_KEY_REMOTE_BASE_MAC, "");
        struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
        if (innerLink) {
            response->putContainer(response, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
        }
        response->putContainer(response, NM_KEY_LINK_INFO, (struct InfoContainer *)linkInfo, sizeof(*linkInfo));
    }

    response->putInt(response, NM_KEY_RESULT_CODE, result);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    return response;
}

// auth related
static void StartListening(const char *localInterface, const char *localIp)
{
    int32_t port = StartListeningForDefaultChannel(localIp);
    CLOGI(LOG_LABEL "localIp=%s port=%d", WifiDirectAnonymizeIp(localIp), port);
    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, localInterface);
    info.putInt(&info, II_KEY_PORT, port);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static void SendHandShakeToGoAsync(void *data)
{
    struct WifiDirectNegotiateChannel *channel = data;
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    char localIp[IP_ADDR_STR_LEN] = {0};
    interfaceInfo->getIpString(interfaceInfo, localIp, sizeof(localIp));
    char *localMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");

    CLOGI(LOG_LABEL "localIp=%s localMac=%s", WifiDirectAnonymizeIp(localIp), WifiDirectAnonymizeMac(localMac));
    struct NegotiateMessage handShakeInfo;
    NegotiateMessageConstructor(&handShakeInfo);
    handShakeInfo.putInt(&handShakeInfo, NM_KEY_COMMAND_TYPE, CMD_CTRL_CHL_HANDSHAKE);
    handShakeInfo.putString(&handShakeInfo, NM_KEY_MAC, localMac);
    handShakeInfo.putString(&handShakeInfo, NM_KEY_IP, localIp);
    handShakeInfo.putPointer(&handShakeInfo, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    GetWifiDirectNegotiator()->postData(&handShakeInfo);
    NegotiateMessageDestructor(&handShakeInfo);
    channel->destructor(channel);
}

static void OnAuthConnectSuccess(uint32_t authRequestId, int64_t p2pAuthId)
{
    GetWifiDirectNegotiator()->onWifiDirectAuthOpened(authRequestId, p2pAuthId);

    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(p2pAuthId);
    CONN_CHECK_AND_RETURN_LOG(channel, LOG_LABEL "new channel failed");

    if (CallMethodAsync(SendHandShakeToGoAsync, channel, 0) != SOFTBUS_OK) {
        DefaultNegotiateChannelDelete(channel);
        return;
    }

    GetLinkManager()->setNegoChannelForLink((struct WifiDirectNegotiateChannel *)channel);
}

static void OnAuthConnectFailure(uint32_t authRequestId, int32_t reason)
{
    CLOGI(LOG_LABEL "authRequestId=%u reason=%d", authRequestId, reason);
}

static void OpenAuthConnection(struct WifiDirectNegotiateChannel *channel, struct InnerLink *link, int32_t remotePort)
{
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = link->getRemoteIpString(link, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get remote ip failed");
    char *remoteMac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
    CLOGI(LOG_LABEL "remoteMac=%s remoteIp=%s remotePort=%d", WifiDirectAnonymizeMac(remoteMac),
          WifiDirectAnonymizeIp(remoteIp), remotePort);

    struct DefaultNegoChannelOpenCallback callback = {
        .onConnectSuccess = OnAuthConnectSuccess,
        .onConnectFailure = OnAuthConnectFailure,
    };
    ret = OpenDefaultNegotiateChannel(remoteIp, remotePort, &callback);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "open p2p auth failed");
}

// group related
static int32_t CreateGroup(struct NegotiateMessage *msg)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CREATE_GROUP_START);
    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = GetP2pV2Processor()->currentRequestId;
    params.freq = linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, 0);
    params.isWideBandSupported = false;
    params.isProxyEnable = msg->getBoolean(msg, NM_KEY_IS_PROXY_ENABLE, false);
    int32_t ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac),
                           linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy remote mac failed");
    ret = strcpy_s(params.interface, sizeof(params.interface),
                   linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->createServer(&params);
}

static int32_t DestroyGroup(void)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.requestId = GetP2pV2Processor()->currentRequestId;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->destroyServer(&params);
}

static int32_t ConnectGroup(struct LinkInfo *linkInfo)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_START);
    struct NegotiateMessage *msg = GetP2pV2Processor()->currentMsg;
    CONN_CHECK_AND_RETURN_RET_LOG(msg, SOFTBUS_ERR, LOG_LABEL "current msg is null");
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.requestId = GetP2pV2Processor()->currentRequestId;
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.isProxyEnable = msg->getBoolean(msg, NM_KEY_IS_PROXY_ENABLE, false);

    int32_t ret = sprintf_s(params.groupConfig, sizeof(params.groupConfig), "%s\n%s\n%s\n%d",
                            linkInfo->getString(linkInfo, LI_KEY_SSID, ""),
                            linkInfo->getString(linkInfo, LI_KEY_BSSID, ""),
                            linkInfo->getString(linkInfo, LI_KEY_PSK, ""),
                            linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, -1));
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format group config failed");

    ret = strcpy_s(params.interface, sizeof(params.interface),
                   linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");
    ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac),
                   linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy remote mac failed");
    ret = linkInfo->getLocalIpString(linkInfo, params.gcIp, sizeof(params.gcIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "copy client ip failed");
    ret = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->connect(&params);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "connect failed");
    return SOFTBUS_OK;
}

static int32_t Reuse(const char *localInterface)
{
    struct WifiDirectConnectParams params;
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = GetP2pV2Processor()->currentRequestId;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");

    ret = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->reuseLink(&params);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "reuse failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_OK, LOG_LABEL "interface info is null");
    info->increaseRefCount(info);
    return SOFTBUS_OK;
}

static int32_t Disconnect(const char *localInterface)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = GetP2pV2Processor()->currentRequestId;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");

    ret = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->disconnect(&params);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "disconnect failed");

    GetP2pV2Processor()->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, ERROR_SOURCE_NO_INTERFACE_INFO, LOG_LABEL "interface info is null");

    info->decreaseRefCount(info);
    return SOFTBUS_OK;
}

static void UpdateInnerLinkAndInterfaceInfoOnCreateGroupComplete(const char *interface, const char *localIp,
                                                                 const char *remoteMac, const char *remoteIp)
{
    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_CONNECT_TYPE_P2P, false, interface, remoteMac);
    SetInnerLinkDeviceId(GetP2pV2Processor()->currentMsg, &link);
    link.putLocalIpString(&link, localIp);
    link.putRemoteIpString(&link, remoteIp);
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, interface);
    info.putInt(&info, II_KEY_REUSE_COUNT, 1);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static int32_t OnCreateGroupComplete(void)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CREATE_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CLOGI(LOG_LABEL "create group done, timeUsed=%zuMS", GetWifiDirectPerfRecorder()->getTime(TC_CREATE_GROUP));

    struct P2pV2Processor *self = GetP2pV2Processor();
    struct LinkInfo *linkInfo = self->currentMsg->getContainer(self->currentMsg, NM_KEY_LINK_INFO);
    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");

    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "apply gc ip failed");

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    char localIp[IP_ADDR_STR_LEN] = {0};
    ret = interfaceInfo->getIpString(interfaceInfo, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get local ip failed");

    StartListening(localInterface, localIp);
    UpdateInnerLinkAndInterfaceInfoOnCreateGroupComplete(localInterface, localIp, remoteMac, remoteIp);
    NotifyNewClient(self->currentRequestId, localInterface, remoteMac);

    struct NegotiateMessage *response;
    enum NegotiateStateType state;
    if (self->needReply) {
        response = BuildConnectResponse1(self->currentMsg);
        CONN_CHECK_AND_RETURN_RET_LOG(response, ret, LOG_LABEL "build connect response1 failed");
        state = NEGO_STATE_AVAILABLE;
    } else {
        response = BuildConnectRequest2(self->currentMsg);
        CONN_CHECK_AND_RETURN_RET_LOG(response, ret, LOG_LABEL "build connect request2 failed");
        state = NEGO_STATE_WAITING_CONNECT_RESPONSE;
    }
    ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, state);
    NegotiateMessageDelete(response);
    return ret;
}

static void UpdateInnerLinkAndInterfaceInfoOnConnectGroupComplete(struct LinkInfo *linkInfo, const char *interface,
                                                                  const char *localIp, const char *remoteMac)
{
    int32_t frequency = linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, -1);
    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, true, interface, remoteMac);
    SetInnerLinkDeviceId(GetP2pV2Processor()->currentMsg, &innerLink);

    if (strlen(localIp)) {
        innerLink.putLocalIpString(&innerLink, localIp);
    }
    innerLink.putInt(&innerLink, IL_KEY_FREQUENCY, frequency);
    innerLink.putInt(&innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
    GetLinkManager()->notifyLinkChange(&innerLink);
    InnerLinkDestructor(&innerLink);

    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, interface);
    info.putInt(&info, II_KEY_CENTER_20M, frequency);
    info.putInt(&info, II_KEY_REUSE_COUNT, 1);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static int32_t OnConnectGroupComplete(void)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CLOGI(LOG_LABEL "connect group done, timeUsed=%zuMS", GetWifiDirectPerfRecorder()->getTime(TC_CONNECT_GROUP));

    struct P2pV2Processor *self = GetP2pV2Processor();
    struct NegotiateMessage *msg = self->currentMsg;
    struct LinkInfo *linkInfo = msg->getContainer(self->currentMsg, NM_KEY_LINK_INFO);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, SOFTBUS_ERR, LOG_LABEL "link info is null");

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    char *localInterface = linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(localInterface);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = interfaceInfo->getIpString(interfaceInfo, localIp, sizeof(localIp));
    if (ret == SOFTBUS_OK) {
        StartListening(localInterface, localIp);
        struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
        OpenAuthConnection(channel, innerLink, msg->getInt(msg, NM_KEY_GO_PORT, -1));
    }

    UpdateInnerLinkAndInterfaceInfoOnConnectGroupComplete(linkInfo, localInterface, localIp, remoteMac);
    channel->setP2pMac(channel, remoteMac);
    ret = ReturnConnectResult(linkInfo, interfaceInfo);
    self->needReply = false;
    return ret;
}

static int32_t SaveCurrentMessage(struct NegotiateMessage *msg)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    struct NegotiateMessage *curMsg = self->currentMsg;
    if (curMsg) {
        struct WifiDirectNegotiateChannel *channel = curMsg->getPointer(curMsg, NM_KEY_NEGO_CHANNEL, NULL);
        if (channel) {
            channel->destructor(channel);
        }
        NegotiateMessageDelete(curMsg);
        self->currentMsg = NULL;
    }

    struct NegotiateMessage *copyMsg = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(copyMsg, SOFTBUS_MALLOC_ERR, LOG_LABEL "malloc msg failed");
    copyMsg->deepCopy(copyMsg, msg);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, "channel is null");
    struct WifiDirectNegotiateChannel *channelCopy = channel->duplicate(channel);
    copyMsg->putPointer(copyMsg, NM_KEY_NEGO_CHANNEL, (void **)&channelCopy);

    self->currentMsg = copyMsg;
    return SOFTBUS_OK;
}

static void SetInnerLinkDeviceId(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_LOG(channel, LOG_LABEL "channel is null");

    char deviceId[UUID_BUF_LEN] = {0};
    channel->getDeviceId(channel, deviceId, sizeof(deviceId));
    CLOGI(LOG_LABEL "deviceId=%s", AnonymizesUUID(deviceId));

    innerLink->putString(innerLink, IL_KEY_DEVICE_ID, deviceId);
}

static int32_t OnRemoveGroupComplete(void)
{
    CLOGI(LOG_LABEL "remove group done");
    GetWifiDirectNegotiator()->handleSuccess(NULL);
    return SOFTBUS_OK;
}

// misc helper
static void NotifyNewClient(int requestId, char *localInterface, char *remoteMac)
{
    struct WifiDirectConnectParams params;
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = requestId;
    (void)strcpy_s(params.interface, sizeof(params.interface), localInterface);
    (void)strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);

    GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->notifyNewClientJoining(&params);
}

static int32_t BuildNotifyInfo(struct LinkInfo *linkInfo, char *string, size_t size)
{
    int32_t ret = sprintf_s(string, size, "%s\n%d\n%d\n%d\n%d",
                            linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, ""),
                            linkInfo->getInt(linkInfo, LI_KEY_CENTER_20M, -1),
                            linkInfo->getInt(linkInfo, LI_KEY_CENTER_FREQUENCY1, -1),
                            linkInfo->getInt(linkInfo, LI_KEY_CENTER_FREQUENCY2, -1),
                            linkInfo->getInt(linkInfo, LI_KEY_BANDWIDTH, -1));

    return ret < 0 ? SOFTBUS_ERR : SOFTBUS_OK;
}

static int32_t HandleFailureResponse(struct NegotiateMessage *msg, struct LinkInfo *linkInfo, int result)
{
    if (!GetP2pV2Processor()->needReply) {
        return result;
    }
    GetP2pV2Processor()->needReply = false;

    struct NegotiateMessage *response;
    response = BuildConnectResponse3(msg, linkInfo, result);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, "build response3 failed");
    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(response);
    return ret;
}

static int32_t ReturnConnectResult(struct LinkInfo *linkInfo, struct InterfaceInfo *interfaceInfo)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    struct NegotiateMessage *msg = self->currentMsg;
    if (!self->needReply) {
        struct NegotiateMessage success;
        NegotiateMessageConstructor(&success);
        char *remoteMac = linkInfo->getString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "");
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
        success.putContainer(&success, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
        success.putPointer(&success, NM_KEY_NEGO_CHANNEL, (void **)&channel);
        GetWifiDirectNegotiator()->handleSuccess(&success);
        NegotiateMessageDestructor(&success);
        return SOFTBUS_OK;
    }

    char *localMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");
    struct WifiDirectIpv4Info *localIpv4 = interfaceInfo->getRawData(interfaceInfo, II_KEY_IPV4, NULL, NULL);
    struct LinkInfo respLinkInfo;
    LinkInfoConstructorWithNameAndMode(&respLinkInfo, linkInfo->getString(linkInfo, LI_KEY_REMOTE_INTERFACE, ""),
                                       linkInfo->getString(linkInfo, LI_KEY_LOCAL_INTERFACE, ""),
                                       linkInfo->getInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE),
                                       linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE));
    respLinkInfo.putBoolean(&respLinkInfo, LI_KEY_IS_CLIENT, false);
    respLinkInfo.putString(&respLinkInfo, LI_KEY_REMOTE_BASE_MAC, localMac);
    respLinkInfo.putRawData(&respLinkInfo, LI_KEY_REMOTE_IPV4, localIpv4, sizeof(*localIpv4));

    struct NegotiateMessage *response = BuildConnectResponse3(msg, &respLinkInfo, OK);
    LinkInfoDestructor(&respLinkInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, "build response3 failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    LinkInfoDestructor(&respLinkInfo);
    NegotiateMessageDelete(response);
    self->needReply = false;
    return ret;
}

static struct P2pV2Processor g_processor = {
    .needReply = false,
    .currentRequestId = REQUEST_ID_INVALID,
    .createLink = CreateLink,
    .disconnectLink = DisconnectLink,
    .reuseLink = ReuseLink,
    .processNegotiateMessage = ProcessNegotiateMessage,
    .onOperationEvent = OnOperationEvent,
    .processUnhandledRequest = ProcessUnhandledRequest,
    .onReversal = OnReversal,
    .name = "P2pV2Processor",
};

/* static class method */
struct P2pV2Processor* GetP2pV2Processor(void)
{
    return &g_processor;
}