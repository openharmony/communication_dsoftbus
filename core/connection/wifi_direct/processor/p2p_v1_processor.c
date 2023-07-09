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

#include "p2p_v1_processor.h"
#include <string.h>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "wifi_direct_types.h"
#include "wifi_direct_negotiate_channel.h"
#include "channel/default_negotiate_channel.h"
#include "data/inner_link.h"
#include "data/negotiate_message.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_role_negotiator.h"
#include "wifi_direct_p2p_adapter.h"
#include "entity/wifi_direct_entity.h"
#include "entity/wifi_direct_entity_factory.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_perf_recorder.h"

#define LOG_LABEL "[WifiDirect] P2pV1Processor: "

#define COMMON_BUFFER_LEN 256
#define REMOVE_LINK_REQUEST_ID 555

/* private method forward declare */
static int32_t CreateLinkAsNone(char *remoteMac, enum WifiDirectRole expectRole, struct InnerLink *innerLink,
                                struct WifiDirectNegotiateChannel *channel);
static int32_t CreateLinkAsGo(int32_t requestId, char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel);
static int32_t CreateLinkAsGc(int32_t requestId, char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel);

static int32_t ProcessConnectRequest(struct NegotiateMessage *msg);
static int32_t ProcessConnectResponse(struct NegotiateMessage *msg);
static int32_t ProcessDisconnectRequest(struct NegotiateMessage *msg);
static int32_t ProcessReuseRequest(struct NegotiateMessage *msg);
static int32_t ProcessReuseResponse(struct NegotiateMessage *msg);
static int32_t ProcessGetInterfaceInfoRequest(struct NegotiateMessage *msg);
static int32_t GetRoleInfo(struct NegotiateMessage *msg, enum WifiDirectRole *myRoleOut,
                           enum WifiDirectRole *peerRoleOut, enum WifiDirectRole *expectRoleOut);

static int32_t CreateGroup(struct NegotiateMessage *msg);
static int32_t DestroyGroup(void);
static int32_t ConnectGroup(struct NegotiateMessage *msg);
static int32_t ReuseP2p(void);
static int32_t RemoveLink(const char *remoteMac);

static int32_t OnCreateGroupComplete(void);
static int32_t OnConnectGroupComplete(void);
static int32_t OnRemoveGroupComplete(void);

static struct NegotiateMessage* BuildConnectRequestAsGo(const char *remoteMac, const char *remoteIp,
                                                        struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildConnectRequestAsNone(const char *remoteMac, enum WifiDirectRole expectRole,
                                                          struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildConnectResponseAsGo(char *remoteMac, char *remoteIp,
                                                         struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildConnectResponseAsNone(const char *remoteMac,
                                                           struct WifiDirectNegotiateChannel *channel);

static struct NegotiateMessage* BuildReuseRequest(char *remoteMac, struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildDisconnectRequest(char *remoteMac,
                                                       struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildReuseResponse(int32_t result, struct WifiDirectNegotiateChannel *channel);
static struct NegotiateMessage* BuildInterfaceInfoResponse(struct NegotiateMessage *msg);
static struct NegotiateMessage* BuildNegotiateResult(enum WifiDirectErrorCode reason,
                                                     struct WifiDirectNegotiateChannel *channel);

static int32_t ProcessFailureResponse(struct NegotiateMessage *input, enum WifiDirectErrorCode reason);
static void UpdateReuseCount(int32_t delta);
static void InitBasicInnerLink(struct InnerLink *innerLink, bool isClient);
static void NotifyNewClient(int requestId, char *localInterface, char *remoteMac);
static void CancelNewClient(int requestId, char *localInterface, const char *remoteMac);
static int32_t ChoseFrequency(int32_t gcFreq, int32_t *gcChannelArray, size_t gcChannelArraySize);
static int32_t SaveCurrentMessage(struct NegotiateMessage *msg);
static void SetInnerLinkDeviceId(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static bool IsNeedDhcp(const char *gcIp, struct NegotiateMessage *msg);

/* public interface */
static int32_t CreateLink(struct WifiDirectConnectInfo *connectInfo)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo, SOFTBUS_INVALID_PARAM, LOG_LABEL "connect info is null");
    GetP2pV1Processor()->fastConnect.started = false;
    GetP2pV1Processor()->needReply = false;
    GetP2pV1Processor()->currentRequestId = connectInfo->requestId;

    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, remoteDeviceId,
                                                        sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, LOG_LABEL "get remote device id failed");
    CLOGI(LOG_LABEL "requestId=%d remoteDeviceId=%s", connectInfo->requestId, AnonymizesUUID(remoteDeviceId));

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link, false);
    link.putString(&link, IL_KEY_DEVICE_ID, remoteDeviceId);

    link.putBoolean(&link, IL_KEY_IS_SOURCE, true);
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, connectInfo->remoteMac);
    link.putRawData(&link, IL_KEY_LOCAL_IPV4, info->getRawData(info, II_KEY_IPV4, NULL, NULL),
                    sizeof(struct WifiDirectIpv4Info));

    enum WifiDirectRole myRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CLOGI(LOG_LABEL "myRole=%d", myRole);
    if (myRole == WIFI_DIRECT_ROLE_NONE) {
        ret = CreateLinkAsNone(connectInfo->remoteMac, connectInfo->expectRole, &link, connectInfo->negoChannel);
    } else if (myRole == WIFI_DIRECT_ROLE_GO) {
        ret = CreateLinkAsGo(connectInfo->requestId, connectInfo->remoteMac, &link, connectInfo->negoChannel);
    } else {
        ret = CreateLinkAsGc(connectInfo->requestId, connectInfo->remoteMac, &link, connectInfo->negoChannel);
    }

    InnerLinkDestructor(&link);
    return ret;
}

static int32_t ReuseLink(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *link)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo, SOFTBUS_INVALID_PARAM, LOG_LABEL "connect info is null");
    CLOGI(LOG_LABEL "requestId=%d remoteMac=%s", connectInfo->requestId,
          WifiDirectAnonymizeMac(connectInfo->remoteMac));
    GetP2pV1Processor()->needReply = false;

    struct WifiDirectIpv4Info *ipv4Info = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(ipv4Info, SOFTBUS_ERR, LOG_LABEL "p2p link is used by another service");

    struct NegotiateMessage *request = BuildReuseRequest(connectInfo->remoteMac, connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build reuse request failed");
    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(request);
    return ret;
}

static int32_t DisconnectLink(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connectInfo, SOFTBUS_INVALID_PARAM, LOG_LABEL "connect info is null");
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_INVALID_PARAM, LOG_LABEL "inner link is null");

    struct P2pV1Processor *self = GetP2pV1Processor();
    self->needReply = false;

    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");
    struct NegotiateMessage *request = BuildDisconnectRequest(remoteMac, connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_ERR, LOG_LABEL "build disconnect request failed");
    int32_t ret = GetWifiDirectNegotiator()->postData(request);
    NegotiateMessageDelete(request);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "post data failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, 0);
    CLOGI(LOG_LABEL "requestId=%d remoteMac=%s reuseCount=%d", connectInfo->requestId,
          WifiDirectAnonymizeMac(remoteMac), reuseCount);
    if (reuseCount == 0) {
        CLOGI(LOG_LABEL "reuseCount already 0");
        GetWifiDirectNegotiator()->handleSuccess(NULL);
        return SOFTBUS_OK;
    }

    enum WifiDirectProcessorState state = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    if (reuseCount > 1) {
        state = PROCESSOR_STATE_AVAILABLE;
    }

    ret = RemoveLink(remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "remove link failed");

    if (state == PROCESSOR_STATE_AVAILABLE) {
        GetWifiDirectNegotiator()->handleSuccess(NULL);
    } else {
        CLOGI(LOG_LABEL "wait removing group to be done");
        self->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    }

    return SOFTBUS_OK;
}

static int32_t ProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    switch (cmd) {
        case CMD_CONN_V1_REQ:
            return ProcessConnectRequest(msg);
        case CMD_CONN_V1_RESP:
            return ProcessConnectResponse(msg);
        case CMD_DISCONNECT_V1_REQ:
            return ProcessDisconnectRequest(msg);
        case CMD_REUSE_REQ:
            return ProcessReuseRequest(msg);
        case CMD_REUSE_RESP:
            return ProcessReuseResponse(msg);
        case CMD_PC_GET_INTERFACE_INFO_REQ:
            return ProcessGetInterfaceInfoRequest(msg);
        default:
            CLOGE(LOG_LABEL "unhandled cmd");
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t OnOperationEvent(int32_t requestId, int32_t result)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    CLOGI(LOG_LABEL "requestId=%d result=%d currentState=%d fastConnect=%d",
        requestId, result, self->currentState, self->fastConnect.started);

    if (result != OK) {
        if (self->fastConnect.started) {
            self->fastConnect.started = false;
            return result;
        }

        if (self->currentMsg) {
            return ProcessFailureResponse(self->currentMsg, result);
        }
        return SOFTBUS_OK;
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
            break;
    }

    self->currentState = PROCESSOR_STATE_AVAILABLE;
    self->needReply = false;
    return ret;
}

static void ProcessUnhandledRequest(struct NegotiateMessage *msg, int32_t reason)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    enum WifiDirectNegotiateCmdType type = msg->getInt(msg, NM_KEY_COMMAND_TYPE, CMD_INVALID);
    struct NegotiateMessage *response = NULL;

    if (type == CMD_REUSE_REQ) {
        CLOGI(LOG_LABEL "send busy reuse response");
        response = BuildReuseResponse(V1_ERROR_BUSY, channel);
    } else {
        CLOGI(LOG_LABEL "send busy negotiate response");
        response = BuildNegotiateResult(V1_ERROR_BUSY, channel);
    }

    if (response) {
        GetWifiDirectNegotiator()->postData(response);
        NegotiateMessageDelete(response);
    }
}

static void OnReversal(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    enum WifiDirectApiRole myApiRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    if (myApiRole == WIFI_DIRECT_API_ROLE_GO) {
        CLOGI(LOG_LABEL "decrease reuseCount and stop new client timer");
        char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
        RemoveLink(remoteMac);
        CancelNewClient(self->currentRequestId, IF_NAME_P2P, remoteMac);
    }

    GetWifiDirectNegotiator()->handleFailureWithoutChangeState(ERROR_WIFI_DIRECT_BIDIRECTIONAL_SIMULTANEOUS_REQ);
}

/* private method implement */
static int32_t CreateLinkAsNone(char *remoteMac, enum WifiDirectRole expectRole, struct InnerLink *innerLink,
                                struct WifiDirectNegotiateChannel *channel)
{
    CLOGI(LOG_LABEL "enter");
    if (!GetResourceManager()->isInterfaceAvailable(IF_NAME_P2P)) {
        CLOGE(LOG_LABEL "V1_ERROR_IF_NOT_AVAILABLE");
        return V1_ERROR_IF_NOT_AVAILABLE;
    }

    struct NegotiateMessage *output = BuildConnectRequestAsNone(remoteMac, expectRole, channel);
    CONN_CHECK_AND_RETURN_RET_LOG(output, SOFTBUS_ERR, LOG_LABEL "build connect request with gc info failed");

    struct WifiDirectNegotiator *negotiator = GetWifiDirectNegotiator();
    int32_t ret = negotiator->handleMessageFromProcessor(output, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(output);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "handle msg from processor failed");

    struct InnerLink *copyLink = InnerLinkNew();
    CONN_CHECK_AND_RETURN_RET_LOG(copyLink, SOFTBUS_ERR, LOG_LABEL "new copy link failed");
    copyLink->deepCopy(copyLink, innerLink);
    GetP2pV1Processor()->currentInnerLink = copyLink;
    return SOFTBUS_OK;
}

static int32_t CreateLinkAsGo(int32_t requestId, char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel)
{
    CLOGI(LOG_LABEL "enter");
    int32_t ret = ReuseP2p();
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "reuse p2p failed");

    NotifyNewClient(requestId, IF_NAME_P2P, remoteMac);

    char gcIp[IP_ADDR_STR_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, gcIp, sizeof(gcIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ERROR_P2P_APPLY_GC_IP_FAIL, LOG_LABEL "request gc ip failed");

    innerLink->putRemoteIpString(innerLink, gcIp);
    innerLink->putBoolean(innerLink, IL_KEY_IS_CLIENT, false);
    GetLinkManager()->notifyLinkChange(innerLink);

    struct NegotiateMessage *output = BuildConnectRequestAsGo(remoteMac, gcIp, channel);
    CONN_CHECK_AND_RETURN_RET_LOG(output, SOFTBUS_ERR, LOG_LABEL "build connect request with go info failed");

    struct WifiDirectNegotiator *negotiator = GetWifiDirectNegotiator();
    ret = negotiator->handleMessageFromProcessor(output, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    NegotiateMessageDelete(output);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "handle msg from processor failed");
    return SOFTBUS_OK;
}

static int32_t CreateLinkAsGc(int32_t requestId, char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel)
{
    CLOGE(LOG_LABEL "ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return V1_ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static int32_t GetRoleInfo(struct NegotiateMessage *msg, enum WifiDirectRole *myRoleOut,
                           enum WifiDirectRole *peerRoleOut, enum WifiDirectRole *expectRoleOut)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    enum WifiDirectApiRole myRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    enum WifiDirectRole peerRole = (enum WifiDirectRole)(msg->getInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE));
    enum WifiDirectRole expectRole =
        (enum WifiDirectRole)(msg->getInt(msg, NM_KEY_EXPECTED_ROLE, WIFI_DIRECT_ROLE_NONE));

    *myRoleOut = GetWifiDirectUtils()->transferModeToRole(myRole);
    *peerRoleOut = peerRole;
    *expectRoleOut = expectRole;

    return SOFTBUS_OK;
}

static int32_t CreateGroup(struct NegotiateMessage *msg)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CREATE_GROUP_START);
    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();

    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);
    bool isWideBandSupported = msg->getBoolean(msg, NM_KEY_WIDE_BAND_SUPPORTED, false);
    int32_t stationFrequency = msg->getInt(msg, NM_KEY_STATION_FREQUENCY, 0);
    char *channelListString = msg->getString(msg, NM_KEY_GC_CHANNEL_LIST, "");

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = netWorkUtils->stringToChannelList(channelListString, channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "transfer channel list failed");

    int32_t finalFrequency = ChoseFrequency(stationFrequency, channelArray, channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(finalFrequency > 0, SOFTBUS_ERR, LOG_LABEL "chose frequency failed");
    CLOGI(LOG_LABEL "stationFrequency=%d finalFrequency=%d", stationFrequency, finalFrequency);

    bool isLocalWideBandSupported = adapter->isWideBandSupported();
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.requestId = requestId;
    params.freq = finalFrequency;
    params.isWideBandSupported = isLocalWideBandSupported && isWideBandSupported;
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->createServer(&params);
}

static int32_t DestroyGroup(void)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.requestId = REMOVE_LINK_REQUEST_ID;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->destroyServer(&params);
}

static int32_t ConnectGroup(struct NegotiateMessage *msg)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_START);
    int32_t goPort = msg->getInt(msg, NM_KEY_GO_PORT, -1);
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *gcIp = msg->getString(msg, NM_KEY_GC_IP, "");
    GetP2pV1Processor()->goPort = goPort;
    CLOGI(LOG_LABEL "goPort=%d gcIp=%s groupConfig=%s", goPort, WifiDirectAnonymizeIp(gcIp), groupConfig);

    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.requestId = GetP2pV1Processor()->currentRequestId;
    params.isNeedDhcp = IsNeedDhcp(gcIp, msg);
    int32_t ret = strcpy_s(params.groupConfig, sizeof(params.groupConfig), groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy group config failed");
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface failed");
    ret = strcpy_s(params.gcIp, sizeof(params.gcIp), gcIp);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy group config failed");

    struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P);
    return entity->connect(&params);
}

static int32_t ReuseP2p(void)
{
    struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P);
    int32_t ret = entity->reuseLink(NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "V1_ERROR_REUSE_FAILED");
    UpdateReuseCount(1);
    return ret;
}

static int32_t RemoveLink(const char *remoteMac)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));

    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = REMOVE_LINK_REQUEST_ID;

    int32_t ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy remote mac failed");
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface name failed");

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, ERROR_SOURCE_NO_INTERFACE_INFO, LOG_LABEL "interface info is null");

    int32_t reuseCount = interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, 0);
    CLOGI(LOG_LABEL "reuseCount=%d", reuseCount);
    if (reuseCount == 0) {
        CLOGI(LOG_LABEL "reuseCount already 0, do not call entity disconnect");
        return SOFTBUS_OK;
    }

    ret = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->disconnect(&params);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "entity disconnect failed");
    UpdateReuseCount(-1);
    return SOFTBUS_OK;
}

static struct NegotiateMessage* BuildConnectRequestAsGo(const char *remoteMac, const char *remoteIp,
                                                        struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, NULL, LOG_LABEL "interface info is null");

    char *myMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");
    char groupConfig[GROUP_CONFIG_STR_LEN];
    int32_t ret = interfaceInfo->getP2pGroupConfig(interfaceInfo, groupConfig, sizeof(groupConfig));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "group config failed");

    char myIp[IP_ADDR_STR_LEN] = {0};
    ret = interfaceInfo->getIpString(interfaceInfo, myIp, sizeof(myIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get my ip failed");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    request->putInt(request, NM_KEY_VERSION, P2P_VERSION);
    request->putString(request, NM_KEY_MAC, myMac);
    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_REQ);
    request->putInt(request, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GO_INFO);
    request->putInt(request, NM_KEY_ROLE, WIFI_DIRECT_ROLE_GO);
    request->putInt(request, NM_KEY_EXPECTED_ROLE, WIFI_DIRECT_ROLE_GO);
    request->putString(request, NM_KEY_GROUP_CONFIG, groupConfig);
    request->putString(request, NM_KEY_GO_MAC, myMac);
    request->putString(request, NM_KEY_GO_IP, myIp);
    request->putInt(request, NM_KEY_GO_PORT, interfaceInfo->getInt(interfaceInfo, II_KEY_PORT, -1));
    request->putString(request, NM_KEY_GC_MAC, remoteMac);
    request->putString(request, NM_KEY_GC_IP, remoteIp);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildConnectRequestAsNone(const char *remoteMac, enum WifiDirectRole expectRole,
                                                          struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, NULL, LOG_LABEL "interface info is null");

    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = adapter->getChannel5GListIntArray(channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get channel list failed");
    char channelString[COMMON_BUFFER_LEN];
    ret = netWorkUtils->channelListToString(channelArray, channelArraySize, channelString, sizeof(channelString));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "channel to string failed");

    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_START);
    ret = adapter->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_END);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get self wifi cfg failed");

    char *myMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    /* common info */
    request->putInt(request, NM_KEY_VERSION, P2P_VERSION);
    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_REQ);
    request->putInt(request, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    request->putString(request, NM_KEY_MAC, myMac);
    request->putBoolean(request, NM_KEY_BRIDGE_SUPPORTED, false);
    request->putInt(request, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    request->putInt(request, NM_KEY_EXPECTED_ROLE, expectRole);

    /* gc info */
    request->putString(request, NM_KEY_GC_MAC, myMac);
    request->putString(request, NM_KEY_GC_CHANNEL_LIST, channelString);
    request->putInt(request, NM_KEY_STATION_FREQUENCY, adapter->getStationFrequency());
    request->putBoolean(request, NM_KEY_WIDE_BAND_SUPPORTED, adapter->isWideBandSupported());
    request->putString(request, NM_KEY_SELF_WIFI_CONFIG, (char *)selfWifiConfig);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}


static struct NegotiateMessage* BuildConnectResponseAsGo(char *remoteMac, char *remoteIp,
                                                         struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get local ip failed");

    int32_t goPort = info->getInt(info, II_KEY_PORT, -1);
    char groupConfig[GROUP_CONFIG_STR_LEN] = {0};
    ret = info->getP2pGroupConfig(info, groupConfig, sizeof(groupConfig));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get group cfg failed");
    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get wifi cfg failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    response->putInt(response, NM_KEY_VERSION, P2P_VERSION);
    response->putString(response, NM_KEY_MAC, myMac);
    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_RESP);
    response->putInt(response, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GO_INFO);
    response->putString(response, NM_KEY_IP, localIp);
    response->putString(response, NM_KEY_GO_MAC, myMac);
    response->putString(response, NM_KEY_GO_IP, localIp);
    response->putInt(response, NM_KEY_GO_PORT, goPort);
    response->putString(response, NM_KEY_GC_MAC, remoteMac);
    response->putString(response, NM_KEY_GC_IP, remoteIp);
    response->putString(response, NM_KEY_GROUP_CONFIG, groupConfig);
    response->putString(response, NM_KEY_SELF_WIFI_CONFIG, (char *)selfWifiConfig);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return response;
}

static struct NegotiateMessage* BuildConnectResponseAsNone(const char *remoteMac,
                                                           struct WifiDirectNegotiateChannel *channel)
{
    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    int32_t ret = SOFTBUS_ERR;
    char localIp[IP_ADDR_STR_LEN] = {0};
    (void)info->getIpString(info, localIp, sizeof(localIp));

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    ret = adapter->getChannel5GListIntArray(channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get channel list failed");
    char channelString[COMMON_BUFFER_LEN];
    ret = GetWifiDirectNetWorkUtils()->channelListToString(channelArray, channelArraySize, channelString,
                                                           sizeof(channelString));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "channel to string failed");

    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    ret = adapter->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get self wifi cfg failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    response->putInt(response, NM_KEY_VERSION, P2P_VERSION);
    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_RESP);
    response->putInt(response, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    response->putString(response, NM_KEY_MAC, myMac);
    response->putString(response, NM_KEY_IP, localIp);
    response->putString(response, NM_KEY_GC_MAC, myMac);
    response->putString(response, NM_KEY_GC_CHANNEL_LIST, channelString);
    response->putInt(response, NM_KEY_STATION_FREQUENCY, adapter->getStationFrequency());
    response->putBoolean(response, NM_KEY_WIDE_BAND_SUPPORTED, adapter->isWideBandSupported());
    response->putString(response, NM_KEY_SELF_WIFI_CONFIG, (char *)selfWifiConfig);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return response;
}

static struct NegotiateMessage* BuildDisconnectRequest(char *remoteMac, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_DISCONNECT_V1_REQ);
    request->putString(request, NM_KEY_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildReuseRequest(char *remoteMac, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, NULL, LOG_LABEL "new negotiate msg failed");

    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_REUSE_REQ);
    request->putString(request, NM_KEY_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildReuseResponse(int32_t result, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_REUSE_RESP);
    response->putString(response, NM_KEY_MAC, myMac);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    response->putInt(response, NM_KEY_RESULT, result);

    return response;
}

static struct NegotiateMessage* BuildInterfaceInfoResponse(struct NegotiateMessage *msg)
{
    char *interface = msg->getString(msg, NM_KEY_INTERFACE_NAME, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, NULL, LOG_LABEL "interface info is null");
    char localIp[IP_ADDR_STR_LEN] = {0};
    info->getIpString(info, localIp, sizeof(localIp));
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);

    CLOGI(LOG_LABEL "interface=%s localMac=%s localIp=%s", interface,
          WifiDirectAnonymizeMac(localMac), WifiDirectAnonymizeIp(localIp));
    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(response, NULL, LOG_LABEL "new negotiate msg failed");

    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_PC_GET_INTERFACE_INFO_RESP);
    response->putString(response, NM_KEY_MAC, localMac);
    response->putString(response, NM_KEY_GC_IP, localIp);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    return response;
}

static struct NegotiateMessage* BuildNegotiateResult(enum WifiDirectErrorCode reason,
                                                     struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *localInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    char localIp[IP_ADDR_STR_LEN] = {0};
    localInfo->getIpString(localInfo, localIp, sizeof(localIp));

    struct NegotiateMessage *result = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(result, NULL, LOG_LABEL "new negotiate msg failed");

    result->putInt(result, NM_KEY_VERSION, P2P_VERSION);
    result->putString(result, NM_KEY_MAC, localInfo->getString(localInfo, II_KEY_BASE_MAC, ""));
    result->putString(result, NM_KEY_IP, localIp);
    result->putInt(result, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_RESP);
    result->putInt(result, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_RESULT);
    result->putInt(result, NM_KEY_RESULT, reason);
    result->putPointer(result, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return result;
}

static int32_t ProcessConnectRequestAsGo(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    if (contentType != P2P_CONTENT_TYPE_GC_INFO) {
        CLOGE(LOG_LABEL "content type not equal gc info");
        ProcessFailureResponse(msg, V1_ERROR_BOTH_GO);
        return SOFTBUS_OK;
    }

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");
    char *remoteMac = msg->getString(msg, NM_KEY_GC_MAC, "");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link, false);
    SetInnerLinkDeviceId(msg, &link);
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    link.putBoolean(&link, IL_KEY_IS_SOURCE, false);
    link.putBoolean(&link, IL_KEY_IS_BEING_USED_BY_REMOTE, true);

    if (myRole != WIFI_DIRECT_ROLE_GO) {
        if (CreateGroup(msg) != SOFTBUS_OK) {
            CLOGE(LOG_LABEL "create group failed");
            ProcessFailureResponse(msg, V1_ERROR_CREATE_GROUP_FAILED);
            return SOFTBUS_OK;
        }

        GetP2pV1Processor()->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
        GetP2pV1Processor()->needReply = true;
        GetLinkManager()->notifyLinkChange(&link);
        InnerLinkDestructor(&link);
        int32_t ret = SaveCurrentMessage(msg);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "save current msg failed");

        GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
        CLOGI(LOG_LABEL "waiting create group to be done");
        return SOFTBUS_OK;
    }

    char remoteIp[IP_ADDR_STR_LEN];
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "apply gc ip failed");
        InnerLinkDestructor(&link);
        ProcessFailureResponse(msg, ERROR_P2P_APPLY_GC_IP_FAIL);
        return SOFTBUS_OK;
    }
    CLOGI(LOG_LABEL "apply gc ip %s", WifiDirectAnonymizeIp(remoteIp));

    ret = ReuseP2p();
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "reuse p2p failed");
        ProcessFailureResponse(msg, V1_ERROR_REUSE_FAILED);
        return SOFTBUS_OK;
    }

    struct WifiDirectIpv4Info *localIpv4 = info->get(info, II_KEY_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(localIpv4, SOFTBUS_ERR, LOG_LABEL "local ipv4 is null");
    link.putRawData(&link, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    link.putRemoteIpString(&link, remoteIp);
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    NotifyNewClient(msg->getInt(msg, NM_KEY_SESSION_ID, -1), IF_NAME_P2P, remoteMac);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");
    struct NegotiateMessage *output = BuildConnectResponseAsGo(remoteMac, remoteIp, channel);
    CONN_CHECK_AND_RETURN_RET_LOG(output, SOFTBUS_ERR, LOG_LABEL "build connection response with go info failed");
    GetP2pV1Processor()->needReply = false;
    ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(output, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(output);

    return ret;
}

static int32_t ProcessConnectRequestAsGc(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link, true);
    SetInnerLinkDeviceId(msg, &link);

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, remoteMac);

    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    CLOGI(LOG_LABEL "localMac=%s remoteMac=%s contentType=%d", WifiDirectAnonymizeMac(localMac),
          WifiDirectAnonymizeMac(remoteMac), contentType);

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    if (contentType == P2P_CONTENT_TYPE_GC_INFO) {
        // None(go) -- None
        GetLinkManager()->notifyLinkChange(&link);
        InnerLinkDestructor(&link);
        self->needReply = false;

        struct NegotiateMessage *response = BuildConnectResponseAsNone(remoteMac, channel);
        CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build response with gc info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_WAITING_CONNECT_REQUEST);
        NegotiateMessageDelete(response);
        CLOGD(LOG_LABEL "send response with gc info success");
        return SOFTBUS_OK;
    }

    if (myRole == WIFI_DIRECT_ROLE_GC) {
        int32_t ret = ReuseP2p();
        if (ret != SOFTBUS_OK) {
            CLOGE(LOG_LABEL "V1_ERROR_REUSE_FAILED");
            ret = V1_ERROR_REUSE_FAILED;
        }
        struct NegotiateMessage *response = BuildNegotiateResult(ret, channel);
        CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build response resulut failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
        NegotiateMessageDelete(response);
        CLOGD(LOG_LABEL "send response result success");
        return SOFTBUS_OK;
    }

    // Go -- None
    CLOGI(LOG_LABEL "start connect group");
    if (ConnectGroup(msg) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "connect group failed");
        return ProcessFailureResponse(msg, V1_ERROR_CONNECT_GROUP_FAILED);
    }

    char *localIp = msg->getString(msg, NM_KEY_GC_IP, "");
    char *remoteIp = msg->getString(msg, NM_KEY_GO_IP, "");
    link.putLocalIpString(&link, localIp);
    link.putRemoteIpString(&link, remoteIp);
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    int32_t ret = SaveCurrentMessage(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "save current msg failed");
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    self->needReply = true;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);

    CLOGI(LOG_LABEL "waiting connect group to be done");
    return SOFTBUS_OK;
}

static int32_t ProcessNoAvailableInterface(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    if (ret != SOFTBUS_OK) {
        ProcessFailureResponse(msg, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
        return SOFTBUS_OK;
    }
    CLOGI(LOG_LABEL "remoteDeviceId=%s", AnonymizesUUID(remoteDeviceId));

    ListNode *linkList = &GetLinkManager()->linkLists[WIFI_DIRECT_CONNECT_TYPE_P2P];
    struct InnerLink *link = NULL;
    LIST_FOR_EACH_ENTRY(link, linkList, struct InnerLink, node) {
        char *remoteDeviceIdOfLink = link->getString(link, IL_KEY_DEVICE_ID, "");
        if (strlen(remoteDeviceIdOfLink) == 0 || strcmp(remoteDeviceId, remoteDeviceIdOfLink) != 0) {
            continue;
        }

        GetLinkManager()->dump();
        CLOGI(LOG_LABEL "fix the obsolete link");
        if (myRole == WIFI_DIRECT_ROLE_GC) {
            (void)DestroyGroup();
            GetP2pV1Processor()->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
            ProcessFailureResponse(msg, ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED);
            return SOFTBUS_OK;
        }
    }

    ProcessFailureResponse(msg, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
    return SOFTBUS_OK;
}

static char *GetGoMac(enum WifiDirectRole myRole)
{
    if (myRole == WIFI_DIRECT_ROLE_NONE) {
        return "";
    }
    if (myRole == WIFI_DIRECT_ROLE_GO) {
        struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
        return info->getString(info, II_KEY_BASE_MAC, "");
    }

    ListNode *p2pList = &GetLinkManager()->linkLists[WIFI_DIRECT_CONNECT_TYPE_P2P];
    if (IsListEmpty(p2pList)) {
        return "";
    }
    struct InnerLink *link = LIST_ENTRY(GET_LIST_HEAD(p2pList), struct InnerLink, node);
    return link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
}

static int32_t ProcessConnectRequest(struct NegotiateMessage *msg)
{
    CLOGI(LOG_LABEL "enter");
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(interfaceInfo, SOFTBUS_ERR, LOG_LABEL "interface info is null");

    struct P2pV1Processor *self = GetP2pV1Processor();
    self->needReply = true;

    enum WifiDirectRole myRole;
    enum WifiDirectRole peerRole;
    enum WifiDirectRole expectRole;
    int32_t ret = GetRoleInfo(msg, &myRole, &peerRole, &expectRole);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get role info failed");

    if (myRole == WIFI_DIRECT_ROLE_NONE && !GetResourceManager()->isInterfaceAvailable(IF_NAME_P2P)) {
        CLOGE(LOG_LABEL "V1_ERROR_IF_NOT_AVAILABLE");
        ProcessFailureResponse(msg, V1_ERROR_IF_NOT_AVAILABLE);
        return SOFTBUS_OK;
    }

    char *remoteConfig = msg->getString(msg, NM_KEY_SELF_WIFI_CONFIG, "");
    if (strlen(remoteConfig) != 0) {
        CLOGI(LOG_LABEL "remoteConfigSize=%d", strlen(remoteConfig));
        ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "set wifi cfg failed");
    }

    char *localGoMac = GetGoMac(myRole);
    char *remoteGoMac = msg->getString(msg, NM_KEY_GO_MAC, "");
    enum WifiDirectRole finalRole = GetRoleNegotiator()->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectRole,
                                                                                          localGoMac, remoteGoMac);
    CLOGI(LOG_LABEL "finalRole=%d", finalRole);
    if (finalRole == WIFI_DIRECT_ROLE_GO) {
        return ProcessConnectRequestAsGo(msg, myRole);
    } else if (finalRole == WIFI_DIRECT_ROLE_GC) {
        return ProcessConnectRequestAsGc(msg, myRole);
    } else if ((int32_t)finalRole == ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE) {
        return ProcessNoAvailableInterface(msg, myRole);
    }

    CLOGI(LOG_LABEL "finalRole invalid");
    ProcessFailureResponse(msg, (enum WifiDirectErrorCode)finalRole);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseAsGo(struct NegotiateMessage *msg)
{
    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    if (contentType != P2P_CONTENT_TYPE_RESULT) {
        CLOGE(LOG_LABEL "content type not equal result type");
        return ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG;
    }

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    CLOGI(LOG_LABEL "remoteMac=%s", WifiDirectAnonymizeMac(remoteMac));

    enum WifiDirectErrorCode result = msg->getInt(msg, NM_KEY_RESULT, -1);
    if (result != OK) {
        CLOGE(LOG_LABEL "peer response error %d", result);
        RemoveLink(remoteMac);
        return result;
    }
    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_CONNECT_TYPE_P2P, false, IF_NAME_P2P, remoteMac);
    link.putInt(&link, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
    link.putRemoteIpString(&link, msg->getString(msg, NM_KEY_IP, ""));
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    struct NegotiateMessage output;
    NegotiateMessageConstructor(&output);
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    GetWifiDirectNegotiator()->handleSuccess(&output);
    NegotiateMessageDestructor(&output);

    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseWithGoInfoAsNone(struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    enum WifiDirectRole myRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    int32_t requestId = msg->getInt(msg, NM_KEY_SESSION_ID, -1);

    if (myRole != WIFI_DIRECT_ROLE_NONE) {
        CLOGE(LOG_LABEL "recv wrong connection response with go info");
        return SOFTBUS_ERR;
    }

    CLOGI(LOG_LABEL "start to connect group");
    if (ConnectGroup(msg) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "connect to group failed");
        return V1_ERROR_CONNECT_GROUP_FAILED;
    }
    if (!self->currentInnerLink) {
        CLOGE(LOG_LABEL "current inner link is null");
        return SOFTBUS_ERR;
    }

    char *localIp = msg->getString(msg, NM_KEY_GC_IP, "");
    char *remoteIp = msg->getString(msg, NM_KEY_IP, "");
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *groupConfigCopy = strdup(groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOG(groupConfigCopy, SOFTBUS_MALLOC_ERR, LOG_LABEL "dup group config failed");
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX] = {0};
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    int32_t ret = GetWifiDirectNetWorkUtils()->splitString(groupConfigCopy, "\n", configs, &configsSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(groupConfigCopy);
        CLOGE(LOG_LABEL "split group config failed");
    }

    struct InnerLink *link = self->currentInnerLink;
    link->putBoolean(link, IL_KEY_IS_CLIENT, true);
    link->putRemoteIpString(link, remoteIp);
    link->putLocalIpString(link, localIp);
    link->putString(link, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    link->putInt(link, IL_KEY_FREQUENCY, atoi(configs[P2P_GROUP_CONFIG_INDEX_FREQ]));
    GetLinkManager()->notifyLinkChange(link);
    InnerLinkDelete(link);
    self->currentInnerLink = NULL;

    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    self->currentRequestId = requestId;
    SoftBusFree(groupConfigCopy);

    ret = SaveCurrentMessage(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "save current msg failed");

    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    CLOGI(LOG_LABEL "waiting connect group to be done");

    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseWithGcInfoAsNone(struct NegotiateMessage *msg)
{
    int32_t ret = CreateGroup(msg);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "create group failed");
        return ret;
    }

    ret = SaveCurrentMessage(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "save current msg failed");
    GetP2pV1Processor()->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseAsNone(struct NegotiateMessage *msg)
{
    char *remoteConfig = msg->getString(msg, NM_KEY_SELF_WIFI_CONFIG, "");
    if (strlen(remoteConfig) != 0) {
        int32_t ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "set wifi cfg failed");
    }

    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_INVALID);
    if (contentType == P2P_CONTENT_TYPE_GO_INFO) {
        return ProcessConnectResponseWithGoInfoAsNone(msg);
    }

    if (contentType == P2P_CONTENT_TYPE_GC_INFO) {
        return ProcessConnectResponseWithGcInfoAsNone(msg);
    }

    enum WifiDirectErrorCode errorCode = msg->getInt(msg, NM_KEY_RESULT, -1);
    CLOGI(LOG_LABEL "errorCode=%d", errorCode);
    return errorCode;
}

static int32_t ProcessConnectResponse(struct NegotiateMessage *msg)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    enum WifiDirectRole myRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CLOGI(LOG_LABEL "myRole=%d", myRole);
    if (myRole == WIFI_DIRECT_ROLE_GO) {
        return ProcessConnectResponseAsGo(msg);
    } else if (myRole == WIFI_DIRECT_ROLE_NONE) {
        return ProcessConnectResponseAsNone(msg);
    }

    CLOGE(LOG_LABEL "myRole invalid");
    return V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE;
}

static int32_t ProcessDisconnectRequest(struct NegotiateMessage *msg)
{
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    int32_t ret = RemoveLink(remoteMac);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "remove link failed");
        return ProcessFailureResponse(msg, ERROR_REMOVE_LINK_FAILED);
    }

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, 0);
    if (reuseCount != 0) {
        GetWifiDirectNegotiator()->handleSuccess(NULL);
        return SOFTBUS_OK;
    }

    CLOGI(LOG_LABEL "wait removing group to be done");
    GetP2pV1Processor()->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    return SOFTBUS_OK;
}

static int32_t ProcessReuseRequest(struct NegotiateMessage *msg)
{
    int32_t result = V1_ERROR_REUSE_FAILED;
    struct NegotiateMessage *response = NULL;
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    if (!channel) {
        CLOGE(LOG_LABEL "channel is null");
        goto Failed;
    }
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (!info) {
        CLOGE(LOG_LABEL "interface info is null");
        goto Failed;
    }
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    struct InnerLink *oldLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    if (!oldLink) {
        CLOGE(LOG_LABEL "link is null");
        goto Failed;
    }
    if (ReuseP2p() != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "V1_ERROR_REUSE_FAILED");
        goto Failed;
    }

    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_CONNECT_TYPE_P2P,
                                 oldLink->getBoolean(oldLink, IL_KEY_IS_CLIENT, false), IF_NAME_P2P, remoteMac);
    link.putBoolean(&link, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);
    result = OK;

Failed:
    response = BuildReuseResponse(result, channel);
    result = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(response);
    return result;
}

static int32_t ProcessReuseResponse(struct NegotiateMessage *msg)
{
    int32_t result = msg->getInt(msg, NM_KEY_RESULT, SOFTBUS_ERR);
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");

    CLOGI(LOG_LABEL "result=%d remoteMac=%s", result, WifiDirectAnonymizeMac(remoteMac));
    CONN_CHECK_AND_RETURN_RET_LOG(result == OK, result, LOG_LABEL "remote response failed %d", result);

    int32_t res = ReuseP2p();
    if (res != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "local reuse failed, send disconnect to remote for decreasing reference");
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        struct NegotiateMessage *request = BuildDisconnectRequest(remoteMac, channel);
        GetWifiDirectNegotiator()->postData(request);
        return V1_ERROR_REUSE_FAILED;
    }

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "local interface info is null");
    bool isClient = info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE) != WIFI_DIRECT_API_ROLE_GO;

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_CONNECT_TYPE_P2P, isClient, IF_NAME_P2P, remoteMac);
    innerLink.putBoolean(&innerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    GetLinkManager()->notifyLinkChange(&innerLink);
    InnerLinkDestructor(&innerLink);

    struct InnerLink *newInnerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(newInnerLink, SOFTBUS_ERR, LOG_LABEL "inner link is null");
    struct NegotiateMessage output;
    NegotiateMessageConstructor(&output);
    output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)newInnerLink, sizeof(*newInnerLink));
    GetWifiDirectNegotiator()->handleSuccess(&output);
    NegotiateMessageDestructor(&output);

    return SOFTBUS_OK;
}

static int32_t ProcessGetInterfaceInfoRequest(struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(msg->getString(msg, NM_KEY_INTERFACE_NAME, ""));
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    if (ret == SOFTBUS_OK) {
        CLOGI(LOG_LABEL "local ip is not empty, send response");
        struct NegotiateMessage *response = BuildInterfaceInfoResponse(msg);
        CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build interface info response failed");
        ret = GetWifiDirectNegotiator()->postData(response);
        NegotiateMessageDelete(response);
        if (self->pendingRequestMsg) {
            NegotiateMessageDelete(self->pendingRequestMsg);
            self->pendingRequestMsg = NULL;
        }
        return ret;
    }

    CLOGI(LOG_LABEL "local ip is empty, wait local ip ready");
    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOG(request, SOFTBUS_OK, LOG_LABEL "new request message failed");
    request->deepCopy(request, msg);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, "channel is null");
    struct WifiDirectNegotiateChannel *channelCopy = channel->duplicate(channel);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channelCopy);
    GetP2pV1Processor()->pendingRequestMsg = request;

    return SOFTBUS_OK;
}

static void StartAuthListening(const char *localIp)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    int32_t port = info->getInt(info, II_KEY_PORT, -1);
    if (port > 0) {
        CLOGI(LOG_LABEL "already has started listening, port=%d", port);
        return;
    }

    port = StartListeningForDefaultChannel(localIp);
    info->putInt(info, II_KEY_PORT, port);
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

static void UpdateInnerLinkOnCreateGroupComplete(const char *localMac, const char *localIp,
                                                 const char *remoteMac, const char *remoteIp)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InnerLink link;
    InnerLinkConstructor(&link);

    InitBasicInnerLink(&link, false);
    SetInnerLinkDeviceId(self->currentMsg, &link);

    link.putLocalIpString(&link, localIp);
    link.putRemoteIpString(&link, remoteIp);
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    GetLinkManager()->notifyLinkChange(&link);

    InnerLinkDestructor(&link);
}

static int32_t OnCreateGroupComplete(void)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CREATE_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CLOGI(LOG_LABEL "create group done, timeUsed=%zuMS", GetWifiDirectPerfRecorder()->getTime(TC_CREATE_GROUP));

    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = self->currentMsg;
    CONN_CHECK_AND_RETURN_RET_LOG(msg, SOFTBUS_ERR, LOG_LABEL "current msg is null");

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char remoteIp[IP_ADDR_STR_LEN];
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "apply gc ip failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");

    char localIp[IP_ADDR_STR_LEN];
    ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "get local ip failed");

    UpdateReuseCount(1);
    UpdateInnerLinkOnCreateGroupComplete(localMac, localIp, remoteMac, remoteIp);
    NotifyNewClient(self->currentRequestId, IF_NAME_P2P, remoteMac);
    StartAuthListening(localIp);

    if (self->fastConnect.started) {
        CLOGI(LOG_LABEL "group created in fast connecting");
        if (self->fastConnect.sessionCreated) {
            CLOGI(LOG_LABEL "fast connect session already created");
            return self->fastConnect.sendGroupConfig();
        }
        return SOFTBUS_OK;
    }

    struct NegotiateMessage *output = NULL;
    if (self->needReply) {
        self->needReply = false;
        output = BuildConnectResponseAsGo(remoteMac, remoteIp, channel);
        CONN_CHECK_AND_RETURN_RET_LOG(output, SOFTBUS_ERR, LOG_LABEL "build connect response with go info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(output, NEGO_STATE_AVAILABLE);
    } else {
        output = BuildConnectRequestAsGo(remoteMac, remoteIp, channel);
        CONN_CHECK_AND_RETURN_RET_LOG(output, SOFTBUS_ERR, LOG_LABEL "build connect request with go info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(output, NEGO_STATE_WAITING_CONNECT_RESPONSE);
    }

    NegotiateMessageDelete(output);
    return SOFTBUS_OK;
}

static void UpdateInnerLinkOnConnectGroupComplete(const char *localMac, const char *localIp,
                                                  const char *remoteMac, const char *remoteIp)
{
    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_CONNECT_TYPE_P2P, true, IF_NAME_P2P, remoteMac);

    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putRemoteIpString(&link, remoteIp);
    link.putLocalIpString(&link, localIp);
    link.putInt(&link, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
    GetLinkManager()->notifyLinkChange(&link);

    InnerLinkDestructor(&link);
}

static int32_t OnConnectGroupComplete(void)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CLOGI(LOG_LABEL "connect group done, timeUsed=%zuMS", GetWifiDirectPerfRecorder()->getTime(TC_CONNECT_GROUP));

    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = self->currentMsg;
    CONN_CHECK_AND_RETURN_RET_LOG(msg, SOFTBUS_ERR, LOG_LABEL "current msg is null");

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "no p2p interface info");
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");

    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "get local ip failed");

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char *remoteIp = msg->getString(msg, NM_KEY_GO_IP, "");

    UpdateReuseCount(1);
    UpdateInnerLinkOnConnectGroupComplete(localMac, localIp, remoteMac, remoteIp);
    channel->setP2pMac(channel, remoteMac);
    StartAuthListening(localIp);

    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_CONNECT_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(innerLink, SOFTBUS_ERR, LOG_LABEL "inner link is null");
    OpenAuthConnection(channel, innerLink, self->goPort);

    if (self->needReply) {
        self->needReply = false;
        struct NegotiateMessage *response = BuildNegotiateResult(OK, channel);
        CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build result failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
        GetWifiDirectNegotiator()->syncLnnInfo(innerLink);
        NegotiateMessageDelete(response);
        return SOFTBUS_OK;
    }

    struct NegotiateMessage success;
    NegotiateMessageConstructor(&success);
    success.putContainer(&success, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
    GetWifiDirectNegotiator()->handleSuccess(&success);
    NegotiateMessageDestructor(&success);

    if (self->pendingRequestMsg && (ProcessGetInterfaceInfoRequest(self->pendingRequestMsg) != SOFTBUS_OK)) {
        CLOGE(LOG_LABEL "process get interface info request failed");
    }

    return SOFTBUS_OK;
}

static int32_t OnRemoveGroupComplete(void)
{
    CLOGI(LOG_LABEL "remove group done");
    GetWifiDirectNegotiator()->handleSuccess(NULL);
    return SOFTBUS_OK;
}

static int32_t ProcessFailureResponse(struct NegotiateMessage *input, enum WifiDirectErrorCode reason)
{
    if (!GetP2pV1Processor()->needReply) {
        CLOGI(LOG_LABEL "no need reply");
        return SOFTBUS_ERR;
    }
    GetP2pV1Processor()->needReply = false;

    struct WifiDirectNegotiateChannel *channel = input->getPointer(input, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    struct NegotiateMessage *response = BuildNegotiateResult(reason, channel);
    CONN_CHECK_AND_RETURN_RET_LOG(response, SOFTBUS_ERR, LOG_LABEL "build result failed");

    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(response, NEGO_STATE_AVAILABLE);
    NegotiateMessageDelete(response);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "handle msg from processor failed");
    return ret;
}

static void UpdateReuseCount(int32_t delta)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_LOG(interfaceInfo, LOG_LABEL "interface info is null");

    int32_t reuseCount = interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, 0);
    if (reuseCount == 0 && delta < 0) {
        CLOGE(LOG_LABEL "reuseCount already 0 and can not be reduced");
        return;
    }

    interfaceInfo->putInt(interfaceInfo, II_KEY_REUSE_COUNT, reuseCount + delta);
    CLOGI(LOG_LABEL "reuseCount=%d", interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, -1));
}

static void InitBasicInnerLink(struct InnerLink *innerLink, bool isClient)
{
    innerLink->putInt(innerLink, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_P2P);
    innerLink->putString(innerLink, IL_KEY_LOCAL_INTERFACE, IF_NAME_P2P);
    innerLink->putString(innerLink, IL_KEY_REMOTE_INTERFACE, IF_NAME_P2P);
    innerLink->putInt(innerLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTING);
    innerLink->putBoolean(innerLink, IL_KEY_IS_CLIENT, isClient);
}

static void NotifyNewClient(int requestId, char *localInterface, char *remoteMac)
{
    struct WifiDirectConnectParams params;
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = requestId;
    (void)strcpy_s(params.interface, sizeof(params.interface), localInterface);
    (void)strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);

    GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->notifyNewClientJoining(&params);
}

static void CancelNewClient(int requestId, char *localInterface, const char *remoteMac)
{
    struct WifiDirectConnectParams params;
    params.connectType = WIFI_DIRECT_CONNECT_TYPE_P2P;
    params.requestId = requestId;
    (void)strcpy_s(params.interface, sizeof(params.interface), localInterface);
    (void)strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);

    GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->cancelNewClientJoining(&params);
}

static int32_t PickIntersectionFrequency(int32_t *gcChannelArray, size_t gcChannelArraySize,
                                         int32_t *goChannelArray, size_t goChannelArraySize)
{
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();

    for (size_t i = 0; i < goChannelArraySize; i++) {
        if (netWorkUtils->isInChannelList(goChannelArray[goChannelArraySize - i - 1], gcChannelArray,
                                          gcChannelArraySize)) {
            return netWorkUtils->channelToFrequency(goChannelArray[goChannelArraySize - i - 1]);
        }
    }

    return FREQUENCY_INVALID;
}

static int32_t ChoseFrequency(int32_t gcFreq, int32_t *gcChannelArray, size_t gcChannelArraySize)
{
    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t goFreq = adapter->getStationFrequency();

    CLOGI(LOG_LABEL "goFreq=%d gcFreq=%d", goFreq, goFreq);
    if (goFreq != CHANNEL_INVALID || gcFreq != CHANNEL_INVALID) {
        int32_t recommendChannel = adapter->getRecommendChannel();
        if (recommendChannel != CHANNEL_INVALID) {
            CLOGI(LOG_LABEL "recommendChannel=%d", recommendChannel);
            return netWorkUtils->channelToFrequency(recommendChannel);
        }
    }

    int32_t goChannelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t goChannelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = adapter->getChannel5GListIntArray(goChannelArray, &goChannelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get local channel list failed");

    int32_t intersectionFreq = PickIntersectionFrequency(gcChannelArray, gcChannelArraySize,
                                                         goChannelArray, goChannelArraySize);
    if (intersectionFreq != FREQUENCY_INVALID) {
        CLOGI(LOG_LABEL "use intersectionFreq=%d", intersectionFreq);
        return intersectionFreq;
    }

    if (netWorkUtils->is2GBand(goFreq)) {
        CLOGI(LOG_LABEL "use goFreq=%d", goFreq);
        return goFreq;
    }
    if (netWorkUtils->is2GBand(gcFreq)) {
        CLOGI(LOG_LABEL "use gcFreq=%d", gcFreq);
        return gcFreq;
    }

    CLOGI(LOG_LABEL "use 2G_FIRST=%d", FREQUENCY_2G_FIRST);
    return FREQUENCY_2G_FIRST;
}

static int32_t SaveCurrentMessage(struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
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

static bool IsNeedDhcp(const char *gcIp, struct NegotiateMessage *msg)
{
    if (strlen(gcIp) == 0) {
        CLOGI(LOG_LABEL "gcIp is empty, DHCP is true");
        return true;
    }
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *groupConfigCopy = strdup(groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOG(groupConfigCopy, false, LOG_LABEL "dup group config failed");

    char *configs[P2P_GROUP_CONFIG_INDEX_MAX] = {0};
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    int32_t ret = GetWifiDirectNetWorkUtils()->splitString(groupConfigCopy, "\n", configs, &configsSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, LOG_LABEL "split group config failed");

    if (configsSize == P2P_GROUP_CONFIG_INDEX_MAX && strcmp(configs[P2P_GROUP_CONFIG_INDEX_MODE], "1") == 0) {
        CLOGI(LOG_LABEL "DHCP is true");
        SoftBusFree(groupConfigCopy);
        return true;
    }
    CLOGI(LOG_LABEL "DHCP is false");
    SoftBusFree(groupConfigCopy);
    return false;
}

static int FastConnectCreateLink(struct WifiDirectConnectInfo *connectInfo, enum WifiDirectRole *finalRole,
    const struct WDFastCfg *remoteCfg)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)connectInfo;
    (void)finalRole;
    (void)remoteCfg;
    return SOFTBUS_ERR;
}

static int FastConnectSendGroupConfig(void)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    return SOFTBUS_ERR;
}

static int OnFastConnectBcastDataReceived(struct WifiDirectConnectInfo *connectInfo,
    enum WifiDirectRole peerRole, struct WDFastCfg *remoteCfg)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)connectInfo;
    (void)peerRole;
    (void)remoteCfg;
    return SOFTBUS_ERR;
}

static int OnFastConnectSessionCreated(struct WifiDirectNegotiateChannel *channel)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)channel;
    return SOFTBUS_ERR;
}

static int OnFastConnectConfigRecvd(struct NegotiateMessage *msg)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)msg;
    return SOFTBUS_ERR;
}

static void OnFastConnectClientConnected(const char *remoteMac)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)remoteMac;
}

static void FastConnectStop(bool destroyGroup, const char *remoteMac)
{
    CLOGE(LOG_LABEL "p2pv1 not supported yet");
    (void)destroyGroup;
    (void)remoteMac;
}

static struct P2pV1Processor g_processor = {
    .needReply = false,
    .pendingRequestMsg = NULL,
    .currentRequestId = REQUEST_ID_INVALID,
    .createLink = CreateLink,
    .disconnectLink = DisconnectLink,
    .reuseLink = ReuseLink,
    .processNegotiateMessage = ProcessNegotiateMessage,
    .onOperationEvent = OnOperationEvent,
    .processUnhandledRequest = ProcessUnhandledRequest,
    .onReversal = OnReversal,
    .initBasicInnerLink = InitBasicInnerLink,
    .saveCurrentMessage = SaveCurrentMessage,
    .setInnerLinkDeviceId = SetInnerLinkDeviceId,
    .createGroup = CreateGroup,
    .connectGroup = ConnectGroup,
    .reuseP2p = ReuseP2p,
    .removeLink = RemoveLink,
    .notifyNewClient = NotifyNewClient,
    .cancelNewClient = CancelNewClient,
    .getGoMac = GetGoMac,

    .fastConnect.createLink = FastConnectCreateLink,
    .fastConnect.onBcastDataReceived = OnFastConnectBcastDataReceived,
    .fastConnect.onSessionCreated = OnFastConnectSessionCreated,
    .fastConnect.sendGroupConfig = FastConnectSendGroupConfig,
    .fastConnect.onConfigRecvd = OnFastConnectConfigRecvd,
    .fastConnect.onClientConnected = OnFastConnectClientConnected,
    .fastConnect.stop = FastConnectStop,
    .fastConnect.started = false,
    .fastConnect.sessionCreated = false,

    .name = "P2pV1Processor",
};

/* static class method */
struct P2pV1Processor* GetP2pV1Processor(void)
{
    return &g_processor;
}