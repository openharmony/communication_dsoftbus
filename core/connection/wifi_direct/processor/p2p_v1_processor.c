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
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "bus_center_manager.h"
#include "wifi_direct_types.h"
#include "wifi_direct_negotiate_channel.h"
#include "command/wifi_direct_command.h"
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
#include "utils/wifi_direct_timer_list.h"
#include "utils/wifi_direct_perf_recorder.h"

#define P2P_VERSION 2
#define COMMON_BUFFER_LEN 256
#define P2P_V1_WAITING_RESPONSE_TIME_MS 10000
#define P2P_V1_WAITING_REQUEST_TIME_MS 10000

/* private method forward declare */
static int32_t CreateLinkAsNone(char *remoteMac, enum WifiDirectRole expectRole, struct InnerLink *innerLink,
                                struct WifiDirectNegotiateChannel *channel);
static int32_t CreateLinkAsGo(int32_t requestId, const char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel);
static int32_t CreateLinkAsGc(int32_t requestId, const char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel);

static int32_t ProcessConnectRequest(struct WifiDirectCommand *command);
static int32_t ProcessConnectResponse(struct WifiDirectCommand *command);
static int32_t ProcessDisconnectRequest(struct WifiDirectCommand *command);
static int32_t ProcessReuseRequest(struct WifiDirectCommand *command);
static int32_t ProcessReuseResponse(struct WifiDirectCommand *command);
static int32_t ProcessGetInterfaceInfoRequest(struct NegotiateMessage *msg);
static int32_t GetRoleInfo(struct NegotiateMessage *msg, enum WifiDirectRole *myRoleOut,
                           enum WifiDirectRole *peerRoleOut, enum WifiDirectRole *expectRoleOut);

static int32_t CreateGroup(struct NegotiateMessage *msg);
static int32_t DestroyGroup(void);
static int32_t ConnectGroup(struct NegotiateMessage *msg);
static int32_t ReuseP2p(void);
static int32_t RemoveLink(const char *remoteMac);

static int32_t OnCreateGroupComplete(int32_t event);
static int32_t OnConnectGroupComplete(int32_t event);
static int32_t OnRemoveGroupComplete(int32_t event);

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

static void UpdateReuseCount(int32_t delta);
static void InitBasicInnerLink(struct InnerLink *innerLink);
static void NotifyNewClient(const char *localInterface, const char *remoteMac);
static void CancelNewClient(const char *localInterface, const char *remoteMac);
static int32_t ChoseFrequency(int32_t gcFreq, int32_t *gcChannelArray, size_t gcChannelArraySize);
static void SetInnerLinkDeviceId(struct NegotiateMessage *msg, struct InnerLink *innerLink);
static bool IsNeedDhcp(const char *gcIp, struct NegotiateMessage *msg);
static enum WifiDirectRole TransferExpectedRole(uint32_t expectApiRole);

static void StartTimer(int32_t timeMs);
static void StopTimer(void);
static void ProcessFailure(int32_t errorCode, bool reply);
static void ProcessSuccess(struct InnerLink *innerLink, bool reply);

/* public interface */
static int32_t CreateLink(struct WifiDirectConnectInfo *connectInfo)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "connect info is null");

    int32_t ret = SOFTBUS_OK;
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    ret = LnnGetRemoteStrInfo(connectInfo->remoteNetworkId, STRING_KEY_UUID, remoteDeviceId, sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT,
                                   "get remote device id failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteDeviceId=%{public}s", connectInfo->requestId,
              WifiDirectAnonymizeDeviceId(remoteDeviceId));

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, V1_ERROR_IF_NOT_AVAILABLE, CONN_WIFI_DIRECT, "interface info is null");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link);
    link.putString(&link, IL_KEY_DEVICE_ID, remoteDeviceId);

    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, connectInfo->remoteMac);
    link.putRawData(&link, IL_KEY_LOCAL_IPV4, info->getRawData(info, II_KEY_IPV4, NULL, NULL),
                    sizeof(struct WifiDirectIpv4Info));

    enum WifiDirectRole myRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", myRole);
    if (myRole == WIFI_DIRECT_ROLE_NONE) {
        enum WifiDirectRole expectRole = TransferExpectedRole(connectInfo->expectApiRole);
        CONN_LOGI(CONN_WIFI_DIRECT, "expectRole=%{public}d", expectRole);
        ret = CreateLinkAsNone(connectInfo->remoteMac, expectRole, &link, connectInfo->negoChannel);
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
    CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "connect info is null");
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s", connectInfo->requestId,
          WifiDirectAnonymizeMac(connectInfo->remoteMac));

    struct WifiDirectIpv4Info *ipv4Info = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(ipv4Info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "p2p link is used by another service");

    struct NegotiateMessage *request = BuildReuseRequest(connectInfo->remoteMac, connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOGW(request, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build reuse request failed");
    int32_t ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(request);
    NegotiateMessageDelete(request);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_POST_MESSAGE_FAILED, CONN_WIFI_DIRECT,
        "post request failed");

    StartTimer(P2P_V1_WAITING_RESPONSE_TIME_MS);
    GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REUSE_RESPONSE;
    return ret;
}

static int32_t DisconnectLink(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "connect info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(innerLink, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "inner link is null");

    struct P2pV1Processor *self = GetP2pV1Processor();
    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");
    struct NegotiateMessage *request = BuildDisconnectRequest(remoteMac, connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOGW(request, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build disconnect request failed");
    int32_t ret = GetWifiDirectNegotiator()->postData(request);
    NegotiateMessageDelete(request);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "post data failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");

    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, 0);
    CONN_LOGI(CONN_WIFI_DIRECT,
        "requestId=%{public}d, remoteMac=%{public}s, reuseCount=%{public}d", connectInfo->requestId,
          WifiDirectAnonymizeMac(remoteMac), reuseCount);
    if (reuseCount == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount already 0");
        ProcessSuccess(NULL, false);
        return SOFTBUS_OK;
    }

    enum P2pV1ProcessorState state = P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    if (reuseCount > 1) {
        state = P2P_V1_PROCESSOR_STATE_AVAILABLE;
    }

    ret = RemoveLink(remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "remove link failed");

    if (state == P2P_V1_PROCESSOR_STATE_AVAILABLE) {
        ProcessSuccess(NULL, false);
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "wait removing group to be done");
        self->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    }

    return SOFTBUS_OK;
}

static void ProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct WifiDirectCommand *command)
{
    bool reply = true;
    int32_t ret = SOFTBUS_OK;
    struct P2pV1Processor *self = GetP2pV1Processor();
    if (self->passiveCommand != NULL) {
        self->passiveCommand->destructor(self->passiveCommand);
    }
    self->passiveCommand = command;
    CONN_LOGI(CONN_WIFI_DIRECT, "passiveCommand=%{public}d", command->type);

    switch (cmd) {
        case CMD_CONN_V1_REQ:
            ret = ProcessConnectRequest(command);
            break;
        case CMD_CONN_V1_RESP:
            reply = false;
            ret = ProcessConnectResponse(command);
            break;
        case CMD_DISCONNECT_V1_REQ:
            reply = false;
            ret = ProcessDisconnectRequest(command);
            break;
        case CMD_REUSE_REQ:
            ret = ProcessReuseRequest(command);
            break;
        case CMD_REUSE_RESP:
            reply = false;
            ret = ProcessReuseResponse(command);
            break;
        case CMD_PC_GET_INTERFACE_INFO_REQ:
            ret = ProcessGetInterfaceInfoRequest(command->msg);
            break;
        default:
            CONN_LOGW(CONN_WIFI_DIRECT, "ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG");
            ret = ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG;
    }

    if (ret != SOFTBUS_OK) {
        ProcessFailure(ret, reply);
    }
}

static void OnOperationEvent(int32_t event, void *data)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "event=%{public}d", event);
    bool reply = true;
    int32_t ret = SOFTBUS_OK;
    struct P2pV1Processor *self = GetP2pV1Processor();
    enum P2pV1ProcessorState currentState = self->currentState;

    switch (currentState) {
        case P2P_V1_PROCESSOR_STATE_WAITING_CREATE_GROUP:
            ret = OnCreateGroupComplete(event);
            break;
        case P2P_V1_PROCESSOR_STATE_WAITING_CONNECT_GROUP:
            ret = OnConnectGroupComplete(event);
            break;
        case P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP:
            reply = false;
            ret = OnRemoveGroupComplete(event);
            break;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "ignore entity event at available state");
    }

    if (ret != SOFTBUS_OK) {
        ProcessFailure(ret, reply);
    }
}

static void ResetContext(void)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct P2pV1Processor *self = GetP2pV1Processor();
    self->currentState = P2P_V1_PROCESSOR_STATE_AVAILABLE;
    self->pendingErrorCode = OK;
    if (self->currentInnerLink != NULL) {
        self->currentInnerLink->destructor(self->currentInnerLink);
        self->currentInnerLink = NULL;
    }
    if (self->activeCommand != NULL) {
        self->activeCommand->destructor(self->activeCommand);
        self->activeCommand = NULL;
        CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=NULL");
    }
    if (self->passiveCommand != NULL) {
        self->passiveCommand->destructor(self->passiveCommand);
        self->passiveCommand = NULL;
        CONN_LOGI(CONN_WIFI_DIRECT, "passiveCommand=NULL");
    }
}

static bool IsMessageNeedPending(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    CONN_LOGI(CONN_WIFI_DIRECT, "currentState=%{public}d", self->currentState);
    switch (self->currentState) {
        case P2P_V1_PROCESSOR_STATE_AVAILABLE:
            return self->passiveCommand != NULL;
        case P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE:
            return !(cmd == CMD_CONN_V1_RESP || cmd == CMD_CONN_V1_REQ);
        case P2P_V1_PROCESSOR_STATE_WAITING_REUSE_RESPONSE:
            return !(cmd == CMD_REUSE_RESP || cmd == CMD_REUSE_REQ);
        case P2P_V1_PROCESSOR_STATE_WAITING_REQUEST:
            return cmd != CMD_CONN_V1_REQ;
        case P2P_V1_PROCESSOR_STATE_WAITING_CREATE_GROUP:
            return true;
        case P2P_V1_PROCESSOR_STATE_WAITING_CONNECT_GROUP:
            return true;
        case P2P_V1_PROCESSOR_STATE_WAITING_DISCONNECT:
            return true;
        case P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP:
            return true;
        default:
            return true;
    }
}

/* private method implement */
static int32_t CreateLinkAsNone(char *remoteMac, enum WifiDirectRole expectRole, struct InnerLink *innerLink,
                                struct WifiDirectNegotiateChannel *channel)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (!GetResourceManager()->isInterfaceAvailable(IF_NAME_P2P, false)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "V1_ERROR_IF_NOT_AVAILABLE");
        return V1_ERROR_IF_NOT_AVAILABLE;
    }

    struct NegotiateMessage *output = BuildConnectRequestAsNone(remoteMac, expectRole, channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(output, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build connect request with gc info failed");

    struct WifiDirectNegotiator *negotiator = GetWifiDirectNegotiator();
    int32_t ret = negotiator->handleMessageFromProcessor(output);
    NegotiateMessageDelete(output);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "handle msg from processor failed");

    struct InnerLink *copyLink = InnerLinkNew();
    CONN_CHECK_AND_RETURN_RET_LOGW(copyLink, SOFTBUS_ERR, CONN_WIFI_DIRECT, "new copy link failed");
    copyLink->deepCopy(copyLink, innerLink);
    GetP2pV1Processor()->currentInnerLink = copyLink;

    StartTimer(P2P_V1_WAITING_RESPONSE_TIME_MS);
    GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE;
    return SOFTBUS_OK;
}

static int32_t CreateLinkAsGo(int32_t requestId, const char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    int32_t ret = ReuseP2p();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse p2p failed");

    NotifyNewClient(IF_NAME_P2P, remoteMac);

    char gcIp[IP_ADDR_STR_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, gcIp, sizeof(gcIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ERROR_P2P_APPLY_GC_IP_FAIL, CONN_WIFI_DIRECT,
        "request gc ip failed");

    innerLink->putRemoteIpString(innerLink, gcIp);
    GetLinkManager()->notifyLinkChange(innerLink);

    struct NegotiateMessage *output = BuildConnectRequestAsGo(remoteMac, gcIp, channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(output, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build connect request with go info failed");

    struct WifiDirectNegotiator *negotiator = GetWifiDirectNegotiator();
    ret = negotiator->handleMessageFromProcessor(output);
    NegotiateMessageDelete(output);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "handle msg from processor failed");

    StartTimer(P2P_V1_WAITING_RESPONSE_TIME_MS);
    GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE;
    return SOFTBUS_OK;
}

static int32_t CreateLinkAsGc(int32_t requestId, const char *remoteMac, struct InnerLink *innerLink,
                              struct WifiDirectNegotiateChannel *channel)
{
    (void)requestId;
    (void)remoteMac;
    (void)innerLink;
    (void)channel;
    CONN_LOGE(CONN_WIFI_DIRECT, "V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE;
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

    bool isRemoteWideBandSupported = msg->getBoolean(msg, NM_KEY_WIDE_BAND_SUPPORTED, false);
    int32_t stationFrequency = msg->getInt(msg, NM_KEY_STATION_FREQUENCY, 0);
    char *channelListString = msg->getString(msg, NM_KEY_GC_CHANNEL_LIST, "");

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = netWorkUtils->stringToChannelList(channelListString, channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "transfer channel list failed");

    int32_t finalFrequency = ChoseFrequency(stationFrequency, channelArray, channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(finalFrequency > 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "chose frequency failed");

    bool isLocalWideBandSupported = adapter->isWideBandSupported();
    CONN_LOGI(CONN_WIFI_DIRECT, "stationFrequency=%{public}d, finalFrequency=%{public}d, "
                                "localWideBand=%{public}d, remoteWideBand=%{public}d",
          stationFrequency, finalFrequency, isLocalWideBandSupported, isRemoteWideBandSupported);

    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.frequency = finalFrequency;
    params.isWideBandSupported = isLocalWideBandSupported && isRemoteWideBandSupported;
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->createServer(&params);
}

static int32_t DestroyGroup(void)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface failed");

    return GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->destroyServer(&params);
}

static int32_t ConnectGroup(struct NegotiateMessage *msg)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_START);
    int32_t goPort = msg->getInt(msg, NM_KEY_GO_PORT, -1);
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *gcIp = msg->getString(msg, NM_KEY_GC_IP, "");
    GetP2pV1Processor()->goPort = goPort;
    CONN_LOGI(CONN_WIFI_DIRECT, "goPort=%{public}d, gcIp=%{public}s", goPort, WifiDirectAnonymizeIp(gcIp));

    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    params.isNeedDhcp = IsNeedDhcp(gcIp, msg);
    int32_t ret = strcpy_s(params.groupConfig, sizeof(params.groupConfig), groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy group config failed");
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface failed");
    ret = strcpy_s(params.gcIp, sizeof(params.gcIp), gcIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy group config failed");

    struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P);
    return entity->connect(&params);
}

static int32_t ReuseP2p(void)
{
    struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P);
    int32_t ret = entity->reuseLink(NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "V1_ERROR_REUSE_FAILED");
    UpdateReuseCount(1);
    return ret;
}

static int32_t RemoveLink(const char *remoteMac)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));

    int32_t ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy remote mac failed");
    ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface name failed");

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(interfaceInfo, ERROR_SOURCE_NO_INTERFACE_INFO, CONN_WIFI_DIRECT,
        "interface info is null");

    int32_t reuseCount = interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", reuseCount);
    if (reuseCount == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount already 0, do not call entity disconnect");
        return SOFTBUS_OK;
    }

    ret = GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->disconnect(&params);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "entity disconnect failed");
    UpdateReuseCount(-1);
    return SOFTBUS_OK;
}

static struct NegotiateMessage* BuildConnectRequestAsGo(const char *remoteMac, const char *remoteIp,
                                                        struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(interfaceInfo, NULL, CONN_WIFI_DIRECT, "interface info is null");

    char *myMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");
    char groupConfig[GROUP_CONFIG_STR_LEN];
    int32_t ret = interfaceInfo->getP2pGroupConfig(interfaceInfo, groupConfig, sizeof(groupConfig));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "group config failed");

    char myIp[IP_ADDR_STR_LEN] = {0};
    ret = interfaceInfo->getIpString(interfaceInfo, myIp, sizeof(myIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get my ip failed");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(request, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

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
    request->putBoolean(request, NM_KEY_BRIDGE_SUPPORTED, false);
    request->putString(request, NM_KEY_SELF_WIFI_CONFIG, "");
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildConnectRequestAsNone(const char *remoteMac, enum WifiDirectRole expectRole,
                                                          struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(interfaceInfo, NULL, CONN_WIFI_DIRECT, "interface info is null");

    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = adapter->getChannel5GListIntArray(channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get channel list failed");
    char channelString[COMMON_BUFFER_LEN];
    ret = netWorkUtils->channelListToString(channelArray, channelArraySize, channelString, sizeof(channelString));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "channel to string failed");

    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_START);
    ret = adapter->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    GetWifiDirectPerfRecorder()->record(TP_P2P_GET_WIFI_CONFIG_END);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get self wifi cfg failed");

    char *myMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(request, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

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
    request->putString(request, NM_KEY_GO_MAC, "");
    request->putString(request, NM_KEY_GC_CHANNEL_LIST, channelString);
    request->putInt(request, NM_KEY_STATION_FREQUENCY, adapter->getStationFrequencyWithFilter());
    request->putBoolean(request, NM_KEY_WIDE_BAND_SUPPORTED, adapter->isWideBandSupported());
    request->putString(request, NM_KEY_SELF_WIFI_CONFIG, (char *)selfWifiConfig);
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}


static struct NegotiateMessage* BuildConnectResponseAsGo(char *remoteMac, char *remoteIp,
                                                         struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get local ip failed");

    int32_t goPort = info->getInt(info, II_KEY_PORT, -1);
    char groupConfig[GROUP_CONFIG_STR_LEN] = {0};
    ret = info->getP2pGroupConfig(info, groupConfig, sizeof(groupConfig));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get group cfg failed");
    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get wifi cfg failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(response, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

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
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    int32_t ret = SOFTBUS_ERR;
    char localIp[IP_ADDR_STR_LEN] = {0};
    (void)info->getIpString(info, localIp, sizeof(localIp));

    int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
    ret = adapter->getChannel5GListIntArray(channelArray, &channelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get channel list failed");
    char channelString[COMMON_BUFFER_LEN];
    ret = GetWifiDirectNetWorkUtils()->channelListToString(channelArray, channelArraySize, channelString,
                                                           sizeof(channelString));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "channel to string failed");

    uint8_t selfWifiConfig[WIFI_CFG_INFO_MAX_LEN] = {0};
    size_t selfWifiConfigSize = WIFI_CFG_INFO_MAX_LEN;
    ret = adapter->getSelfWifiConfigInfo(selfWifiConfig, &selfWifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get self wifi cfg failed");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(response, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

    response->putInt(response, NM_KEY_VERSION, P2P_VERSION);
    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_RESP);
    response->putInt(response, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    response->putString(response, NM_KEY_MAC, myMac);
    response->putString(response, NM_KEY_IP, localIp);
    response->putString(response, NM_KEY_GC_MAC, myMac);
    response->putString(response, NM_KEY_GC_CHANNEL_LIST, channelString);
    response->putString(response, NM_KEY_GO_MAC, remoteMac);
    response->putInt(response, NM_KEY_STATION_FREQUENCY, adapter->getStationFrequencyWithFilter());
    response->putBoolean(response, NM_KEY_WIDE_BAND_SUPPORTED, adapter->isWideBandSupported());
    response->putString(response, NM_KEY_SELF_WIFI_CONFIG, (char *)selfWifiConfig);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return response;
}

static struct NegotiateMessage* BuildDisconnectRequest(char *remoteMac, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");
    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(request, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_DISCONNECT_V1_REQ);
    request->putString(request, NM_KEY_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildReuseRequest(char *remoteMac, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");

    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(request, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

    request->putInt(request, NM_KEY_COMMAND_TYPE, CMD_REUSE_REQ);
    request->putString(request, NM_KEY_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    request->putPointer(request, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return request;
}

static struct NegotiateMessage* BuildReuseResponse(int32_t result, struct WifiDirectNegotiateChannel *channel)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");
    char *myMac = info->getString(info, II_KEY_BASE_MAC, "");

    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(response, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

    response->putInt(response, NM_KEY_COMMAND_TYPE, CMD_REUSE_RESP);
    response->putString(response, NM_KEY_MAC, myMac);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    response->putInt(response, NM_KEY_RESULT, ErrorCodeToV1ProtocolCode(result));

    return response;
}

static struct NegotiateMessage* BuildInterfaceInfoResponse(struct NegotiateMessage *msg)
{
    char *interface = msg->getString(msg, NM_KEY_INTERFACE_NAME, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, NULL, CONN_WIFI_DIRECT, "interface info is null");
    char localIp[IP_ADDR_STR_LEN] = {0};
    info->getIpString(info, localIp, sizeof(localIp));
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);

    CONN_LOGI(CONN_WIFI_DIRECT, "interface=%{public}s, localMac=%{public}s, localIp=%{public}s", interface,
          WifiDirectAnonymizeMac(localMac), WifiDirectAnonymizeIp(localIp));
    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(response, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

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
    CONN_CHECK_AND_RETURN_RET_LOGE(result, NULL, CONN_WIFI_DIRECT, "new negotiate msg failed");

    result->putInt(result, NM_KEY_VERSION, P2P_VERSION);
    result->putString(result, NM_KEY_MAC, localInfo->getString(localInfo, II_KEY_BASE_MAC, ""));
    result->putString(result, NM_KEY_IP, localIp);
    result->putInt(result, NM_KEY_COMMAND_TYPE, CMD_CONN_V1_RESP);
    result->putInt(result, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_RESULT);
    result->putInt(result, NM_KEY_RESULT, ErrorCodeToV1ProtocolCode(reason));
    result->putPointer(result, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    return result;
}

static int32_t SendConnectResponseAsGo(struct NegotiateMessage *msg, struct InnerLink *link, struct InterfaceInfo *info)
{
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    char *remoteMac = msg->getString(msg, NM_KEY_GC_MAC, "");
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ERROR_P2P_APPLY_GC_IP_FAIL, CONN_WIFI_DIRECT,
        "apply gc ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "apply gc ip. WifiDirectAnonymizeIp=%{public}s", WifiDirectAnonymizeIp(remoteIp));

    ret = ReuseP2p();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_REUSE_FAILED, CONN_WIFI_DIRECT, "reuse p2p failed");

    struct WifiDirectIpv4Info *localIpv4 = info->get(info, II_KEY_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(localIpv4, SOFTBUS_ERR, CONN_WIFI_DIRECT, "local ipv4 is null");
    link->putRawData(link, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
    link->putRemoteIpString(link, remoteIp);
    GetLinkManager()->notifyLinkChange(link);

    NotifyNewClient(IF_NAME_P2P, remoteMac);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");
    struct NegotiateMessage *output = BuildConnectResponseAsGo(remoteMac, remoteIp, channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(output, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "build connection response with go info failed");
    ret = GetWifiDirectNegotiator()->handleMessageFromProcessor(output);
    NegotiateMessageDelete(output);

    return ret;
}

static int32_t ProcessConnectRequestAsGo(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    CONN_CHECK_AND_RETURN_RET_LOGW(contentType == P2P_CONTENT_TYPE_GC_INFO, V1_ERROR_BOTH_GO, CONN_WIFI_DIRECT,
        "content type not equal gc info");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link);
    SetInnerLinkDeviceId(msg, &link);
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, info->getString(info, II_KEY_BASE_MAC, ""));
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, msg->getString(msg, NM_KEY_GC_MAC, ""));
    link.putBoolean(&link, IL_KEY_IS_BEING_USED_BY_REMOTE, true);

    int32_t ret = SOFTBUS_OK;
    if (myRole != WIFI_DIRECT_ROLE_GO) {
        ret = CreateGroup(msg);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_CREATE_GROUP_FAILED, CONN_WIFI_DIRECT,
            "create group failed");
        GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_CREATE_GROUP;
        GetLinkManager()->notifyLinkChange(&link);
        InnerLinkDestructor(&link);
        CONN_LOGI(CONN_WIFI_DIRECT, "waiting create group to be done");
        return SOFTBUS_OK;
    }

    ret = SendConnectResponseAsGo(msg, &link, info);
    InnerLinkDestructor(&link);
    ProcessSuccess(NULL, false);
    return ret;
}

static int32_t ProcessConnectRequestAsGc(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");

    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link);
    SetInnerLinkDeviceId(msg, &link);

    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, remoteMac);

    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    CONN_LOGI(CONN_WIFI_DIRECT,
        "localMac=%{public}s, remoteMac=%{public}s, contentType=%{public}d", WifiDirectAnonymizeMac(localMac),
        WifiDirectAnonymizeMac(remoteMac), contentType);

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");

    if (contentType == P2P_CONTENT_TYPE_GC_INFO) {
        // None(go) -- None
        GetLinkManager()->notifyLinkChange(&link);
        InnerLinkDestructor(&link);
        struct NegotiateMessage *response = BuildConnectResponseAsNone(remoteMac, channel);
        CONN_CHECK_AND_RETURN_RET_LOGW(response, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build response with gc info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(response);
        NegotiateMessageDelete(response);
        StartTimer(P2P_V1_WAITING_REQUEST_TIME_MS);
        self->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REQUEST;
        CONN_LOGD(CONN_WIFI_DIRECT, "send response with gc info success");
        return SOFTBUS_OK;
    }

    int32_t ret = SOFTBUS_OK;
    if (myRole == WIFI_DIRECT_ROLE_GC) {
        ret = ReuseP2p();
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_REUSE_FAILED, CONN_WIFI_DIRECT,
            "V1_ERROR_REUSE_FAILED");
        ProcessSuccess(NULL, true);
        return SOFTBUS_OK;
    }

    // Go -- None
    StopTimer();
    CONN_LOGI(CONN_WIFI_DIRECT, "start connect group");
    ret = ConnectGroup(msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_CONNECT_GROUP_FAILED, CONN_WIFI_DIRECT,
        "connect group failed");
    link.putLocalIpString(&link, msg->getString(msg, NM_KEY_GC_IP, ""));
    link.putRemoteIpString(&link, msg->getString(msg, NM_KEY_GO_IP, ""));
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    self->currentState = P2P_V1_PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    CONN_LOGI(CONN_WIFI_DIRECT, "waiting connect group to be done");
    return SOFTBUS_OK;
}

static int32_t ProcessNoAvailableInterface(struct NegotiateMessage *msg, enum WifiDirectRole myRole)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    if (ret != SOFTBUS_OK) {
        return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId));

    ListNode *linkList = &GetLinkManager()->linkLists[WIFI_DIRECT_LINK_TYPE_P2P];
    struct InnerLink *link = NULL;
    LIST_FOR_EACH_ENTRY(link, linkList, struct InnerLink, node) {
        char *remoteDeviceIdOfLink = link->getString(link, IL_KEY_DEVICE_ID, "");
        if (strlen(remoteDeviceIdOfLink) == 0 || strcmp(remoteDeviceId, remoteDeviceIdOfLink) != 0) {
            continue;
        }

        GetLinkManager()->dump(0);
        CONN_LOGI(CONN_WIFI_DIRECT, "fix the obsolete link");
        if (myRole == WIFI_DIRECT_ROLE_GC) {
            (void)DestroyGroup();
            GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP;
            return ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED;
        }
    }

    return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
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

    ListNode *p2pList = &GetLinkManager()->linkLists[WIFI_DIRECT_LINK_TYPE_P2P];
    if (IsListEmpty(p2pList)) {
        return "";
    }
    struct InnerLink *link = LIST_ENTRY(GET_LIST_HEAD(p2pList), struct InnerLink, node);
    return link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
}

static bool IsNeedReversal(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char localMac[MAC_ADDR_STR_LEN] = {0};
    char remoteMac[MAC_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->getMacAddress(localMac, sizeof(localMac));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get local mac failed");
    ret = channel->getP2pMac(channel, remoteMac, sizeof(remoteMac));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get remote mac failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "localMac=%{public}s, remoteMac=%{public}s",
          WifiDirectAnonymizeMac(localMac), WifiDirectAnonymizeMac(remoteMac));
    return GetWifiDirectUtils()->strCompareIgnoreCase(localMac, remoteMac) < 0;
}

static int32_t ProcessConflictRequest(struct WifiDirectCommand *command)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = command->msg;
    if (!IsNeedReversal(msg)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "no need reversal, ignore remote request");
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        struct NegotiateMessage *response = BuildNegotiateResult(V1_ERROR_BUSY, channel);
        if (response) {
            GetWifiDirectNegotiator()->postData(response);
            NegotiateMessageDelete(response);
        }
        self->passiveCommand->destructor(self->passiveCommand);
        self->passiveCommand = NULL;
        CONN_LOGI(CONN_WIFI_DIRECT, "passiveCommand=NULL");
        return SOFTBUS_OK;
    }

    StopTimer();
    CONN_LOGI(CONN_WIFI_DIRECT, "need reversal, process remote request and retry local command");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    enum WifiDirectApiRole myApiRole =
        (enum WifiDirectApiRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    if (myApiRole == WIFI_DIRECT_API_ROLE_GO) {
        CONN_LOGI(CONN_WIFI_DIRECT, "decrease reuseCount and stop new client timer");
        char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
        RemoveLink(remoteMac);
        CancelNewClient(IF_NAME_P2P, remoteMac);
    }

    GetWifiDirectNegotiator()->retryCurrentCommand();
    self->activeCommand = NULL;
    CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=NULL");
    self->currentState = P2P_V1_PROCESSOR_STATE_AVAILABLE;
    return SOFTBUS_ERR;
}

static int32_t ProcessConnectRequest(struct WifiDirectCommand *command)
{
    enum P2pV1ProcessorState currentState = GetP2pV1Processor()->currentState;
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (currentState == P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE) {
        if (ProcessConflictRequest(command) == SOFTBUS_OK) {
            return SOFTBUS_OK;
        }
    }

    enum WifiDirectRole myRole;
    enum WifiDirectRole peerRole;
    enum WifiDirectRole expectRole;
    struct NegotiateMessage *msg = command->msg;
    int32_t ret = GetRoleInfo(msg, &myRole, &peerRole, &expectRole);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get role info failed");

    if (myRole == WIFI_DIRECT_ROLE_NONE && !GetResourceManager()->isInterfaceAvailable(IF_NAME_P2P, false)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "V1_ERROR_IF_NOT_AVAILABLE");
        return V1_ERROR_IF_NOT_AVAILABLE;
    }

    char *remoteConfig = msg->getString(msg, NM_KEY_SELF_WIFI_CONFIG, "");
    if (strlen(remoteConfig) != 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteConfigSize=%{public}zu", strlen(remoteConfig));
        ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "set wifi cfg failed");
    }

    char *localGoMac = GetGoMac(myRole);
    char *remoteGoMac = msg->getString(msg, NM_KEY_GO_MAC, "");
    enum WifiDirectRole finalRole = GetRoleNegotiator()->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectRole,
                                                                                          localGoMac, remoteGoMac);
    CONN_LOGI(CONN_WIFI_DIRECT, "finalRole=%{public}d", finalRole);
    if (finalRole == WIFI_DIRECT_ROLE_GO) {
        return ProcessConnectRequestAsGo(msg, myRole);
    } else if (finalRole == WIFI_DIRECT_ROLE_GC) {
        return ProcessConnectRequestAsGc(msg, myRole);
    } else if ((int32_t)finalRole == ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE) {
        return ProcessNoAvailableInterface(msg, myRole);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "finalRole invalid");
    return finalRole;
}

static int32_t ProcessConnectResponseAsGo(struct NegotiateMessage *msg)
{
    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, -1);
    if (contentType != P2P_CONTENT_TYPE_RESULT) {
        CONN_LOGE(CONN_WIFI_DIRECT, "content type not equal result type");
        return ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG;
    }

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac));

    enum WifiDirectErrorCode result = ErrorCodeFromV1ProtocolCode(msg->getInt(msg, NM_KEY_RESULT, -1));
    if (result != OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "peer response error. result=%{public}d", result);
        RemoveLink(remoteMac);
        return result;
    }
    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, remoteMac);
    link.setState(&link, INNER_LINK_STATE_CONNECTED);
    link.putRemoteIpString(&link, msg->getString(msg, NM_KEY_IP, ""));
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);

    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_LINK_TYPE_P2P, remoteMac);
    ProcessSuccess(innerLink, false);
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseWithGoInfoAsNone(struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(self->currentInnerLink != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "current inner link is null");
    int32_t ret = ConnectGroup(msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, V1_ERROR_CONNECT_GROUP_FAILED, CONN_WIFI_DIRECT,
        "connect group failed");

    char *localIp = msg->getString(msg, NM_KEY_GC_IP, "");
    char *remoteIp = msg->getString(msg, NM_KEY_IP, "");
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *groupConfigCopy = strdup(groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(groupConfigCopy, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "dup group config failed");
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX] = {0};
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    ret = GetWifiDirectNetWorkUtils()->splitString(groupConfigCopy, "\n", configs, &configsSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(groupConfigCopy);
        CONN_LOGW(CONN_WIFI_DIRECT, "split group config failed");
        return SOFTBUS_ERR;
    }

    struct InnerLink *link = self->currentInnerLink;
    link->putRemoteIpString(link, remoteIp);
    link->putLocalIpString(link, localIp);
    link->putString(link, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    link->putInt(link, IL_KEY_FREQUENCY, atoi(configs[P2P_GROUP_CONFIG_INDEX_FREQ]));
    GetLinkManager()->notifyLinkChange(link);
    InnerLinkDelete(link);
    self->currentInnerLink = NULL;

    self->currentState = P2P_V1_PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    SoftBusFree(groupConfigCopy);
    CONN_LOGI(CONN_WIFI_DIRECT, "waiting connect group to be done");
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseWithGcInfoAsNone(struct NegotiateMessage *msg)
{
    int32_t ret = CreateGroup(msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "create group failed");
    GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_CREATE_GROUP;
    return SOFTBUS_OK;
}

static int32_t ProcessConnectResponseAsNone(struct NegotiateMessage *msg)
{
    char *remoteConfig = msg->getString(msg, NM_KEY_SELF_WIFI_CONFIG, "");
    if (strlen(remoteConfig) != 0) {
        int32_t ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "set wifi cfg failed");
    }

    enum WifiDirectP2pContentType contentType = msg->getInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_INVALID);
    if (contentType == P2P_CONTENT_TYPE_GO_INFO) {
        return ProcessConnectResponseWithGoInfoAsNone(msg);
    }

    if (contentType == P2P_CONTENT_TYPE_GC_INFO) {
        return ProcessConnectResponseWithGcInfoAsNone(msg);
    }

    enum WifiDirectErrorCode errorCode = ErrorCodeFromV1ProtocolCode(msg->getInt(msg, NM_KEY_RESULT, -1));
    CONN_LOGI(CONN_WIFI_DIRECT, "errorCode=%{public}d", errorCode);
    if (errorCode == OK) {
        ProcessSuccess(NULL, false);
    }
    return errorCode;
}

static int32_t ProcessConnectResponse(struct WifiDirectCommand *command)
{
    StopTimer();
    struct NegotiateMessage *msg = command->msg;
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    enum WifiDirectRole myRole = GetWifiDirectUtils()->transferModeToRole(
        info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", myRole);
    if (myRole == WIFI_DIRECT_ROLE_GO) {
        return ProcessConnectResponseAsGo(msg);
    } else if (myRole == WIFI_DIRECT_ROLE_NONE) {
        return ProcessConnectResponseAsNone(msg);
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "myRole invalid");
    return V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE;
}

static int32_t ProcessDisconnectRequest(struct WifiDirectCommand *command)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    int32_t reuseCountOld = info->getInt(info, II_KEY_REUSE_COUNT, 0);
    if (reuseCountOld <= 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCountOld already 0, do not call RemoveLink");
        command->onSuccess(command, NULL);
        return SOFTBUS_OK;
    }

    struct NegotiateMessage *msg = command->msg;
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    int32_t ret = RemoveLink(remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ERROR_REMOVE_LINK_FAILED, CONN_WIFI_DIRECT, "remove link failed");

    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, 0);
    if (reuseCount > 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", reuseCount);
        command->onSuccess(command, NULL);
        return SOFTBUS_OK;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "wait removing group to be done");
    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_LINK_TYPE_P2P, remoteMac);
    if (innerLink != NULL) {
        innerLink->setState(innerLink, INNER_LINK_STATE_DISCONNECTING);
        CONN_LOGI(CONN_WIFI_DIRECT, "set innerLink state to disconnecting");
    }
    GetP2pV1Processor()->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    return SOFTBUS_OK;
}

static int32_t ProcessReuseRequest(struct WifiDirectCommand *command)
{
    int32_t result = V1_ERROR_REUSE_FAILED;
    struct NegotiateMessage *response = NULL;
    struct NegotiateMessage *msg = command->msg;
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    if (channel == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "channel is null");
        goto Failed;
    }
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (info == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "interface info is null");
        goto Failed;
    }
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    struct InnerLink *oldLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_LINK_TYPE_P2P, remoteMac);
    if (oldLink == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "link is null");
        goto Failed;
    }
    if (ReuseP2p() != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "V1_ERROR_REUSE_FAILED");
        goto Failed;
    }

    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, remoteMac);
    link.putBoolean(&link, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    GetLinkManager()->notifyLinkChange(&link);
    InnerLinkDestructor(&link);
    result = OK;

Failed:
    response = BuildReuseResponse(result, channel);
    result = GetWifiDirectNegotiator()->handleMessageFromProcessor(response);
    NegotiateMessageDelete(response);
    if (result == OK) {
        command->onSuccess(command, NULL);
    } else {
        command->onFailure(command, result);
    }
    return result;
}

static int32_t ProcessReuseResponse(struct WifiDirectCommand *command)
{
    struct NegotiateMessage *msg = command->msg;
    int32_t result = ErrorCodeFromV1ProtocolCode(msg->getInt(msg, NM_KEY_RESULT, SOFTBUS_ERR));
    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");

    CONN_LOGI(CONN_WIFI_DIRECT,
        "result=%{public}d, remoteMac=%{public}s", result, WifiDirectAnonymizeMac(remoteMac));
    CONN_CHECK_AND_RETURN_RET_LOGW(result == OK, result, CONN_WIFI_DIRECT,
        "remote response failed. result=%{public}d", result);

    int32_t res = ReuseP2p();
    if (res != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "local reuse failed, send disconnect to remote for decreasing reference");
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        struct NegotiateMessage *request = BuildDisconnectRequest(remoteMac, channel);
        GetWifiDirectNegotiator()->postData(request);
        return SOFTBUS_OK;
    }

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "local interface info is null");

    struct InnerLink innerLink;
    InnerLinkConstructorWithArgs(&innerLink, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, remoteMac);
    innerLink.putBoolean(&innerLink, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    GetLinkManager()->notifyLinkChange(&innerLink);
    InnerLinkDestructor(&innerLink);

    struct InnerLink *newInnerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_LINK_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(newInnerLink, SOFTBUS_ERR, CONN_WIFI_DIRECT, "inner link is null");
    ProcessSuccess(newInnerLink, false);
    return SOFTBUS_OK;
}

static int32_t ProcessGetInterfaceInfoRequest(struct NegotiateMessage *msg)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(msg->getString(msg, NM_KEY_INTERFACE_NAME, ""));
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    if (ret == SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local ip is not empty, send response");
        struct NegotiateMessage *response = BuildInterfaceInfoResponse(msg);
        CONN_CHECK_AND_RETURN_RET_LOGW(response, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build interface info response failed");
        ret = GetWifiDirectNegotiator()->postData(response);
        NegotiateMessageDelete(response);
        if (self->pendingRequestMsg != NULL) {
            NegotiateMessageDelete(self->pendingRequestMsg);
            self->pendingRequestMsg = NULL;
        }
        CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "post data failed");
        ProcessSuccess(NULL, false);
        return ret;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "local ip is empty, wait local ip ready");
    struct NegotiateMessage *request = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_RET_LOGE(request, SOFTBUS_OK, CONN_WIFI_DIRECT, "new request message failed");
    request->deepCopy(request, msg);
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");
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
        CONN_LOGI(CONN_WIFI_DIRECT, "already has started listening, port=%{public}d", port);
        return;
    }

    ListenerModule module = 0;
    port = StartListeningForDefaultChannel(AUTH_LINK_TYPE_P2P, localIp, 0, &module);
    info->putInt(info, II_KEY_PORT, port);
}

static void SendHandShakeToGoAsync(void *data)
{
    struct WifiDirectNegotiateChannel *channel = data;
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    char localIp[IP_ADDR_STR_LEN] = {0};
    interfaceInfo->getIpString(interfaceInfo, localIp, sizeof(localIp));
    char *localMac = interfaceInfo->getString(interfaceInfo, II_KEY_BASE_MAC, "");

    CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s, localMac=%{public}s", WifiDirectAnonymizeIp(localIp),
        WifiDirectAnonymizeMac(localMac));
    struct NegotiateMessage handShakeInfo;
    NegotiateMessageConstructor(&handShakeInfo);
    handShakeInfo.putInt(&handShakeInfo, NM_KEY_COMMAND_TYPE, CMD_CTRL_CHL_HANDSHAKE);
    handShakeInfo.putString(&handShakeInfo, NM_KEY_MAC, localMac);
    handShakeInfo.putString(&handShakeInfo, NM_KEY_IP, localIp);
    handShakeInfo.putPointer(&handShakeInfo, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    GetWifiDirectNegotiator()->postData(&handShakeInfo);
    NegotiateMessageDestructor(&handShakeInfo);

    GetLinkManager()->setNegotiateChannelForLink((struct WifiDirectNegotiateChannel*)channel,
                                                 WIFI_DIRECT_LINK_TYPE_P2P);
    channel->destructor(channel);
}

static void OnAuthConnectSuccess(uint32_t authRequestId, int64_t p2pAuthId)
{
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(p2pAuthId);
    CONN_CHECK_AND_RETURN_LOGW(channel, CONN_WIFI_DIRECT, "new channel failed");

    if (CallMethodAsync(SendHandShakeToGoAsync, channel, 0) != SOFTBUS_OK) {
        DefaultNegotiateChannelDelete(channel);
        return;
    }
}

static void OnAuthConnectFailure(uint32_t authRequestId, int32_t reason)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "authRequestId=%{public}u, reason=%{public}d", authRequestId, reason);
}

static void OpenAuthConnection(struct WifiDirectNegotiateChannel *channel, struct InnerLink *link, int32_t remotePort)
{
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = link->getRemoteIpString(link, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get remote ip failed");
    char *remoteMac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
    char *remoteUuid = link->getString(link, IL_KEY_DEVICE_ID, "");
    CONN_LOGI(CONN_WIFI_DIRECT,
        "remoteMac=%{public}s, remoteUuid=%{public}s, remoteIp=%{public}s, remotePort=%{public}d",
        WifiDirectAnonymizeMac(remoteMac), WifiDirectAnonymizeDeviceId(remoteUuid),
        WifiDirectAnonymizeIp(remoteIp), remotePort);

    struct DefaultNegoChannelParam param = {
        .type = AUTH_LINK_TYPE_P2P,
        .remoteUuid = remoteUuid,
        .remoteIp = remoteIp,
        .remotePort = remotePort,
    };
    struct DefaultNegoChannelOpenCallback callback = {
        .onConnectSuccess = OnAuthConnectSuccess,
        .onConnectFailure = OnAuthConnectFailure,
    };
    ret = OpenDefaultNegotiateChannel(&param, channel, &callback);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "open p2p auth failed");
}

static void UpdateInnerLinkOnCreateGroupComplete(const char *localMac, const char *localIp,
                                                 const char *remoteMac, const char *remoteIp)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct InnerLink link;
    InnerLinkConstructor(&link);
    InitBasicInnerLink(&link);
    SetInnerLinkDeviceId(self->passiveCommand->msg, &link);

    link.putLocalIpString(&link, localIp);
    link.putRemoteIpString(&link, remoteIp);
    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putString(&link, IL_KEY_REMOTE_BASE_MAC, remoteMac);
    GetLinkManager()->notifyLinkChange(&link);

    InnerLinkDestructor(&link);
}

static int32_t OnCreateGroupComplete(int32_t event)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CREATE_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CONN_CHECK_AND_RETURN_RET_LOGW(event == ENTITY_EVENT_P2P_CREATE_COMPLETE, V1_ERROR_CREATE_GROUP_FAILED,
                                  CONN_WIFI_DIRECT, "create group failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "create group done, timeUsed=%{public}" PRIu64 "MS",
        GetWifiDirectPerfRecorder()->getTime(TC_CREATE_GROUP));

    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = self->passiveCommand->msg;
    CONN_CHECK_AND_RETURN_RET_LOGW(msg, SOFTBUS_ERR, CONN_WIFI_DIRECT, "current msg is null");

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char remoteIp[IP_ADDR_STR_LEN];
    int32_t ret = GetWifiDirectP2pAdapter()->requestGcIp(remoteMac, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "apply gc ip failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");

    char localIp[IP_ADDR_STR_LEN];
    ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get local ip failed");

    UpdateReuseCount(1);
    UpdateInnerLinkOnCreateGroupComplete(localMac, localIp, remoteMac, remoteIp);
    NotifyNewClient(IF_NAME_P2P, remoteMac);
    StartAuthListening(localIp);

    struct NegotiateMessage *output = NULL;
    if (self->activeCommand == NULL) {
        output = BuildConnectResponseAsGo(remoteMac, remoteIp, channel);
        CONN_CHECK_AND_RETURN_RET_LOGW(output, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build response with go info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(output);
        ProcessSuccess(NULL, false);
    } else {
        output = BuildConnectRequestAsGo(remoteMac, remoteIp, channel);
        CONN_CHECK_AND_RETURN_RET_LOGW(output, SOFTBUS_ERR, CONN_WIFI_DIRECT, "build request with go info failed");
        GetWifiDirectNegotiator()->handleMessageFromProcessor(output);
        StartTimer(P2P_V1_WAITING_RESPONSE_TIME_MS);
        self->currentState = P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE;
    }

    NegotiateMessageDelete(output);
    return SOFTBUS_OK;
}

static void UpdateInnerLinkOnConnectGroupComplete(const char *localMac, const char *localIp,
                                                  const char *remoteMac, const char *remoteIp)
{
    struct InnerLink link;
    InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, remoteMac);

    link.putString(&link, IL_KEY_LOCAL_BASE_MAC, localMac);
    link.putRemoteIpString(&link, remoteIp);
    link.putLocalIpString(&link, localIp);
    link.setState(&link, INNER_LINK_STATE_CONNECTED);
    GetLinkManager()->notifyLinkChange(&link);

    InnerLinkDestructor(&link);
}

static int32_t OnConnectGroupComplete(int32_t event)
{
    GetWifiDirectPerfRecorder()->record(TP_P2P_CONNECT_GROUP_END);
    GetWifiDirectPerfRecorder()->calculate();
    CONN_CHECK_AND_RETURN_RET_LOGW(event == ENTITY_EVENT_P2P_CONNECT_COMPLETE, V1_ERROR_CONNECT_GROUP_FAILED,
                                   CONN_WIFI_DIRECT, "connect group failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "connect group done, timeUsed=%{public}" PRIu64 "MS",
              GetWifiDirectPerfRecorder()->getTime(TC_CONNECT_GROUP));

    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = self->passiveCommand->msg;
    CONN_CHECK_AND_RETURN_RET_LOGW(msg, SOFTBUS_ERR, CONN_WIFI_DIRECT, "current msg is null");

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "no p2p interface info");
    char *localMac = info->getString(info, II_KEY_BASE_MAC, "");
    info->setP2pGroupConfig(info, msg->getString(msg, NM_KEY_GROUP_CONFIG, ""));

    char localIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = info->getIpString(info, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get local ip failed");

    char *remoteMac = msg->getString(msg, NM_KEY_MAC, "");
    char *remoteIp = msg->getString(msg, NM_KEY_GO_IP, "");

    UpdateReuseCount(1);
    UpdateInnerLinkOnConnectGroupComplete(localMac, localIp, remoteMac, remoteIp);
    channel->setP2pMac(channel, remoteMac);
    StartAuthListening(localIp);

    struct InnerLink *innerLink = GetLinkManager()->getLinkByTypeAndDevice(WIFI_DIRECT_LINK_TYPE_P2P, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(innerLink, SOFTBUS_ERR, CONN_WIFI_DIRECT, "inner link is null");
    OpenAuthConnection(channel, innerLink, self->goPort);

    if (self->activeCommand == NULL) {
        GetWifiDirectNegotiator()->syncLnnInfo(innerLink);
        ProcessSuccess(NULL, true);
        return SOFTBUS_OK;
    }

    ProcessSuccess(innerLink, false);
    if (self->pendingRequestMsg && (ProcessGetInterfaceInfoRequest(self->pendingRequestMsg) != SOFTBUS_OK)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "process get interface info request failed");
    }
    return SOFTBUS_OK;
}

static int32_t OnRemoveGroupComplete(int32_t event)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(event == ENTITY_EVENT_P2P_REMOVE_COMPLETE, ERROR_REMOVE_LINK_FAILED,
                                  CONN_WIFI_DIRECT, "remove group failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "remove group done");
    struct P2pV1Processor *self = GetP2pV1Processor();
    if (self->activeCommand != NULL) {
        ProcessSuccess(NULL, false);
        return SOFTBUS_OK;
    }
    if (self->passiveCommand != NULL) {
        self->passiveCommand->onSuccess(self->passiveCommand, NULL);
    }
    return SOFTBUS_OK;
}

static void UpdateReuseCount(int32_t delta)
{
    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_LOGW(interfaceInfo, CONN_WIFI_DIRECT, "interface info is null");

    int32_t reuseCount = interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, 0);
    if (reuseCount == 0 && delta < 0) {
        CONN_LOGW(CONN_WIFI_DIRECT, "reuseCount already 0 and can not be reduced");
        return;
    }

    interfaceInfo->putInt(interfaceInfo, II_KEY_REUSE_COUNT, reuseCount + delta);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", interfaceInfo->getInt(interfaceInfo, II_KEY_REUSE_COUNT, -1));
}

static void InitBasicInnerLink(struct InnerLink *innerLink)
{
    innerLink->putInt(innerLink, IL_KEY_LINK_TYPE, WIFI_DIRECT_LINK_TYPE_P2P);
    innerLink->putString(innerLink, IL_KEY_LOCAL_INTERFACE, IF_NAME_P2P);
    innerLink->putString(innerLink, IL_KEY_REMOTE_INTERFACE, IF_NAME_P2P);
    innerLink->setState(innerLink, INNER_LINK_STATE_CONNECTING);
}

static void NotifyNewClient(const char *localInterface, const char *remoteMac)
{
    struct WifiDirectConnectParams params;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), localInterface);
    CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_WIFI_DIRECT, "copy local interface failed");
    ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);
    CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_WIFI_DIRECT, "copy remote mac failed");

    GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->notifyNewClientJoining(&params);
}

static void CancelNewClient(const char *localInterface, const char *remoteMac)
{
    struct WifiDirectConnectParams params;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), localInterface);
    CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_WIFI_DIRECT, "copy local interface failed");
    ret = strcpy_s(params.remoteMac, sizeof(params.remoteMac), remoteMac);
    CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_WIFI_DIRECT, "copy remote mac failed");

    GetWifiDirectEntityFactory()->createEntity(ENTITY_TYPE_P2P)->cancelNewClientJoining(&params);
}

static int32_t PickIntersectionFrequency(int32_t *gcChannelArray, size_t gcChannelArraySize,
                                         int32_t *goChannelArray, size_t goChannelArraySize)
{
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();

    for (size_t i = 0; i < goChannelArraySize; i++) {
        if (netWorkUtils->isInChannelList(goChannelArray[i], gcChannelArray, gcChannelArraySize)) {
            return netWorkUtils->channelToFrequency(goChannelArray[i]);
        }
    }

    return FREQUENCY_INVALID;
}

static int32_t ChoseFrequency(int32_t gcFreq, int32_t *gcChannelArray, size_t gcChannelArraySize)
{
    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t goFreq = adapter->getStationFrequencyWithFilter();

    CONN_LOGI(CONN_WIFI_DIRECT, "goFreq=%{public}d, gcFreq=%{public}d", goFreq, gcFreq);
    if (goFreq != CHANNEL_INVALID || gcFreq != CHANNEL_INVALID) {
        int32_t recommendChannel = adapter->getRecommendChannel();
        if (recommendChannel != CHANNEL_INVALID) {
            CONN_LOGI(CONN_WIFI_DIRECT, "recommendChannel=%{public}d", recommendChannel);
            return netWorkUtils->channelToFrequency(recommendChannel);
        }
    }

    int32_t goChannelArray[CHANNEL_ARRAY_NUM_MAX];
    size_t goChannelArraySize = CHANNEL_ARRAY_NUM_MAX;
    int32_t ret = adapter->getChannel5GListIntArray(goChannelArray, &goChannelArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get local channel list failed");

    int32_t intersectionFreq = PickIntersectionFrequency(gcChannelArray, gcChannelArraySize,
                                                         goChannelArray, goChannelArraySize);
    if (intersectionFreq != FREQUENCY_INVALID) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use intersectionFreq=%{public}d", intersectionFreq);
        return intersectionFreq;
    }

    if (netWorkUtils->is2GBand(goFreq)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use goFreq=%{public}d", goFreq);
        return goFreq;
    }
    if (netWorkUtils->is2GBand(gcFreq)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use gcFreq=%{public}d", gcFreq);
        return gcFreq;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "use 2G_FIRST=%{public}d", FREQUENCY_2G_FIRST);
    return FREQUENCY_2G_FIRST;
}

static void SetInnerLinkDeviceId(struct NegotiateMessage *msg, struct InnerLink *innerLink)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_LOGW(channel, CONN_WIFI_DIRECT, "channel is null");

    char deviceId[UUID_BUF_LEN] = {0};
    channel->getDeviceId(channel, deviceId, sizeof(deviceId));
    CONN_LOGI(CONN_WIFI_DIRECT, "deviceId=%{public}s", WifiDirectAnonymizeDeviceId(deviceId));
    innerLink->putString(innerLink, IL_KEY_DEVICE_ID, deviceId);
}

static bool IsNeedDhcp(const char *gcIp, struct NegotiateMessage *msg)
{
    if (strlen(gcIp) == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "gcIp is empty, DHCP is true");
        return true;
    }
    char *groupConfig = msg->getString(msg, NM_KEY_GROUP_CONFIG, "");
    char *groupConfigCopy = strdup(groupConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(groupConfigCopy, false, CONN_WIFI_DIRECT, "dup group config failed");

    char *configs[P2P_GROUP_CONFIG_INDEX_MAX] = {0};
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    int32_t ret = GetWifiDirectNetWorkUtils()->splitString(groupConfigCopy, "\n", configs, &configsSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "split group config failed");

    if (configsSize == P2P_GROUP_CONFIG_INDEX_MAX && strcmp(configs[P2P_GROUP_CONFIG_INDEX_MODE], "1") == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "DHCP is true");
        SoftBusFree(groupConfigCopy);
        return true;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "DHCP is false");
    SoftBusFree(groupConfigCopy);
    return false;
}

static enum WifiDirectRole TransferExpectedRole(uint32_t expectApiRole)
{
    expectApiRole &= ~(WIFI_DIRECT_API_ROLE_HML);
    switch (expectApiRole) {
        case WIFI_DIRECT_API_ROLE_GC:
            return WIFI_DIRECT_ROLE_GC;
        case WIFI_DIRECT_API_ROLE_GO:
            return WIFI_DIRECT_ROLE_GO;
        case WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO:
            return WIFI_DIRECT_ROLE_AUTO;
        default:
            CONN_LOGW(CONN_WIFI_DIRECT, "invalid api role. expectApiRole=0x%{public}x", expectApiRole);
            return WIFI_DIRECT_ROLE_INVALID;
    }
}

static void OnTimeOut(void *data)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    self->timerId = TIMER_ID_INVALID;

    CONN_LOGI(CONN_WIFI_DIRECT, "currentState=%{public}d", self->currentState);
    if (self->currentState == P2P_V1_PROCESSOR_STATE_WAITING_REQ_RESPONSE) {
        CONN_LOGI(CONN_WIFI_DIRECT, "wait connect response timeout");
        ProcessFailure(ERROR_WIFI_DIRECT_WAIT_CONNECT_RESPONSE_TIMEOUT, false);
    } else if (self->currentState == P2P_V1_PROCESSOR_STATE_WAITING_REUSE_RESPONSE) {
        CONN_LOGI(CONN_WIFI_DIRECT, "wait reuse response timeout");
        ProcessFailure(ERROR_WIFI_DIRECT_WAIT_CONNECT_REQUEST_TIMEOUT, false);
    } else if (self->currentState == P2P_V1_PROCESSOR_STATE_WAITING_REQUEST) {
        CONN_LOGI(CONN_WIFI_DIRECT, "wait connect request timeout");
        ProcessFailure(ERROR_WIFI_DIRECT_WAIT_CONNECT_REQUEST_TIMEOUT, false);
    }
}

static void StartTimer(int32_t timeMs)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    self->timerId = GetWifiDirectTimerList()->startTimer(OnTimeOut, timeMs, TIMER_FLAG_ONE_SHOOT, NULL);
}

static void StopTimer(void)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    if (self->timerId >= 0) {
        GetWifiDirectTimerList()->stopTimer(self->timerId);
        self->timerId = TIMER_ID_INVALID;
    }
}

static void ProcessFailure(int32_t errorCode, bool reply)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    CONN_LOGI(CONN_WIFI_DIRECT, "errorCode=%{public}d", errorCode);
    if (self->activeCommand != NULL) {
        self->activeCommand->onFailure(self->activeCommand, errorCode);
        return;
    }

    if (self->passiveCommand != NULL) {
        if (reply) {
            struct NegotiateMessage *msg = self->passiveCommand->msg;
            struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
            CONN_CHECK_AND_RETURN_LOGW(channel != NULL, CONN_WIFI_DIRECT, "channel is null");

            struct NegotiateMessage *response = BuildNegotiateResult(errorCode, channel);
            CONN_CHECK_AND_RETURN_LOGW(response != NULL, CONN_WIFI_DIRECT, "build connect response failed");
            GetWifiDirectNegotiator()->handleMessageFromProcessor(response);
            NegotiateMessageDelete(response);
        }
        self->passiveCommand->onFailure(self->passiveCommand, errorCode);
    }
}

static void ProcessSuccess(struct InnerLink *innerLink, bool reply)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    if (self->activeCommand != NULL) {
        if (innerLink != NULL) {
            struct NegotiateMessage output;
            NegotiateMessageConstructor(&output);
            output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)innerLink, sizeof(*innerLink));
            self->activeCommand->onSuccess(self->activeCommand, &output);
            NegotiateMessageDestructor(&output);
            return;
        }

        self->activeCommand->onSuccess(self->activeCommand, NULL);
        return;
    }

    if (self->passiveCommand != NULL) {
        if (reply) {
            struct NegotiateMessage *msg = self->passiveCommand->msg;
            struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
            CONN_CHECK_AND_RETURN_LOGW(channel != NULL, CONN_WIFI_DIRECT, "channel is null");

            struct NegotiateMessage *response = BuildNegotiateResult(OK, channel);
            CONN_CHECK_AND_RETURN_LOGW(response != NULL, CONN_WIFI_DIRECT, "build connect response failed");
            GetWifiDirectNegotiator()->handleMessageFromProcessor(response);
            NegotiateMessageDelete(response);
        }
        self->passiveCommand->onSuccess(self->passiveCommand, NULL);
    }
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (!info->getBoolean(info, II_KEY_IS_ENABLE, false)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "IS_ENABLE=0. IF_NAME_P2P=%{public}s", IF_NAME_P2P);
        return V1_ERROR_IF_NOT_AVAILABLE;
    }
    if (info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE) == WIFI_DIRECT_API_ROLE_GC) {
        CONN_LOGE(CONN_WIFI_DIRECT, "already gc");
        return V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE;
    }
    return SOFTBUS_OK;
}

static struct P2pV1Processor g_processor = {
    .createLink = CreateLink,
    .disconnectLink = DisconnectLink,
    .reuseLink = ReuseLink,
    .processNegotiateMessage = ProcessNegotiateMessage,
    .onOperationEvent = OnOperationEvent,
    .resetContext = ResetContext,
    .isMessageNeedPending = IsMessageNeedPending,
    .prejudgeAvailability = PrejudgeAvailability,

    .name = "P2pV1Processor",
    .timerId = TIMER_ID_INVALID,
    .currentState = P2P_V1_PROCESSOR_STATE_AVAILABLE,
    .currentInnerLink = NULL,
    .pendingRequestMsg = NULL,
};

/* static class method */
struct P2pV1Processor* GetP2pV1Processor(void)
{
    return &g_processor;
}
