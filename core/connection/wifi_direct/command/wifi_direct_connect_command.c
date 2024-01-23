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

#include "wifi_direct_connect_command.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "bus_center_manager.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_decision_center.h"
#include "command/wifi_direct_command_manager.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/negotiate_message.h"
#include "data/inner_link.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "conn_event.h"
#include "wifi_direct_statistic.h"

static bool IsNeedRetry(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    if (self->times > MAX_EXECUTE_TIMES) {
        return false;
    }

    return GetWifiDirectNegotiator()->isRetryErrorCode(reason);
}


static int32_t PreferNegotiateChannelForConnectInfo(struct InnerLink *link, struct WifiDirectConnectInfo *connectInfo)
{
    if (connectInfo->negoChannel != NULL) {
        CONN_LOGD(CONN_WIFI_DIRECT, "prefer input channel");
        return SOFTBUS_OK;
    }
    struct WifiDirectNegotiateChannel *channel = link->getPointer(link, IL_KEY_NEGO_CHANNEL, NULL);
    if (channel != NULL) {
        CONN_LOGD(CONN_WIFI_DIRECT, "prefer inner link channel");
        if (connectInfo->negoChannel != NULL) {
            connectInfo->negoChannel->destructor(connectInfo->negoChannel);
        }
        connectInfo->negoChannel = channel->duplicate(channel);
        CONN_CHECK_AND_RETURN_RET_LOGW(connectInfo->negoChannel != NULL, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT,
                                       "new channel failed");
        return SOFTBUS_OK;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "no channel");
    return ERROR_WRONG_AUTH_CONNECTION_INFO;
}

static enum WifiDirectLinkType GetLinkType(enum WifiDirectConnectType connectType)
{
    switch (connectType) {
        case WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P:
            return WIFI_DIRECT_LINK_TYPE_P2P;
        case WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML:
        case WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML:
        case WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML:
            return WIFI_DIRECT_LINK_TYPE_HML;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "connectType invalid. connectType=%{public}d", connectType);
            return WIFI_DIRECT_LINK_TYPE_INVALID;
    }
}

static struct InnerLink *GetReuseLink(struct WifiDirectConnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;
    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(connectInfo->remoteNetworkId, STRING_KEY_UUID, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, NULL, CONN_WIFI_DIRECT, "get remote uuid failed");

    enum WifiDirectLinkType linkType = GetLinkType(connectInfo->connectType);
    struct InnerLink *link = GetLinkManager()->getLinkByTypeAndUuid(linkType, remoteUuid);
    if (link == NULL) {
        link = GetLinkManager()->getLinkByTypeAndUuid(WIFI_DIRECT_LINK_TYPE_P2P, remoteUuid);
    }
    CONN_CHECK_AND_RETURN_RET_LOGW(link != NULL, NULL, CONN_WIFI_DIRECT, "link is null");
    enum InnerLinkState state = link->getInt(link, IL_KEY_STATE, INNER_LINK_STATE_DISCONNECTED);
    CONN_CHECK_AND_RETURN_RET_LOGW(state == INNER_LINK_STATE_CONNECTED, NULL, CONN_WIFI_DIRECT,
                                   "state not connected. state=%{public}d", state);
    struct WifiDirectIpv4Info *ipv4 = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(ipv4 != NULL, NULL, CONN_WIFI_DIRECT, "ipv4 is null");
    return link;
}

static int32_t ReuseLink(struct WifiDirectConnectCommand *command, struct InnerLink *link)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;
    bool isBeingUsedByLocal = link->getBoolean(link, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    CONN_LOGI(CONN_WIFI_DIRECT, "isBeingUsedByLocal=%{public}d", isBeingUsedByLocal);

    if (isBeingUsedByLocal) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuse success");
        struct NegotiateMessage output;
        NegotiateMessageConstructor(&output);
        output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)link, sizeof(*link));
        command->onSuccess((struct WifiDirectCommand *)command, &output);
        NegotiateMessageDestructor(&output);
        return SOFTBUS_OK;
    }

    enum WifiDirectLinkType linkType = link->getInt(link, IL_KEY_LINK_TYPE, WIFI_DIRECT_LINK_TYPE_HML);
    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByChannelAndLinkType(connectInfo->negoChannel, linkType);

    int32_t ret = PreferNegotiateChannelForConnectInfo(link, connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "prefer channel failed");

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    GetWifiDirectNegotiator()->currentProcessor = processor;
    CONN_LOGI(CONN_WIFI_DIRECT,
        "activeCommand=%{public}d, currentProcessor=%{public}s", command->type,  processor->name);

    return processor->reuseLink(connectInfo, link);
}

static void SetWifiDirectStatisticType(struct WifiDirectConnectInfo *connectInfo)
{
    if (connectInfo == NULL || connectInfo->negoChannel == NULL) {
        return;
    }
    if (connectInfo->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P) {
        SetWifiDirectStatisticLinkType(connectInfo->requestId, STATISTIC_P2P);
    } else if (connectInfo->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML) {
        SetWifiDirectStatisticLinkType(connectInfo->requestId, STATISTIC_HML);
    } else if (connectInfo->connectType == WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML) {
        SetWifiDirectStatisticLinkType(connectInfo->requestId, STATISTIC_TRIGGER_HML);
        SetWifiDirectStatisticBootLinkType(connectInfo->requestId, STATISTIC_NONE);
        return;
    } else if (connectInfo->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML) {
        SetWifiDirectStatisticLinkType(connectInfo->requestId, STATISTIC_TRIGGER_HML);
    }
    enum WifiDirectNegotiateChannelType type = connectInfo->negoChannel->getMediumType(connectInfo->negoChannel);
    if (type == NEGOTIATE_WIFI) {
        SetWifiDirectStatisticBootLinkType(connectInfo->requestId, STATISTIC_WLAN);
    } else if (type == NEGOTIATE_BLE) {
        SetWifiDirectStatisticBootLinkType(connectInfo->requestId, STATISTIC_BLE);
    } else if (type == NEGOTIATE_BR) {
        SetWifiDirectStatisticBootLinkType(connectInfo->requestId, STATISTIC_BR);
    }
}

static int32_t OpenLink(struct WifiDirectConnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;
    struct InnerLink *link = GetReuseLink(command);
    if (link != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuse link");
        SetWifiDirectStatisticReuse(connectInfo->requestId);
        return ReuseLink(command, link);
    }

    SetWifiDirectStatisticType(connectInfo);
    struct WifiDirectDecisionCenter *decisionCenter = GetWifiDirectDecisionCenter();
    struct WifiDirectProcessor *processor =
        decisionCenter->getProcessorByChannelAndConnectType(connectInfo->negoChannel, connectInfo->connectType);
    CONN_CHECK_AND_RETURN_RET_LOGW(processor != NULL, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, CONN_WIFI_DIRECT,
                                   "no suitable processor");

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    GetWifiDirectNegotiator()->currentProcessor = processor;
    CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=%{public}d, currentProcessor=%{public}s",
        command->type,  processor->name);

    SetWifiDirectStatisticLinkStartTime(connectInfo->requestId);
    return processor->createLink(connectInfo);
}

static void ExecuteConnection(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    self->times++;
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, times=%{public}d", self->connectInfo.requestId, self->times);

    int32_t ret = OpenLink(self);
    if (ret != SOFTBUS_OK) {
        self->onFailure(base, ret);
    }
}

static void FillConnEventExtra(int32_t requestId, ConnEventExtra *extra)
{
    extra->peerIp = NULL;
    extra->peerBleMac = NULL;
    extra->peerBrMac = NULL;
    extra->peerWifiMac = NULL;
    extra->peerPort = NULL;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->lnnType = NULL;
    enum StatisticLinkType statisticLinkType = STATISTIC_LINK_TYPE_NUM;
    GetWifiDirectStatisticLinkType(requestId, &statisticLinkType);
    if (statisticLinkType == STATISTIC_P2P) {
        extra->linkType = CONNECT_P2P;
    } else if (statisticLinkType == STATISTIC_HML) {
        extra->linkType = CONNECT_HML;
    } else {
        extra->linkType = CONNECT_TRIGGER_HML;
    }
    GetWifiDirectStatisticBootLinkType(requestId, &(extra->bootLinkType));
    GetWifiDirectStatisticRenegotiate(requestId, &(extra->isRenegotiate));
    GetWifiDirectStatisticReuse(requestId, &(extra->isReuse));
    GetWifiDirectStatisticLinkTime(requestId, &(extra->linkTime));
    GetWifiDirectStatisticNegotiateTime(requestId, &(extra->negotiateTime));
    DestroyWifiDirectStatisticElement(requestId);
}

static void OnConnectSuccess(struct WifiDirectCommand *base, struct NegotiateMessage *msg)
{
    struct InnerLink *innerLink = NULL;
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    SetWifiDirectStatisticLinkEndTime(self->connectInfo.requestId);
    if (msg != NULL) {
        innerLink = msg->get(msg, NM_KEY_INNER_LINK, NULL, NULL);
    }
    if (innerLink == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "no inner link");
        base->onFailure(base, ERROR_NO_CONTEXT);
        GetWifiDirectNegotiator()->resetContext();
        GetResourceManager()->dump(0);
        GetLinkManager()->dump(0);
        return;
    }

    struct WifiDirectLink link;
    (void)memset_s(&link, sizeof(link), 0, sizeof(link));
    int32_t requestId = self->connectInfo.requestId;
    innerLink->getLink(innerLink, requestId, self->connectInfo.pid, &link);
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, linkId=%{public}d", requestId, link.linkId);

    if (self->callback.onConnectSuccess != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onConnectSuccess");
        self->callback.onConnectSuccess(requestId, &link);
    }
    ConnEventExtra extra = {
        .requestId = self->connectInfo.requestId,
        .result = EVENT_STAGE_RESULT_OK
    };
    FillConnEventExtra(self->connectInfo.requestId, &extra);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump(0);
    GetLinkManager()->dump(0);
}

static void OnConnectFailure(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    SetWifiDirectStatisticLinkEndTime(self->connectInfo.requestId);
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, reason=%{public}d", self->connectInfo.requestId, reason);

    if (IsNeedRetry(base, reason)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "retry command");
        GetWifiDirectNegotiator()->retryCurrentCommand();
        GetWifiDirectNegotiator()->resetContext();
        return;
    }

    if (self->callback.onConnectFailure != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onConnectFailure");
        self->callback.onConnectFailure(self->connectInfo.requestId, reason);
    }
    ConnEventExtra extra = {
        .requestId = self->connectInfo.requestId,
        .result = EVENT_STAGE_RESULT_FAILED,
        .errcode = reason
    };
    FillConnEventExtra(self->connectInfo.requestId, &extra);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    ConnAlarmExtra extraAlarm = {
        .linkType = CONNECT_P2P,
        .errcode = SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL,
    };
    CONN_ALARM(CONNECTION_FAIL_ALARM, MANAGE_ALARM_TYPE, extraAlarm);
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump(0);
    GetLinkManager()->dump(0);
}

static void OnConnectTimeout(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    if (self->callback.onConnectFailure != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onConnectFailure");
        self->callback.onConnectFailure(self->connectInfo.requestId, ERROR_WIFI_DIRECT_COMMAND_WAIT_TIMEOUT);
    }
}

static struct WifiDirectCommand* Duplicate(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    struct WifiDirectConnectCommand *copy =
        (struct WifiDirectConnectCommand *)WifiDirectConnectCommandNew(&self->connectInfo, &self->callback);
    if (copy != NULL) {
        copy->times = self->times;
        copy->commandId = self->commandId;
    }
    return (struct WifiDirectCommand *)copy;
}

void WifiDirectConnectCommandConstructor(struct WifiDirectConnectCommand *self,
                                         struct WifiDirectConnectInfo *connectInfo,
                                         struct WifiDirectConnectCallback *callback)
{
    self->type = COMMAND_TYPE_CONNECT;
    self->timerId = TIMER_ID_INVALID;
    self->commandId = GetWifiDirectCommandManager()->allocateCommandId();
    self->execute = ExecuteConnection;
    self->onSuccess = OnConnectSuccess;
    self->onFailure = OnConnectFailure;
    self->onTimeout = OnConnectTimeout;
    self->duplicate = Duplicate;
    self->destructor = WifiDirectConnectCommandDelete;
    *(&self->connectInfo) = *connectInfo;
    if (connectInfo->negoChannel != NULL) {
        self->connectInfo.negoChannel = connectInfo->negoChannel->duplicate(connectInfo->negoChannel);
    }
    self->callback = *callback;
}

void WifiDirectConnectCommandDestructor(struct WifiDirectConnectCommand *self)
{
    if (self->connectInfo.negoChannel != NULL) {
        self->connectInfo.negoChannel->destructor(self->connectInfo.negoChannel);
    }
}

struct WifiDirectCommand* WifiDirectConnectCommandNew(struct WifiDirectConnectInfo *connectInfo,
                                                      struct WifiDirectConnectCallback *callback)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "malloc failed");
    WifiDirectConnectCommandConstructor(self, connectInfo, callback);
    return (struct WifiDirectCommand *)self;
}

void WifiDirectConnectCommandDelete(struct WifiDirectCommand *base)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    WifiDirectConnectCommandDestructor((struct WifiDirectConnectCommand *)base);
    SoftBusFree(base);
}