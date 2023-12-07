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
#include "wifi_direct_negotiator.h"
#include "wifi_direct_decision_center.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/negotiate_message.h"
#include "data/inner_link.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "conn_event.h"

static bool IsNeedRetry(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    if (self->times > MAX_EXECUTE_TIMES) {
        return false;
    }

    return GetWifiDirectNegotiator()->isRetryErrorCode(reason);
}

static int32_t ReuseLink(struct WifiDirectConnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;
    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get remote uuid failed");
    struct InnerLink *link = GetLinkManager()->getLinkByUuid(remoteUuid);
    CONN_CHECK_AND_RETURN_RET_LOGW(link, SOFTBUS_ERR, CONN_WIFI_DIRECT, "link is null");
    enum InnerLinkState state = link->getInt(link, IL_KEY_STATE, INNER_LINK_STATE_DISCONNECTED);
    CONN_CHECK_AND_RETURN_RET_LOGW(state == INNER_LINK_STATE_CONNECTED, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "link is not connected");

    struct WifiDirectIpv4Info *ipv4 = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(ipv4, SOFTBUS_ERR, CONN_WIFI_DIRECT, "ipv4 is null");

    bool isBeingUsedByLocal = link->getBoolean(link, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    CONN_LOGI(CONN_WIFI_DIRECT, "isBeingUsedByLocal=%d", isBeingUsedByLocal);

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
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannelAndLinkType(connectInfo->negoChannel, linkType);

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=%d", command->type);
    GetWifiDirectNegotiator()->currentProcessor = processor;

    return processor->reuseLink(connectInfo, link);
}

static int32_t OpenLink(struct WifiDirectConnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;

    CONN_LOGI(CONN_WIFI_DIRECT, "try reuse link");
    if (ReuseLink(command) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }

    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannel(connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOGW(processor, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, CONN_WIFI_DIRECT,
        "no suitable processor");

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=%d", command->type);
    GetWifiDirectNegotiator()->currentProcessor = processor;

    return processor->createLink(connectInfo);
}

static void ExecuteConnection(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    self->times++;
    CONN_LOGI(CONN_WIFI_DIRECT, "times=%d", self->times);

    int32_t ret = OpenLink(self);
    if (ret != SOFTBUS_OK) {
        self->onFailure(base, ret);
    }
}

static void OnSuccess(struct WifiDirectCommand *base, struct NegotiateMessage *msg)
{
    struct InnerLink *innerLink = NULL;
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
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
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%d linkId=%d", requestId, link.linkId);

    if (self->callback.onConnectSuccess != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onConnectSuccess");
        self->callback.onConnectSuccess(requestId, &link);
    }
    ConnEventExtra extra = {
        .requestId = self->connectInfo.requestId,
        .linkType = CONNECT_P2P,
        .result = EVENT_STAGE_RESULT_OK
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump(0);
    GetLinkManager()->dump(0);
}

static void OnFailure(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%d reason=%d", self->connectInfo.requestId, reason);

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
        .linkType = CONNECT_P2P,
        .result = EVENT_STAGE_RESULT_FAILED,
        .errcode = reason
    };
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

static struct WifiDirectCommand* Duplicate(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    struct WifiDirectConnectCommand *copy =
        (struct WifiDirectConnectCommand *)WifiDirectConnectCommandNew(&self->connectInfo, &self->callback);
    if (copy != NULL) {
        copy->times = self->times;
    }
    return (struct WifiDirectCommand *)copy;
}

void WifiDirectConnectCommandConstructor(struct WifiDirectConnectCommand *self,
                                         struct WifiDirectConnectInfo *connectInfo,
                                         struct WifiDirectConnectCallback *callback)
{
    self->type = COMMAND_TYPE_CONNECT;
    ListInit(&self->node);
    self->execute = ExecuteConnection;
    self->onSuccess = OnSuccess;
    self->onFailure = OnFailure;
    self->duplicate = Duplicate;
    self->deleteSelf = WifiDirectConnectCommandDelete;
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