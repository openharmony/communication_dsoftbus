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
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_decision_center.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/negotiate_message.h"
#include "data/inner_link.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"

#define LOG_LABEL "[WD] ConCmd: "

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
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "get remote uuid failed");
    struct InnerLink *link = GetLinkManager()->getLinkByUuid(remoteUuid);
    CONN_CHECK_AND_RETURN_RET_LOG(link, SOFTBUS_ERR, LOG_LABEL "link is null");
    enum InnerLinkState state = link->getInt(link, IL_KEY_STATE, INNER_LINK_STATE_DISCONNECTED);
    CONN_CHECK_AND_RETURN_RET_LOG(state == INNER_LINK_STATE_CONNECTED, SOFTBUS_ERR, LOG_LABEL "link is not connected");

    struct WifiDirectIpv4Info *ipv4 = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(ipv4, SOFTBUS_ERR, LOG_LABEL "ipv4 is null");

    bool isBeingUsedByLocal = link->getBoolean(link, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    CLOGI(LOG_LABEL "isBeingUsedByLocal=%d", isBeingUsedByLocal);

    if (isBeingUsedByLocal) {
        CLOGI(LOG_LABEL "reuse success");
        struct NegotiateMessage output;
        NegotiateMessageConstructor(&output);
        output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)link, sizeof(*link));
        command->onSuccess((struct WifiDirectCommand *)command, &output);
        NegotiateMessageDestructor(&output);
        return SOFTBUS_OK;
    }

    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_HML);
    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannelAndConnectType(connectInfo->negoChannel, connectType);

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    GetWifiDirectNegotiator()->currentProcessor = processor;

    return processor->reuseLink(connectInfo, link);
}

static int32_t OpenLink(struct WifiDirectConnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;

    CLOGI(LOG_LABEL "try reuse link");
    if (ReuseLink(command) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }

    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannel(connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOG(processor, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, LOG_LABEL "no suitable processor");

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    GetWifiDirectNegotiator()->currentProcessor = processor;

    return processor->createLink(connectInfo);
}

static void ExecuteConnection(struct WifiDirectCommand *base)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    self->times++;
    CLOGI(LOG_LABEL "times=%d", self->times);

    int32_t ret = OpenLink(self);
    if (ret != SOFTBUS_OK) {
        self->onFailure(base, ret);
    }
}

static void OnSuccess(struct WifiDirectCommand *base, struct NegotiateMessage *msg)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    struct InnerLink *innerLink = msg->get(msg, NM_KEY_INNER_LINK, NULL, NULL);
    if (innerLink == NULL) {
        CLOGE(LOG_LABEL " no inner link");
        base->onFailure(base, ERROR_NO_CONTEXT);
        GetWifiDirectNegotiator()->resetContext();
        GetResourceManager()->dump();
        GetLinkManager()->dump();
        return;
    }

    struct WifiDirectLink link;
    (void)memset_s(&link, sizeof(link), 0, sizeof(link));
    int32_t requestId = self->connectInfo.requestId;
    innerLink->getLink(innerLink, requestId, self->connectInfo.pid, &link);
    CLOGI(LOG_LABEL "requestId=%d linkId=%d", requestId, link.linkId);

    if (self->callback.onConnectSuccess != NULL) {
        CLOGI(LOG_LABEL "call onConnectSuccess");
        self->callback.onConnectSuccess(requestId, &link);
    }
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
}

static void OnFailure(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)base;
    CLOGI(LOG_LABEL "requestId=%d reason=%d", self->connectInfo.requestId, reason);

    if (IsNeedRetry(base, reason)) {
        CLOGI(LOG_LABEL "retry command");
        GetWifiDirectNegotiator()->retryCurrentCommand();
        return;
    }

    if (self->callback.onConnectFailure != NULL) {
        CLOGI(LOG_LABEL "call onConnectFailure");
        self->callback.onConnectFailure(self->connectInfo.requestId, reason);
    }

    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
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
    CLOGI(LOG_LABEL);
    struct WifiDirectConnectCommand *self = (struct WifiDirectConnectCommand *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOG(self != NULL, NULL, LOG_LABEL "malloc failed");
    WifiDirectConnectCommandConstructor(self, connectInfo, callback);
    return (struct WifiDirectCommand *)self;
}

void WifiDirectConnectCommandDelete(struct WifiDirectCommand *base)
{
    CLOGI(LOG_LABEL);
    WifiDirectConnectCommandDestructor((struct WifiDirectConnectCommand *)base);
    SoftBusFree(base);
}