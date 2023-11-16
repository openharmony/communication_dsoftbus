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

#include "wifi_direct_disconnect_command.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_decision_center.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "utils/wifi_direct_anonymous.h"

static int32_t PreferNegotiateChannelForConnectInfo(struct InnerLink *link, struct WifiDirectConnectInfo *connectInfo)
{
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
    if (connectInfo->negoChannel != NULL) {
        CONN_LOGD(CONN_WIFI_DIRECT, "prefer input channel");
        return SOFTBUS_OK;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "no channel");
    return ERROR_WRONG_AUTH_CONNECTION_INFO;
}

static int32_t CloseLink(struct WifiDirectDisconnectCommand *command)
{
    struct WifiDirectConnectInfo *connectInfo = &command->connectInfo;
    struct WifiDirectNegotiator *negotiator = GetWifiDirectNegotiator();

    int32_t ret = strcpy_s(negotiator->currentRemoteMac, sizeof(negotiator->currentRemoteMac), connectInfo->remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy remote mac failed");

    struct InnerLink *link = GetLinkManager()->getLinkById(connectInfo->linkId);
    if (link == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "find inner link by linkId failed");
        link = GetLinkManager()->getLinkByDevice(connectInfo->remoteMac);
        if (link == NULL) {
            CONN_LOGI(CONN_WIFI_DIRECT, "link is already not exist");
            command->onSuccess((struct WifiDirectCommand *)command, NULL);
            return SOFTBUS_OK;
        }
    }

    int32_t reference = link->getReference(link);
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%s reference=%d",
          WifiDirectAnonymizeMac(link->getString(link, IL_KEY_REMOTE_BASE_MAC, "")), reference);
    if (reference > 1) {
        command->onSuccess((struct WifiDirectCommand *)command, NULL);
        return SOFTBUS_OK;
    }

    ret = PreferNegotiateChannelForConnectInfo(link, connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "prefer channel failed");

    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);
    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannelAndConnectType(connectInfo->negoChannel, connectType);
    CONN_CHECK_AND_RETURN_RET_LOGW(processor, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, CONN_WIFI_DIRECT,
        "no suitable processor");

    command->processor = processor;
    processor->activeCommand = (struct WifiDirectCommand *)command;
    negotiator->currentProcessor = processor;

    return processor->disconnectLink(connectInfo, link);
}

static void ExecuteDisconnection(struct WifiDirectCommand *base)
{
    struct WifiDirectDisconnectCommand *self = (struct WifiDirectDisconnectCommand *)base;
    self->times++;
    CONN_LOGI(CONN_WIFI_DIRECT, "times=%d", self->times);

    int32_t ret = CloseLink(self);
    if (ret != SOFTBUS_OK) {
        self->onFailure(base, ret);
    }
}

static void OnSuccess(struct WifiDirectCommand *base, struct NegotiateMessage *msg)
{
    (void)msg;
    struct WifiDirectDisconnectCommand *self = (struct WifiDirectDisconnectCommand *)base;
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%d linkId=%d", self->connectInfo.requestId, self->connectInfo.linkId);
    GetLinkManager()->recycleLinkId(self->connectInfo.linkId, self->connectInfo.remoteMac);

    if (self->callback.onDisconnectSuccess != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onDisconnectSuccess");
        self->callback.onDisconnectSuccess(self->connectInfo.requestId);
    }

    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
}

static void OnFailure(struct WifiDirectCommand *base, int32_t reason)
{
    struct WifiDirectDisconnectCommand *self = (struct WifiDirectDisconnectCommand *)base;
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%d linkId=%d reason=%d", self->connectInfo.requestId,
        self->connectInfo.linkId, reason);
    GetLinkManager()->recycleLinkId(self->connectInfo.linkId, self->connectInfo.remoteMac);

    if (self->callback.onDisconnectFailure != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "call onDisconnectFailure");
        self->callback.onDisconnectFailure(self->connectInfo.requestId, reason);
    }

    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
}

void WifiDirectDisconnectCommandConstructor(struct WifiDirectDisconnectCommand *self,
                                            struct WifiDirectConnectInfo *connectInfo,
                                            struct WifiDirectConnectCallback *callback)
{
    self->type = COMMAND_TYPE_DISCONNECT;
    ListInit(&self->node);
    self->execute = ExecuteDisconnection;
    self->onSuccess = OnSuccess;
    self->onFailure = OnFailure;
    self->deleteSelf = WifiDirectDisconnectCommandDelete;
    *(&self->connectInfo) = *connectInfo;
    if (connectInfo->negoChannel != NULL) {
        self->connectInfo.negoChannel = connectInfo->negoChannel->duplicate(connectInfo->negoChannel);
    }
    self->callback = *callback;
}

void WifiDirectDisconnectCommandDestructor(struct WifiDirectDisconnectCommand *self)
{
    if (self->connectInfo.negoChannel != NULL) {
        self->connectInfo.negoChannel->destructor(self->connectInfo.negoChannel);
    }
}

struct WifiDirectCommand* WifiDirectDisconnectCommandNew(struct WifiDirectConnectInfo *connectInfo,
                                                         struct WifiDirectConnectCallback *callback)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct WifiDirectDisconnectCommand *self = (struct WifiDirectDisconnectCommand *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "malloc failed");
    WifiDirectDisconnectCommandConstructor(self, connectInfo, callback);
    return (struct WifiDirectCommand *)self;
}

void WifiDirectDisconnectCommandDelete(struct WifiDirectCommand *base)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    WifiDirectDisconnectCommandDestructor((struct WifiDirectDisconnectCommand *)base);
    SoftBusFree(base);
}