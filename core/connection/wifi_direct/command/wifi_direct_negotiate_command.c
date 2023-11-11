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
#include "wifi_direct_negotiate_command.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_negotiator.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"

static void ExecuteProcessRemoteNegotiateMessage(struct WifiDirectCommand *base)
{
    struct WifiDirectNegotiateCommand *self = (struct WifiDirectNegotiateCommand *)base;
    GetWifiDirectNegotiator()->currentCommand = base;
    GetWifiDirectNegotiator()->currentProcessor = base->processor;
    base->processor->processNegotiateMessage(self->cmdType, base);
}

static void OnNegotiateComplete(struct WifiDirectCommand *base, struct NegotiateMessage *msg)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    (void)base;
    (void)msg;
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
}

static void OnFailure(struct WifiDirectCommand *base, int32_t reason)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    (void)base;
    (void)reason;
    GetWifiDirectNegotiator()->resetContext();
    GetResourceManager()->dump();
    GetLinkManager()->dump();
}

void WifiDirectNegotiateCommandConstructor(struct WifiDirectNegotiateCommand *self, int32_t cmdType,
                                           struct NegotiateMessage *msg)
{
    self->type = COMMAND_TYPE_MESSAGE;
    ListInit(&self->node);
    self->execute = ExecuteProcessRemoteNegotiateMessage;
    self->onSuccess = OnNegotiateComplete;
    self->onFailure = OnFailure;
    self->deleteSelf = WifiDirectNegotiateCommandDelete;
    self->msg = msg;
    self->cmdType = cmdType;
}

void WifiDirectNegotiateCommandDestructor(struct WifiDirectNegotiateCommand *self)
{
    struct WifiDirectNegotiateChannel *channel = self->msg->getPointer(self->msg, NM_KEY_NEGO_CHANNEL, NULL);
    if (channel != NULL) {
        channel->destructor(channel);
    }
    NegotiateMessageDelete(self->msg);
    self->msg = NULL;
}

struct WifiDirectCommand* WifiDirectNegotiateCommandNew(int32_t cmdType, struct NegotiateMessage *msg)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct WifiDirectNegotiateCommand *self = (struct WifiDirectNegotiateCommand *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "malloc failed");
    WifiDirectNegotiateCommandConstructor(self, cmdType, msg);
    return (struct WifiDirectCommand *)self;
}

void WifiDirectNegotiateCommandDelete(struct WifiDirectCommand *base)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    WifiDirectNegotiateCommandDestructor((struct WifiDirectNegotiateCommand *)base);
    SoftBusFree(base);
}