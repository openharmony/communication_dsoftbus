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

#include "fast_connect_bcast_channel.h"
#include "softbus_adapter_mem.h"
#include "softbus_log.h"
#include "softbus_error_code.h"

#define LOG_LABEL "[WifiDirect] FastBcastChannel: "

static int32_t PostData(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size)
{
    (void)base;
    (void)data;
    (void)size;
    CLOGE(LOG_LABEL "not supported yet");
    return SOFTBUS_ERR;
}

static bool IsRemoteTlvSupported(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    CLOGE(LOG_LABEL "not supported yet");
    return false;
}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    (void)base;
    (void)deviceId;
    (void)deviceIdSize;
    CLOGE(LOG_LABEL "not supported yet");
    return SOFTBUS_ERR;
}

static int32_t GetP2pMac(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize)
{
    CLOGE(LOG_LABEL "not supported yet");
    (void)base;
    (void)p2pMac;
    (void)p2pMacSize;
    return SOFTBUS_ERR;
}

static void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    (void)base;
    (void)p2pMac;
}

static bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    return true;
}

static struct WifiDirectNegotiateChannel *Duplicate(struct WifiDirectNegotiateChannel *base)
{
    CLOGE(LOG_LABEL "not supported yet");
    (void)base;
    return NULL;
}

static void Destructor(struct WifiDirectNegotiateChannel *base)
{
    CLOGE(LOG_LABEL "not supported yet");
    (void)base;
}

void FastConnectBcastChannelConstructor(struct FastConnectBcastChannel *self, const char *networkId)
{
    (void)networkId;
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));

    self->postData = PostData;
    self->getDeviceId = GetDeviceId;
    self->isRemoteTlvSupported = IsRemoteTlvSupported;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->duplicate = Duplicate;
    self->destructor = Destructor;

    self->tlvFeature = false;
}

void FastConnectBcastChannelDestructor(struct FastConnectBcastChannel *self)
{
    (void)self;
}

struct FastConnectBcastChannel *FastConnectBcastChannelNew(const char *networkId)
{
    struct FastConnectBcastChannel *self = SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOG(self, NULL, LOG_LABEL "malloc failed");
    FastConnectBcastChannelConstructor(self, networkId);
    return self;
}

void FastConnectBcastChannelDelete(struct FastConnectBcastChannel *self)
{
    FastConnectBcastChannelDestructor(self);
    SoftBusFree(self);
}