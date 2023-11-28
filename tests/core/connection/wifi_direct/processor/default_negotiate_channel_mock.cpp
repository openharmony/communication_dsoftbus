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
#include "default_negotiate_channel_mock.h"

#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

static int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return DefaultNegotiateChannelMock::GetMock()->AuthGetDeviceUuid(authId, uuid, size);
}

static int32_t PostData(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size)
{
    (void)base;
    (void)data;
    (void)size;
    return SOFTBUS_OK;
}

static bool IsRemoteTlvSupported(struct WifiDirectNegotiateChannel *base)
{
    struct DefaultNegotiateChannel *channel = (struct DefaultNegotiateChannel *)base;
    return channel->tlvFeature;
}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    return AuthGetDeviceUuid(((struct DefaultNegotiateChannel *)base)->authId, deviceId, deviceIdSize);
}

static int32_t GetP2pMac(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize)
{
    (void)base;
    (void)p2pMac;
    (void)p2pMacSize;
    return SOFTBUS_OK;
}

static void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    (void)base;
    (void)p2pMac;
}

static bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    return false;
}

static bool IsMetaChannel(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    return false;
}

static bool GetTlvFeature(struct DefaultNegotiateChannel *self)
{
    (void)self;
    return false;
}

static struct WifiDirectNegotiateChannel* Duplicate(struct WifiDirectNegotiateChannel *base)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    struct DefaultNegotiateChannel *copy = DefaultNegotiateChannelNew(self->authId);
    return (struct WifiDirectNegotiateChannel*)copy;
}

static void Destructor(struct WifiDirectNegotiateChannel *base)
{
    DefaultNegotiateChannelDelete((struct DefaultNegotiateChannel *)base);
}

void DefaultNegotiateChannelConstructor(struct DefaultNegotiateChannel *self, int64_t authId)
{
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));
    self->authId = authId;

    self->postData = PostData;
    self->getDeviceId = GetDeviceId;
    self->isRemoteTlvSupported = IsRemoteTlvSupported;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->isMetaChannel = IsMetaChannel;
    self->duplicate = Duplicate;
    self->destructor = Destructor;

    self->tlvFeature = GetTlvFeature(self);
}

void DefaultNegotiateChannelDestructor(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

struct DefaultNegotiateChannel* DefaultNegotiateChannelNew(int64_t authId)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)SoftBusCalloc(sizeof(*self));
    if (!self) {
        CONN_LOGE(CONN_WIFI_DIRECT, "malloc failed");
        return nullptr;
    }
    DefaultNegotiateChannelConstructor(self, authId);
    return self;
}

void DefaultNegotiateChannelDelete(struct DefaultNegotiateChannel *self)
{
    DefaultNegotiateChannelDestructor(self);
    SoftBusFree(self);
}

int32_t OpenDefaultNegotiateChannel(const char *remoteIp, int32_t remotePort,
                                    struct WifiDirectNegotiateChannel *srcChannel,
                                    struct DefaultNegoChannelOpenCallback *callback)
{
    (void)remoteIp;
    (void)remotePort;
    (void)srcChannel;
    (void)callback;
    return SOFTBUS_OK;
}

void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

int32_t StartListeningForDefaultChannel(const char *localIp)
{
    (void)localIp;
    return 0;
}

void StopListeningForDefaultChannel(void)
{
}

DefaultNegotiateChannelMock* DefaultNegotiateChannelMock::mock = nullptr;

DefaultNegotiateChannelMock::DefaultNegotiateChannelMock()
{
    mock = this;
}

DefaultNegotiateChannelMock::~DefaultNegotiateChannelMock()
{
    mock = nullptr;
}