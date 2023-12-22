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

#include "wifi_direct_protocol_factory.h"
#include "protocol/json_protocol.h"
#include "protocol/tlv_protocol.h"

static struct WifiDirectTlvProtocol* NewWifiDirectTlvProtocol(void)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol*)SoftBusCalloc(sizeof(*self));
    if (self != NULL) {
        if (!WifiDirectTlvProtocolConstructor(self)) {
            SoftBusFree(self);
            self = NULL;
        }
    }

    return self;
}

static struct WifiDirectJsonProtocol* NewWifiDirectJsonProtocol(void)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol*)SoftBusCalloc(sizeof(*self));
    if (self != NULL) {
        if (!WifiDirectJsonProtocolConstructor(self)) {
            SoftBusFree(self);
            self = NULL;
        }
    }

    return self;
}

static struct WifiDirectProtocol* CreateProtocol(enum WifiDirectProtocolType type)
{
    struct WifiDirectProtocol *protocol = NULL;
    if (type == WIFI_DIRECT_PROTOCOL_JSON) {
        protocol = (struct WifiDirectProtocol *) NewWifiDirectJsonProtocol();
    } else if (type == WIFI_DIRECT_PROTOCOL_TLV) {
        protocol = (struct WifiDirectProtocol *) NewWifiDirectTlvProtocol();
    }
    return protocol;
}

static void DestroyProtocol(struct WifiDirectProtocol *protocol)
{
    protocol->destructor(protocol);
    SoftBusFree(protocol);
}

static struct WifiDirectProtocolFactory g_factory = {
    .createProtocol = CreateProtocol,
    .destroyProtocol = DestroyProtocol,
};

struct WifiDirectProtocolFactory* GetWifiDirectProtocolFactory(void)
{
    return &g_factory;
}