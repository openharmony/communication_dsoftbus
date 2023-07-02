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

#include "wifi_direct_intent.h"

#define LOG_LABEL "[WifiDirect] WifiDirectIntent: "

#define INTENT_TAG_P2P_STATE 0
#define INTENT_TAG_P2P_CONNECT_STATE 1
#define INTENT_TAG_P2P_GROUP_INFO 2
#define INTENT_TAG_HML_STATE 3
#define INTENT_TAG_HML_GROUP_INFO 4
#define INTENT_TAG_NETWORK_INFO 5
#define INTENT_TAG_EXTRA_INFO 6
#define INTENT_TAG_WIFI_RPT_STATE 7
#define INTENT_TAG_INTERFACE_NAME 8

IC_DECLARE_KEY_PROPERTIES(WifiDirectIntent, INTENT_KEY_MAX) = {
    IC_KEY_PROPERTY(INTENT_KEY_P2P_STATE, INTENT_TAG_P2P_STATE, "P2P_STATE", INT, 0),
    IC_KEY_PROPERTY(INTENT_KEY_P2P_CONNECT_STATE, INTENT_TAG_P2P_CONNECT_STATE, "P2P_CONNECT_STATE", INT, 0),
    IC_KEY_PROPERTY(INTENT_KEY_P2P_GROUP_INFO, INTENT_TAG_P2P_GROUP_INFO, "P2P_GROUP_INFO", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(INTENT_KEY_HML_STATE, INTENT_TAG_HML_STATE, "HML_STATE", INT, 0),
    IC_KEY_PROPERTY(INTENT_KEY_HML_GROUP_INFO, INTENT_TAG_HML_GROUP_INFO, "HML_GROUP_INFO", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(INTENT_KEY_NETWORK_INFO, INTENT_TAG_NETWORK_INFO, "NETWORK_INFO", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(INTENT_KEY_EXTRA_INFO, INTENT_TAG_EXTRA_INFO, "EXTRA_INFO", STRING, 0),
    IC_KEY_PROPERTY(INTENT_KEY_WIFI_RPT_STATE, INTENT_TAG_WIFI_RPT_STATE, "WIFI_RPT_STATE", INT, 0),
    IC_KEY_PROPERTY(INTENT_KEY_INTERFACE_NAME, INTENT_TAG_INTERFACE_NAME, "INTERFACE_NAME", BYTE_ARRAY, 0),
};

static size_t GetKeySize(void)
{
    return INTENT_KEY_MAX;
}

/* constructor and destructor */
void WifiDirectIntentConstructor(struct WifiDirectIntent* self)
{
    InfoContainerConstructor((struct InfoContainer *)self, WifiDirectIntentKeyProperties, INTENT_KEY_MAX);

    self->getKeySize = GetKeySize;
    self->destructor = WifiDirectIntentDestructor;
}

void WifiDirectIntentDestructor(struct WifiDirectIntent* self)
{
    InfoContainerDestructor((struct InfoContainer *)self, INTENT_KEY_MAX);
}

/* new and delete */
struct WifiDirectIntent* WifiDirectIntentNew(void)
{
    struct WifiDirectIntent *self = (struct WifiDirectIntent *)SoftBusCalloc(sizeof(*self));
    if (self) {
        WifiDirectIntentConstructor(self);
    }

    return self;
}

void WifiDirectIntentDelete(struct WifiDirectIntent* self)
{
    WifiDirectIntentDestructor(self);
    SoftBusFree(self);
}