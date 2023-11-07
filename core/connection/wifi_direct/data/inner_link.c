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

#include "inner_link.h"
#include <securec.h>
#include <string.h>
#include "softbus_log_old.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "wifi_direct_types.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_anonymous.h"
#include "protocol/wifi_direct_protocol_factory.h"

#define LOG_LABEL "[WD] IL: "

#define IL_TAG_CONNECT_TYPE 1
#define IL_TAG_STATE 2
#define IL_TAG_LOCAL_INTERFACE 3
#define IL_TAG_LOCAL_BASE_MAC 4
#define IL_TAG_LOCAL_DYNAMIC_MAC 5
#define IL_TAG_LOCAL_IPV4 6
#define IL_TAG_REMOTE_INTERFACE 7
#define IL_TAG_REMOTE_BASE_MAC 8
#define IL_TAG_REMOTE_DYNAMIC_MAC 9
#define IL_TAG_REMOTE_IPV4 10
#define IL_TAG_IS_CLIENT 11
#define IL_TAG_IS_BEING_USED_BY_LOCAL 12
#define IL_TAG_IS_BEING_USED_BY_REMOTE 13
#define IL_TAG_IS_SOURCE 14
#define IL_TAG_FREQUENCY 15
#define IL_TAG_STATE_CHANGE_TIME 16
#define IL_TAG_DEVICE_ID 17
#define IL_TAG_AUTH_CONNECTION 18

IC_DECLARE_KEY_PROPERTIES(InnerLink, IL_KEY_MAX) = {
    IC_KEY_PROPERTY(IL_KEY_CONNECT_TYPE, IL_TAG_CONNECT_TYPE, "CONNECT_TYPE", INT, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_STATE, IL_TAG_STATE, "STATE", INT, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_LOCAL_INTERFACE, IL_TAG_LOCAL_INTERFACE, "LOCAL_INTERFACE", STRING, 0),
    IC_KEY_PROPERTY(IL_KEY_LOCAL_BASE_MAC, IL_TAG_LOCAL_BASE_MAC, "LOCAL_BASE_MAC", STRING, MAC_ADDR_FLAG | DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_LOCAL_DYNAMIC_MAC, IL_TAG_LOCAL_DYNAMIC_MAC, "LOCAL_DYNAMIC_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(IL_KEY_LOCAL_IPV4, IL_TAG_LOCAL_IPV4, "LOCAL_IPV4", IPV4_INFO, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_REMOTE_INTERFACE, IL_TAG_REMOTE_INTERFACE, "REMOTE_INTERFACE", STRING, 0),
    IC_KEY_PROPERTY(IL_KEY_REMOTE_BASE_MAC, IL_TAG_REMOTE_BASE_MAC, "REMOTE_BASE_MAC", STRING,
                    MAC_ADDR_FLAG | DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_REMOTE_DYNAMIC_MAC, IL_TAG_REMOTE_DYNAMIC_MAC, "REMOTE_DYNAMIC_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(IL_KEY_REMOTE_IPV4, IL_TAG_REMOTE_IPV4, "REMOTE_IPV4", IPV4_INFO, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_IS_CLIENT, IL_TAG_IS_CLIENT, "IS_CLIENT", BOOLEAN, 0),
    IC_KEY_PROPERTY(IL_KEY_IS_BEING_USED_BY_LOCAL, IL_TAG_IS_BEING_USED_BY_LOCAL, "IS_BEING_USED_BY_LOCAL",
                    BOOLEAN, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_IS_BEING_USED_BY_REMOTE, IL_TAG_IS_BEING_USED_BY_REMOTE, "IS_BEING_USED_BY_REMOTE",
                    BOOLEAN, DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_IS_SOURCE, IL_TAG_IS_SOURCE, "IS_SOURCE", BOOLEAN, 0),
    IC_KEY_PROPERTY(IL_KEY_FREQUENCY, IL_TAG_FREQUENCY, "FREQUENCY", INT, 0),
    IC_KEY_PROPERTY(IL_KEY_STATE_CHANGE_TIME, IL_TAG_STATE_CHANGE_TIME, "STATE_CHANGE_TIME", LONG, 0),
    IC_KEY_PROPERTY(IL_KEY_DEVICE_ID, IL_TAG_DEVICE_ID, "DEVICE_ID", STRING, DEVICE_ID_FLAG | DUMP_FLAG),
    IC_KEY_PROPERTY(IL_KEY_NEGO_CHANNEL, IL_TAG_AUTH_CONNECTION, "AUTH_CONNECTION", AUTH_CONNECTION, 0),
};

struct LinkIdStruct {
    ListNode node;
    int32_t id;
    int32_t requestId;
    int32_t pid;
};

/* private method forward declare */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty);
static bool UnmarshallingPrimary(struct InnerLink *self, enum InnerLinkKey key, uint8_t *data, size_t size);

/* public interface */
static size_t GetKeySize(void)
{
    return IL_KEY_MAX;
}

static const char* GetContainerName(void)
{
    return "InnerLink";
}

static bool Marshalling(struct InnerLink *self, struct WifiDirectProtocol *protocol)
{
    for (size_t key = 0; key < IL_KEY_MAX; key++) {
        if (key == IL_KEY_DEVICE_ID) {
            continue;
        }

        size_t size = 0;
        uint8_t *value = self->get(self, key, &size, NULL);
        if (!value || !size) {
            continue;
        }

        bool ret = false;
        struct InfoContainerKeyProperty *keyProperty = self->keyProperties + key;
        switch (keyProperty->type) {
            case BOOLEAN: {
                    uint8_t boolValue = (uint8_t)!!*(bool *)value;
                    ret = protocol->writeData(protocol, keyProperty, &boolValue, 1);
                    break;
                }
            case BYTE:
            case INT:
            case INT_ARRAY:
            case BYTE_ARRAY:
            case IPV4_INFO_ARRAY:
                ret = protocol->writeData(protocol, keyProperty, value, size);
                break;
            case STRING:
                ret = protocol->writeData(protocol, keyProperty, value, size >= 1 ? size - 1 : 0);
                break;
            case IPV4_INFO: {
                    uint8_t ipv4Bytes[IPV4_INFO_BYTES_ARRAY_LEN] = {0};
                    size_t ipv4BytesLen = IPV4_INFO_BYTES_ARRAY_LEN;
                    WifiDirectIpv4InfoToBytes((struct WifiDirectIpv4Info *)value, 1, ipv4Bytes, &ipv4BytesLen);
                    ret = protocol->writeData(protocol, keyProperty, ipv4Bytes, ipv4BytesLen);
                    break;
                }
            default:
                CLOGI(LOG_LABEL "no need to pack for type=%d", keyProperty->type);
                continue;
        }

        CONN_CHECK_AND_RETURN_RET_LOG(ret, false, LOG_LABEL "marshalling failed");
    }

    return true;
}

static bool Unmarshalling(struct InnerLink *self, struct WifiDirectProtocol *protocol)
{
    size_t size = 0;
    uint8_t *data = NULL;
    struct InfoContainerKeyProperty keyProperty;

    while (protocol->readData(protocol, &keyProperty, &data, &size)) {
        bool ret = true;
        enum InnerLinkKey key = GetKeyFromKeyProperty(&keyProperty);
        CONN_CHECK_AND_RETURN_RET_LOG(key < IL_KEY_MAX, false, LOG_LABEL "key out of range, tag=%d", keyProperty.tag);

        enum InfoContainerEntryType type = keyProperty.type;
        switch (type) {
            case BOOLEAN:
                self->putBoolean(self, key, (bool)data[0]);
                break;
            case INT:
            case BYTE:
            case INT_ARRAY:
            case BYTE_ARRAY:
            case IPV4_INFO_ARRAY:
                ret = UnmarshallingPrimary(self, key, data, size);
                break;
            case IPV4_INFO: {
                    struct WifiDirectIpv4Info ipv4;
                    size_t ipv4Count = 1;
                    WifiDirectIpv4BytesToInfo(data, size, &ipv4, &ipv4Count);
                    self->putRawData(self, key, &ipv4, sizeof(ipv4));
                    break;
                }
            case STRING: {
                char *string = SoftBusCalloc(size + 1);
                CONN_CHECK_AND_RETURN_RET_LOG(string, false, LOG_LABEL "alloc failed");
                if (memcpy_s(string, size + 1, data, size) != EOK) {
                    CLOGE("string memcpy fail");
                    SoftBusFree(string);
                    return false;
                }
                ret = UnmarshallingPrimary(self, key, (uint8_t *) string, size + 1);
                SoftBusFree(string);
            }
                break;
            default:
                CLOGI(LOG_LABEL "no need to unpack for type=%d", type);
                continue;
        }
        CONN_CHECK_AND_RETURN_RET_LOG(ret, false, LOG_LABEL "unmarshalling failed key=%d", key);
    }

    return true;
}

static int32_t GetLink(struct InnerLink *self, int32_t requestId, int32_t pid, struct WifiDirectLink *link)
{
    CONN_CHECK_AND_RETURN_RET_LOG(link, SOFTBUS_INVALID_PARAM, "link is null");

    link->linkId = GetLinkManager()->generateLinkId(self, requestId, pid);
    link->connectType = self->getInt(self, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);

    int32_t ret = self->getLocalIpString(self, link->localIp, sizeof(link->localIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, "get local ip failed");

    ret = self->getRemoteIpString(self, link->remoteIp, sizeof(link->remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, "get remote ip failed");

    return SOFTBUS_OK;
}

static int32_t GetLocalIpString(struct InnerLink *self, char *ipString, int32_t ipStringSize)
{
    struct WifiDirectIpv4Info *ipv4 = self->getRawData(self, IL_KEY_LOCAL_IPV4, NULL, NULL);
    return WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
}

static int32_t GetRemoteIpString(struct InnerLink *self, char *ipString, int32_t ipStringSize)
{
    struct WifiDirectIpv4Info *ipv4 = self->getRawData(self, IL_KEY_REMOTE_IPV4, NULL, NULL);
    return WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
}

static void PutLocalIpString(struct InnerLink *self, const char *ipString)
{
    struct WifiDirectIpv4Info ipv4;
    int32_t ret = WifiDirectIpStringToIpv4(ipString, &ipv4);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "ip to ipv4 failed");
    self->putRawData(self, IL_KEY_LOCAL_IPV4, &ipv4, sizeof(ipv4));
}

static void PutRemoteIpString(struct InnerLink *self, const char *ipString)
{
    struct WifiDirectIpv4Info ipv4;
    int32_t ret = WifiDirectIpStringToIpv4(ipString, &ipv4);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "ip to ipv4 failed");
    self->putRawData(self, IL_KEY_REMOTE_IPV4, &ipv4, sizeof(ipv4));
}

static void IncreaseReference(struct InnerLink *self)
{
    self->reference++;
    CLOGI(LOG_LABEL "reference=%d IS_BEING_USED_BY_LOCAL=true", self->reference);
    self->putBoolean(self, IL_KEY_IS_BEING_USED_BY_LOCAL, true);
}

static void DecreaseReference(struct InnerLink *self)
{
    if (self->reference > 0) {
        self->reference--;
    }

    CLOGI(LOG_LABEL "reference=%d", self->reference);
    if (self->reference == 0) {
        self->putBoolean(self, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
        CLOGI(LOG_LABEL "IS_BEING_USED_BY_LOCAL=false");
    }
}

static int32_t GetReference(struct InnerLink *self)
{
    return self->reference;
}

static void AddId(struct InnerLink *self, int32_t linkId, int32_t requestId, int32_t pid)
{
    struct LinkIdStruct *item = SoftBusCalloc(sizeof(*item));
    CONN_CHECK_AND_RETURN_LOG(item, "malloc LinkId struct failed");

    ListInit(&item->node);
    item->id = linkId;
    item->requestId = requestId;
    item->pid = pid;
    ListTailInsert(&self->idList, &item->node);
    self->increaseReference(self);
    self->putBoolean(self, IL_KEY_IS_BEING_USED_BY_LOCAL, true);
}

static void RemoveId(struct InnerLink *self, int32_t linkId)
{
    struct LinkIdStruct *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &self->idList, struct LinkIdStruct, node) {
        if (item->id == linkId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            self->decreaseReference(self);
            break;
        }
    }

    if (IsListEmpty(&self->idList)) {
        self->putBoolean(self, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    }
}

static bool ContainId(struct InnerLink *self, int32_t linkId)
{
    struct LinkIdStruct *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &self->idList, struct LinkIdStruct, node) {
        if (item->id == linkId) {
            return true;
        }
    }
    return false;
}

static void DumpLinkId(struct InnerLink *self)
{
    struct LinkIdStruct *item = NULL;
    CLOGI(LOG_LABEL "reference=%d", self->reference);
    LIST_FOR_EACH_ENTRY(item, &self->idList, struct LinkIdStruct, node) {
        CLOGI(LOG_LABEL "linkId=%d requestId=%d pid=%d", item->id, item->requestId, item->pid);
    }
}

static void SetState(struct InnerLink *self, enum InnerLinkState newState)
{
    enum InnerLinkState oldState = self->getInt(self, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    if (oldState != newState) {
        uint64_t changeTime = SoftBusGetSysTimeMs();
        self->putRawData(self, IL_KEY_STATE_CHANGE_TIME, &changeTime, sizeof(changeTime));
        self->putInt(self, IL_KEY_STATE, newState);
    }
}

#define PROTECT_DURATION_MS 2000
static bool IsProtected(struct InnerLink *self)
{
    enum InnerLinkState state = (enum InnerLinkState)self->getInt(self, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    if (state != INNER_LINK_STATE_CONNECTED) {
        CLOGI(LOG_LABEL "state=%d", state);
        return false;
    }

    uint64_t currentTime = SoftBusGetSysTimeMs();
    uint64_t *changeTime = self->getRawData(self, IL_KEY_STATE_CHANGE_TIME, NULL, NULL);
    CLOGI(LOG_LABEL "changeTime=%zu curTime=%zu", *changeTime, currentTime);
    if (currentTime && currentTime - PROTECT_DURATION_MS < *changeTime) {
        return true;
    }
    return false;
}

/* private method implement */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty)
{
    struct InfoContainerKeyProperty *predefineKeyProperty = NULL;
    for (size_t key = 0; key < IL_KEY_MAX; key++) {
        predefineKeyProperty = InnerLinkKeyProperties + key;
        if ((keyProperty->content && strcmp(keyProperty->content, predefineKeyProperty->content) == 0) ||
            (keyProperty->tag == predefineKeyProperty->tag)) {
            *keyProperty = *predefineKeyProperty;
            return key;
        }
    }

    return IL_KEY_MAX;
}

static bool UnmarshallingPrimary(struct InnerLink *self, enum InnerLinkKey key, uint8_t *data, size_t size)
{
    self->putRawData(self, key, data, ALIGN_SIZE_4(size));
    return true;
}

/* constructor and destructor */
void InnerLinkConstructor(struct InnerLink *self)
{
    InfoContainerConstructor((struct InfoContainer*)(self), InnerLinkKeyProperties, IL_KEY_MAX);

    /* virtual method */
    self->getKeySize = GetKeySize;
    self->getContainerName = GetContainerName;
    self->marshalling = Marshalling;
    self->unmarshalling = Unmarshalling;
    self->destructor = InnerLinkDestructor;

    ListInit(&self->node);
    ListInit(&self->idList);

    self->reference = 0;
    self->getLink = GetLink;
    self->getLocalIpString = GetLocalIpString;
    self->getRemoteIpString = GetRemoteIpString;
    self->putLocalIpString = PutLocalIpString;
    self->putRemoteIpString = PutRemoteIpString;
    self->increaseReference = IncreaseReference;
    self->decreaseReference = DecreaseReference;
    self->getReference = GetReference;
    self->addId = AddId;
    self->removeId = RemoveId;
    self->containId = ContainId;
    self->dumpLinkId = DumpLinkId;
    self->setState = SetState;
    self->isProtected = IsProtected;
}

void InnerLinkConstructorWithArgs(struct InnerLink *self, enum WifiDirectConnectType type, bool isClient,
                                  const char *localInterface, const char *remoteMac)
{
    InnerLinkConstructor(self);
    self->putInt(self, IL_KEY_CONNECT_TYPE, type);
    self->putBoolean(self, IL_KEY_IS_CLIENT, isClient);
    self->putString(self, IL_KEY_LOCAL_INTERFACE, localInterface);
    self->putString(self, IL_KEY_REMOTE_BASE_MAC, remoteMac);
}

void InnerLinkDestructor(struct InnerLink *self)
{
    InfoContainerDestructor((struct InfoContainer*)(self), IL_KEY_MAX);
}

/* new and delete */
struct InnerLink* InnerLinkNew(void)
{
    struct InnerLink *self = SoftBusCalloc(sizeof(*self));
    InnerLinkConstructor(self);
    return self;
}

void InnerLinkDelete(struct InnerLink *self)
{
    InnerLinkDestructor(self);
    SoftBusFree(self);
}

struct InnerLink* InnerLinkNewArray(size_t size)
{
    struct InnerLink *self = (struct InnerLink *)SoftBusCalloc(sizeof(*self) * size);
    if (self) {
        for (size_t i = 0; i < size; i++) {
            InnerLinkConstructor(self + i);
        }
    }

    return self;
}

void InnerLinkDeleteArray(struct InnerLink *self, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        InnerLinkDestructor(self + i);
    }
    SoftBusFree(self);
}