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

#include "link_manager.h"
#include <string.h>
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "inner_link.h"
#include "broadcast_receiver.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_negotiate_channel.h"
#include "channel/default_negotiate_channel.h"
#include "wifi_direct_p2p_adapter.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_ip_manager.h"

#define LOG_LABEL "[WD] LM: "

/* private method forward declare */
static void UpdateLink(struct InnerLink *oldLink, struct InnerLink *newLink);
static void OnInnerLinkChange(struct InnerLink *innerLink, bool isStateChange);
static void CloseP2pNegotiateChannel(struct InnerLink *innerLink);

/* public interface */
static struct InnerLink* GetLinkByDevice(const char *macString)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, NULL, LOG_LABEL "not inited");
    struct InnerLink *target = NULL;
    for (size_t type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        target = self->getLinkByTypeAndDevice(type, macString);
        if (target) {
            return target;
        }
    }
    return NULL;
}

static struct InnerLink* GetLinkByTypeAndDevice(enum WifiDirectConnectType connectType, const char *macString)
{
    CONN_CHECK_AND_RETURN_RET_LOG(macString, NULL, "mac is null");
    CONN_CHECK_AND_RETURN_RET_LOG(connectType < WIFI_DIRECT_CONNECT_TYPE_MAX, NULL, "connect type invalid");
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, NULL, LOG_LABEL "not inited");
    struct InnerLink *target = NULL;
    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(target, &self->linkLists[connectType], struct InnerLink, node) {
        char *mac = target->get(target, IL_KEY_REMOTE_BASE_MAC, NULL, NULL);
        if (mac && !strcmp(mac, macString)) {
            SoftBusMutexUnlock(&self->mutex);
            return target;
        }
    }
    SoftBusMutexUnlock(&self->mutex);
    return NULL;
}

static struct InnerLink* GetLinkByIp(const char *ipString, bool isRemoteIp)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, NULL, LOG_LABEL "not inited");
    struct InnerLink *target = NULL;
    char targetIpString[IP_ADDR_STR_LEN] = {0};
    int32_t ret = SOFTBUS_ERR;

    SoftBusMutexLock(&self->mutex);
    for (size_t type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        LIST_FOR_EACH_ENTRY(target, &self->linkLists[type], struct InnerLink, node) {
            char *mac = target->getString(target, IL_KEY_REMOTE_BASE_MAC, "");
            if (isRemoteIp) {
                ret = target->getRemoteIpString(target, targetIpString, sizeof(targetIpString));
            } else {
                ret = target->getLocalIpString(target, targetIpString, sizeof(targetIpString));
            }
            if (ret != SOFTBUS_OK) {
                CLOGE("get ip failed, continue");
                continue;
            }

            if (!strcmp(ipString, targetIpString)) {
                CLOGD(LOG_LABEL "find target %s inner link for %s",
                      WifiDirectAnonymizeMac(mac), WifiDirectAnonymizeIp(ipString));
                SoftBusMutexUnlock(&self->mutex);
                return target;
            }
        }
    }
    SoftBusMutexUnlock(&self->mutex);

    CLOGD(LOG_LABEL "not find for %s", WifiDirectAnonymizeIp(ipString));
    return NULL;
}

static struct InnerLink* GetLinkById(int32_t linkId)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, NULL, LOG_LABEL "not inited");
    struct InnerLink *target = NULL;

    SoftBusMutexLock(&self->mutex);
    for (size_t type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        LIST_FOR_EACH_ENTRY(target, &self->linkLists[type], struct InnerLink, node) {
            if (target->containId(target, linkId)) {
                CLOGD(LOG_LABEL "find for linkId=%d", linkId);
                SoftBusMutexUnlock(&self->mutex);
                return target;
            }
        }
    }
    SoftBusMutexUnlock(&self->mutex);

    CLOGD(LOG_LABEL "not find for linkId=%d", linkId);
    return NULL;
}

struct InnerLink* GetLinkByUuid(const char *uuid)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, NULL, LOG_LABEL "not inited");
    struct InnerLink *target = NULL;

    SoftBusMutexLock(&self->mutex);
    for (size_t type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        LIST_FOR_EACH_ENTRY(target, &self->linkLists[type], struct InnerLink, node) {
            const char *linkUuid = target->getString(target, IL_KEY_DEVICE_ID, "");
            if (strcmp(linkUuid, uuid) == 0) {
                CLOGD(LOG_LABEL "find for uuid=%s", AnonymizesUUID(uuid));
                SoftBusMutexUnlock(&self->mutex);
                return target;
            }
        }
    }
    SoftBusMutexUnlock(&self->mutex);

    CLOGD(LOG_LABEL "not find for uuid=%s", AnonymizesUUID(uuid));
    return NULL;
}

static int32_t GetAllLinks(struct InnerLink **linkArray, int32_t *linkArraySize)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, SOFTBUS_ERR, LOG_LABEL "not inited");

    CLOGI(LOG_LABEL "count=%d", self->count);
    if (self->count <= 0) {
        *linkArray = NULL;
        *linkArraySize = 0;
        return SOFTBUS_OK;
    }

    int32_t size = self->count;
    struct InnerLink *array = InnerLinkNewArray(size);
    CONN_CHECK_AND_RETURN_RET_LOG(array, SOFTBUS_ERR, "new link array failed");

    int32_t i = 0;
    struct InnerLink *link = NULL;

    SoftBusMutexLock(&self->mutex);
    for (size_t type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        LIST_FOR_EACH_ENTRY(link, &self->linkLists[type], struct InnerLink, node) {
            array[i].deepCopy(array + i, link);
            i++;
        }
    }
    SoftBusMutexUnlock(&self->mutex);

    *linkArray = array;
    *linkArraySize = size;
    return SOFTBUS_OK;
}

static void NotifyLinkChange(struct InnerLink *newLink)
{
    CONN_CHECK_AND_RETURN_LOG(newLink, "link is null");
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");
    enum InnerLinkState state = newLink->getInt(newLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    if (state == INNER_LINK_STATE_DISCONNECTED) {
        UpdateLink(newLink, NULL);
    }

    enum WifiDirectConnectType type = newLink->getInt(newLink, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_MAX);
    char *mac = newLink->getString(newLink, IL_KEY_REMOTE_BASE_MAC, "");

    struct InnerLink *oldLink = GetLinkManager()->getLinkByTypeAndDevice(type, mac);
    UpdateLink(oldLink, newLink);
}

static void ReleaseLinkIp(struct InnerLink *link)
{
    char *interface = link->getString(link, IL_KEY_LOCAL_INTERFACE, "");
    struct WifiDirectIpv4Info *localIpv4 = link->getRawData(link, IL_KEY_LOCAL_IPV4, NULL, NULL);
    struct WifiDirectIpv4Info *remoteIpv4 = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    char *remoteMac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");

    if (!localIpv4) {
        CLOGD(LOG_LABEL "local ipv4 is null");
        return;
    }
    if (!remoteIpv4) {
        CLOGD(LOG_LABEL "local ipv4 is null");
        return;
    }

    GetWifiDirectIpManager()->releaseIp(interface, localIpv4, remoteIpv4, remoteMac);
}

static void RemoveLinksByConnectType(enum WifiDirectConnectType connectType)
{
    CONN_CHECK_AND_RETURN_LOG(connectType < WIFI_DIRECT_CONNECT_TYPE_MAX, "connect type invalid");
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");
    SoftBusMutexLock(&self->mutex);
    ListNode *list = &self->linkLists[connectType];
    while (!IsListEmpty(list)) {
        struct InnerLink *link = LIST_ENTRY(list->next, struct InnerLink, node);
        ListDelete(&link->node);
        self->count--;
        link->setState(link, INNER_LINK_STATE_DISCONNECTED);
        OnInnerLinkChange(link, true);
        CloseP2pNegotiateChannel(link);
        if (connectType == WIFI_DIRECT_CONNECT_TYPE_HML) {
            ReleaseLinkIp(link);
        }
        ListDelete(&link->node);
        self->count--;
        InnerLinkDelete(link);
    }
    SoftBusMutexUnlock(&self->mutex);
}

static void RefreshLinks(enum WifiDirectConnectType connectType, int32_t clientDeviceSize, char *clientDevices[])
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");
    struct InnerLink *link = NULL;
    struct InnerLink *linkNext = NULL;

    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY_SAFE(link, linkNext, self->linkLists + connectType, struct InnerLink, node) {
        bool found = false;
        enum InnerLinkState state = link->getInt(link, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
        char *remoteMac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
        if (state == INNER_LINK_STATE_CONNECTING) {
            continue;
        }
        for (int32_t i = 0; i < clientDeviceSize; i++) {
            if (strcmp(remoteMac, clientDevices[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            CLOGD(LOG_LABEL "remoteMac=%s is removed type=%d", WifiDirectAnonymizeMac(remoteMac), connectType);
            if (connectType == WIFI_DIRECT_CONNECT_TYPE_HML) {
                ReleaseLinkIp(link);
            }
            ListDelete(&link->node);
            self->count--;
            link->setState(link, INNER_LINK_STATE_DISCONNECTED);
            OnInnerLinkChange(link, true);
            CloseP2pNegotiateChannel(link);
            ListDelete(&link->node);
            self->count--;
            InnerLinkDelete(link);
        }
    }
    SoftBusMutexUnlock(&self->mutex);
}

static void RegisterListener(struct LinkManagerListener *listener)
{
    GetLinkManager()->listener = *listener;
}

static int32_t GenerateLinkId(struct InnerLink *innerLink, int32_t requestId, int32_t pid)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_RET_LOG(self->isInited, SOFTBUS_OK, LOG_LABEL "not inited");
    enum WifiDirectConnectType type = innerLink->getInt(innerLink, IL_KEY_CONNECT_TYPE,
                                                        WIFI_DIRECT_CONNECT_TYPE_INVALID);
    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");
    struct InnerLink *originInnerLink = self->getLinkByTypeAndDevice(type, remoteMac);
    if (!originInnerLink) {
        CLOGE(LOG_LABEL "not find");
        return LINK_ID_INVALID;
    }

    if (self->currentLinkId < 0) {
        self->currentLinkId = 0;
    }

    int32_t newId = self->currentLinkId++;
    while (self->getLinkById(newId)) {
        newId = self->currentLinkId++;
    }

    originInnerLink->addId(originInnerLink, newId, requestId, pid);
    return newId;
}

static void RecycleLinkId(int32_t linkId, const char *remoteMac)
{
    if (linkId < 0) {
        struct InnerLink *originInnerLink = GetLinkManager()->getLinkByDevice(remoteMac);
        CONN_CHECK_AND_RETURN_LOG(originInnerLink, "originInnerLink is null");
        originInnerLink->decreaseReference(originInnerLink);
        return;
    }
    struct InnerLink *originInnerLink = GetLinkManager()->getLinkById(linkId);
    if (!originInnerLink) {
        CLOGE(LOG_LABEL "not find");
        return;
    }
    originInnerLink->removeId(originInnerLink, linkId);
}

static void SetNegoChannelForLink(struct WifiDirectNegotiateChannel *channel)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");

    char uuid[UUID_BUF_LEN] = {0};
    (void)channel->getDeviceId(channel, uuid, sizeof(uuid));

    struct InnerLink *target = self->getLinkByUuid(uuid);
    CONN_CHECK_AND_RETURN_LOG(target, "uuid=%s failed", AnonymizesUUID(uuid));

    struct WifiDirectNegotiateChannel *channelOld = target->getPointer(target, IL_KEY_NEGO_CHANNEL, NULL);
    if (channelOld) {
        channelOld->destructor(channelOld);
    }
    struct WifiDirectNegotiateChannel *channelNew = channel->duplicate(channel);
    target->putPointer(target, IL_KEY_NEGO_CHANNEL, (void **)&channelNew);
}

static void RemoveP2pGroupIfNeeded(struct InnerLink *link)
{
    enum WifiDirectConnectType type =
        (enum WifiDirectConnectType)link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);
    if (type != WIFI_DIRECT_CONNECT_TYPE_P2P) {
        return;
    }

    struct WifiDirectP2pGroupInfo *groupInfo = NULL;
    int32_t ret = GetWifiDirectP2pAdapter()->getGroupInfo(&groupInfo);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get group info failed");

    if (!groupInfo->isGroupOwner) {
        CLOGI(LOG_LABEL "remove gc group");
        (void)GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(IF_NAME_P2P);
        SoftBusFree(groupInfo);
        return;
    }

    if (groupInfo->clientDeviceSize > 1) {
        SoftBusFree(groupInfo);
        return;
    }

    bool removeGo = false;
    if (groupInfo->clientDeviceSize == 0) {
        removeGo = true;
    } else if (groupInfo->clientDeviceSize == 1) {
        const char *remoteMac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");
        size_t addressSize = MAC_ADDR_ARRAY_SIZE;
        uint8_t address[MAC_ADDR_ARRAY_SIZE] = {0};
        ret = GetWifiDirectNetWorkUtils()->macStringToArray(remoteMac, address, &addressSize);
        if (ret != SOFTBUS_OK) {
            CLOGE(LOG_LABEL "convert failed");
            SoftBusFree(groupInfo);
            return;
        }
        if (memcmp(address, groupInfo->clientDevices[0].address, sizeof(address)) == 0) {
            removeGo = true;
        }
    }

    if (removeGo) {
        CLOGI(LOG_LABEL "remove go group");
        (void)GetWifiDirectP2pAdapter()->removeGroup(IF_NAME_P2P);
    }

    SoftBusFree(groupInfo);
}

static void ClearNegoChannelForLink(const char *uuid, bool destroy)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");

    SoftBusMutexLock(&self->mutex);
    struct InnerLink *target = self->getLinkByUuid(uuid);
    if (target == NULL) {
        SoftBusMutexUnlock(&self->mutex);
        CLOGE(LOG_LABEL "uuid=%s failed", AnonymizesUUID(uuid));
        return;
    }

    struct DefaultNegotiateChannel *channelOld = target->getPointer(target, IL_KEY_NEGO_CHANNEL, NULL);
    if (channelOld) {
        DefaultNegotiateChannelDelete(channelOld);
    }
    target->remove(target, IL_KEY_NEGO_CHANNEL);
    if (destroy) {
        int32_t type = target->getInt(target, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);
        if (type == WIFI_DIRECT_CONNECT_TYPE_P2P) {
            RemoveP2pGroupIfNeeded(target);
        }
    }
    SoftBusMutexUnlock(&self->mutex);
}

static void Dump(void)
{
    struct LinkManager *self = GetLinkManager();
    CONN_CHECK_AND_RETURN_LOG(self->isInited, LOG_LABEL "not inited");
    struct InnerLink *innerLink = NULL;

    SoftBusMutexLock(&self->mutex);
    for (enum WifiDirectConnectType type = 0; type < WIFI_DIRECT_CONNECT_TYPE_MAX; type++) {
        LIST_FOR_EACH_ENTRY(innerLink, &self->linkLists[type], struct InnerLink, node) {
            innerLink->dump(innerLink);
            innerLink->dumpLinkId(innerLink);
        }
    }
    SoftBusMutexUnlock(&self->mutex);
}

static bool CheckAll(enum WifiDirectConnectType type, const char *interface, bool (*checker)(struct InnerLink *))
{
    CONN_CHECK_AND_RETURN_RET_LOG(checker, false, "invalid parameter");
    struct LinkManager *self = GetLinkManager();
    struct InnerLink *innerLink = NULL;
    bool result = true;
    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(innerLink, &self->linkLists[type], struct InnerLink, node) {
        const char *linkInterface = innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, "");
        CLOGD(LOG_LABEL "check %s", linkInterface);
        if (!strcmp(interface, linkInterface) && !checker(innerLink)) {
            result = false;
            break;
        }
    }
    SoftBusMutexUnlock(&self->mutex);
    return result;
}

static struct LinkManager g_manager = {
    .getLinkByDevice = GetLinkByDevice,
    .getLinkByTypeAndDevice = GetLinkByTypeAndDevice,
    .getLinkByIp = GetLinkByIp,
    .getLinkById = GetLinkById,
    .getLinkByUuid = GetLinkByUuid,
    .getAllLinks = GetAllLinks,
    .notifyLinkChange = NotifyLinkChange,
    .removeLinksByConnectType = RemoveLinksByConnectType,
    .refreshLinks = RefreshLinks,
    .registerListener = RegisterListener,
    .generateLinkId = GenerateLinkId,
    .recycleLinkId = RecycleLinkId,
    .setNegoChannelForLink = SetNegoChannelForLink,
    .clearNegoChannelForLink = ClearNegoChannelForLink,
    .dump = Dump,
    .checkAll = CheckAll,
    .currentLinkId = 0,
    .count = 0,
    .isInited = false,
};

struct LinkManager* GetLinkManager(void)
{
    return &g_manager;
}

int32_t LinkManagerInit(void)
{
    SoftBusMutexAttr attr;
    int32_t ret = SoftBusMutexAttrInit(&attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "init mutex attr failed");
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&g_manager.mutex, &attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "init mutex ailed");

    for (uint32_t i = 0; i < WIFI_DIRECT_CONNECT_TYPE_MAX; i++) {
        ListInit(&g_manager.linkLists[i]);
    }

    g_manager.isInited = true;
    return SOFTBUS_OK;
}

/* private method implement */
static void AddLink(struct InnerLink *link)
{
    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_MAX);
    CONN_CHECK_AND_RETURN_LOG(connectType < WIFI_DIRECT_CONNECT_TYPE_MAX, "connect type is invalid");

    struct InnerLink *newLink = InnerLinkNew();
    CONN_CHECK_AND_RETURN_LOG(newLink, "alloc new link failed");
    newLink->deepCopy(newLink, link);

    struct LinkManager *self = GetLinkManager();
    SoftBusMutexLock(&self->mutex);
    ListTailInsert(&self->linkLists[connectType], &newLink->node);
    self->count++;
    OnInnerLinkChange(link, true);
    SoftBusMutexUnlock(&self->mutex);
}

static void RemoveLink(struct InnerLink *link)
{
    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_MAX);
    CONN_CHECK_AND_RETURN_LOG(connectType < WIFI_DIRECT_CONNECT_TYPE_MAX, "connect type is invalid");
    char *mac = link->getString(link, IL_KEY_REMOTE_BASE_MAC, "");

    struct LinkManager *self = GetLinkManager();
    struct InnerLink *oldLink = self->getLinkByTypeAndDevice(connectType, mac);
    if (oldLink) {
        SoftBusMutexLock(&self->mutex);
        oldLink->setState(oldLink, INNER_LINK_STATE_DISCONNECTED);
        OnInnerLinkChange(oldLink, true);
        CloseP2pNegotiateChannel(oldLink);
        ListDelete(&oldLink->node);
        self->count--;
        SoftBusMutexUnlock(&self->mutex);
        InnerLinkDelete(oldLink);
    }
}

static void UpdateLink(struct InnerLink *oldLink, struct InnerLink *newLink)
{
    if (!oldLink) {
        AddLink(newLink);
        return;
    }
    if (!newLink) {
        RemoveLink(oldLink);
        return;
    }

    enum InnerLinkState oldState = oldLink->getInt(oldLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    enum InnerLinkState newState = newLink->getInt(newLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    bool isStateChange = false;
    if (newState != INNER_LINK_STATE_INVALID) {
        isStateChange = oldState != newState;
    }

    bool isChanged = false;
    for (size_t key = 0; key < IL_KEY_MAX; key++) {
        struct InfoContainerKeyProperty *property = &newLink->keyProperties[key];
        size_t size = 0;
        size_t count = 0;
        void *data = newLink->get(newLink, key, &size, &count);
        if (data) {
            if (property->flag == CONTAINER_FLAG) {
                oldLink->putContainer(oldLink, key, data, size);
            } else if (property->flag == CONTAINER_ARRAY_FLAG) {
                oldLink->putContainerArray(oldLink, key, data, count, size / count);
            } else {
                oldLink->putRawData(oldLink, key, data, size);
            }
            isChanged = true;
        }
    }
    if (isChanged) {
        OnInnerLinkChange(oldLink, isStateChange);
    }
}

static void AdjustIfRemoteMacChange(struct InnerLink *innerLink)
{
    struct LinkManager *self = GetLinkManager();
    enum WifiDirectConnectType type =
        innerLink->getInt(innerLink, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);
    char *deviceId = innerLink->getString(innerLink, IL_KEY_DEVICE_ID, "");
    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");

    if (type < 0 || type >= WIFI_DIRECT_CONNECT_TYPE_MAX) {
        return;
    }

    bool found = false;
    struct InnerLink *target = NULL;
    LIST_FOR_EACH_ENTRY(target, &self->linkLists[type], struct InnerLink, node) {
        char *targetDeviceId = target->getString(target, IL_KEY_DEVICE_ID, "");
        char *targetRemoteMac = target->getString(target, IL_KEY_REMOTE_BASE_MAC, "");
        CLOGI(LOG_LABEL "remoteMac=%s targetRemoteMac=%s", WifiDirectAnonymizeMac(remoteMac),
              WifiDirectAnonymizeMac(targetRemoteMac));
        if (strlen(remoteMac) != 0 && strlen(targetRemoteMac) != 0 &&
            strcmp(remoteMac, targetRemoteMac) != 0 && strcmp(deviceId, targetDeviceId) == 0) {
            CLOGD(LOG_LABEL "find");
            found = true;
            break;
        }
    }

    if (!found) {
        CLOGD(LOG_LABEL "not find");
        return;
    }

    ListDelete(&target->node);
    self->count--;

    char *targetLocalMac = target->getString(target, IL_KEY_LOCAL_BASE_MAC, "");
    if (strlen(targetLocalMac) != 0) {
        innerLink->putString(innerLink, IL_KEY_LOCAL_BASE_MAC, targetLocalMac);
    }
    struct WifiDirectIpv4Info *targetRemoteIpv4 = target->getRawData(target, IL_KEY_REMOTE_IPV4, NULL, NULL);
    if (targetRemoteIpv4) {
        innerLink->putRawData(innerLink, IL_KEY_REMOTE_IPV4, targetRemoteIpv4, sizeof(*targetRemoteIpv4));
    }
    SoftBusFree(target);
}

static void OnInnerLinkChange(struct InnerLink *innerLink, bool isStateChange)
{
    struct LinkManager *self = GetLinkManager();
    if (self->listener.onInnerLinkChange) {
        self->listener.onInnerLinkChange(innerLink, isStateChange);
    }
    enum InnerLinkState state = innerLink->getInt(innerLink, IL_KEY_STATE, INNER_LINK_STATE_INVALID);
    if (isStateChange && state == INNER_LINK_STATE_CONNECTED) {
        AdjustIfRemoteMacChange(innerLink);
    }
}

static void CloseP2pNegotiateChannel(struct InnerLink *innerLink)
{
    struct DefaultNegotiateChannel *channel = innerLink->getPointer(innerLink, IL_KEY_NEGO_CHANNEL, NULL);
    if (channel) {
        CLOGD(LOG_LABEL "enter");
        CloseDefaultNegotiateChannel(channel);
        DefaultNegotiateChannelDelete(channel);
        innerLink->remove(innerLink, IL_KEY_NEGO_CHANNEL);
    }
}