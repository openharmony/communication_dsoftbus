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
#ifndef WIFI_DIRECT_LINK_MANAGER_H
#define WIFI_DIRECT_LINK_MANAGER_H

#include "wifi_direct_types.h"
#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "data/inner_link.h"

#ifdef __cplusplus
extern "C" {
#endif

struct LinkManagerListener {
    void (*onInnerLinkChange)(struct InnerLink *innerLink, bool isStateChange);
};

struct LinkManager {
    struct InnerLink* (*getLinkByDevice)(const char *macString);
    struct InnerLink* (*getLinkByTypeAndDevice)(enum WifiDirectLinkType linkType, const char *macString);
    struct InnerLink* (*getLinkByIp)(const char *ipString, bool isRemoteIp);
    struct InnerLink* (*getLinkById)(int32_t linkId);
    struct InnerLink* (*getLinkByTypeAndUuid)(enum WifiDirectLinkType linkType, const char *uuid);
    int32_t (*getAllLinks)(struct InnerLink **linkArray, int32_t *linkArraySize);
    void (*notifyLinkChange)(struct InnerLink *link);
    void (*removeLinksByLinkType)(enum WifiDirectLinkType linkType);
    void (*refreshLinks)(enum WifiDirectLinkType linkType, int32_t clientDeviceSize, char *clientDevices[]);
    void (*registerListener)(const struct LinkManagerListener *listener);
    int32_t (*generateLinkId)(struct InnerLink *innerLink, int32_t requestId, int32_t pid);
    void (*recycleLinkId)(int32_t linkId, const char *remoteMac);
    void (*setNegotiateChannelForLink)(struct WifiDirectNegotiateChannel *channel, enum WifiDirectLinkType linkType);
    void  (*clearNegotiateChannelForLink)(struct WifiDirectNegotiateChannel *channel);
    void (*dump)(int32_t fd);
    bool (*checkAll)(enum WifiDirectLinkType type, const char *interface, bool (*checker)(struct InnerLink *));

    SoftBusMutex mutex;
    ListNode linkLists[WIFI_DIRECT_LINK_TYPE_MAX]; // type/interface/remoteMac
    struct LinkManagerListener listener;
    int32_t currentLinkId;
    int32_t count;
    bool isInited;
};

struct LinkManager* GetLinkManager(void);
int32_t LinkManagerInit(void);

#ifdef __cplusplus
}
#endif
#endif