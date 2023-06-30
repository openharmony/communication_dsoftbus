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

#include "wifi_direct_decision_center.h"
#include <string.h>
#include <cJSON.h>
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "wifi_direct_negotiate_channel.h"
#include "wifi_direct_p2p_adapter.h"
#include "data/wifi_config_info.h"
#include "data/link_info.h"
#include "data/inner_link.h"
#include "data/negotiate_message.h"
#include "data/resource_manager.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "processor/wifi_direct_processor_factory.h"
#include "utils/wifi_direct_utils.h"

#define LOG_LABEL "[WifiDirect] WifiDirectDecisionCenter: "

#define LENGTH_HEADER 2
#define LINK_MODE_HML_HML 1
#define LINK_MODE_GC_GO 2
#define LINK_MODE_GO_GC 3
#define LINK_LIST_STRING_MAX_SIZE 1024
#define COMMON_BUFFER_LEN 256
#define WIFI_P2P_DEFAULT_BANDWIDTH 3

/* private method forward declare */
static struct WifiDirectProcessor* GetProcessorByLinkInfo(struct LinkInfo *linkInfo);
static struct LinkInfo* CreateLinkInfo(struct NegotiateMessage *msg);

static struct WifiDirectProtocol* GetProtocol(struct WifiDirectNegotiateChannel *channel)
{
    enum WifiDirectProtocolType type = WIFI_DIRECT_PROTOCOL_TLV;
    if (!channel->isRemoteTlvSupported(channel)) {
        type = WIFI_DIRECT_PROTOCOL_JSON;
    }
    struct WifiDirectProtocolFactory *factory = GetWifiDirectProtocolFactory();
    return factory->createProtocol(type);
}

static void PutProtocol(struct WifiDirectProtocol *protocol)
{
    struct WifiDirectProtocolFactory *factory = GetWifiDirectProtocolFactory();
    factory->destroyProtocol(protocol);
}

static struct WifiDirectProcessor* GetProcessorByNegoChannel(struct WifiDirectNegotiateChannel *channel)
{
    enum WifiDirectProcessorType type = WIFI_DIRECT_PROCESSOR_TYPE_HML;
    if (!channel->isRemoteTlvSupported(channel)) {
        type = WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1;
    }

    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(type);
}

static struct WifiDirectProcessor* GetProcessorByNegoChannelAndConnectType(struct WifiDirectNegotiateChannel *channel,
                                                                           enum WifiDirectConnectType connectType)
{
    enum WifiDirectProcessorType type;
    if (!channel->isRemoteTlvSupported(channel)) {
        type = WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1;
    } else if (connectType == WIFI_DIRECT_CONNECT_TYPE_P2P) {
        type = WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2;
    } else {
        type = WIFI_DIRECT_PROCESSOR_TYPE_HML;
    }

    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(type);
}

static struct WifiDirectProcessor* GetProcessorByNegotiateMessage(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, NULL, "channel is null");

    if (!channel->isRemoteTlvSupported(channel)) {
        struct WifiDirectProcessor *processor =
            GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
        return processor;
    }

    struct LinkInfo *linkInfo = msg->getContainer(msg, NM_KEY_LINK_INFO);
    if (linkInfo) {
        return GetProcessorByLinkInfo(linkInfo);
    }

    linkInfo = CreateLinkInfo(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(linkInfo, NULL, "create link info failed");
    struct WifiDirectProcessor *processor = GetProcessorByLinkInfo(linkInfo);
    if (processor) {
        msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)linkInfo, sizeof(*linkInfo));
    }
    LinkInfoDelete(linkInfo);
    return processor;
}

/* private method implement */
static struct WifiDirectProcessor* GetProcessorByLinkInfo(struct LinkInfo *linkInfo)
{
    enum WifiDirectProcessorType type;
    enum WifiDirectRole localRole =
        (enum WifiDirectRole)(linkInfo->getInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_ROLE_NONE));
    if (localRole == WIFI_DIRECT_API_ROLE_HML) {
        type = WIFI_DIRECT_PROCESSOR_TYPE_HML;
    } else if (localRole == WIFI_DIRECT_API_ROLE_GO || localRole == WIFI_DIRECT_API_ROLE_GC) {
        type = WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2;
    } else {
        CLOGE(LOG_LABEL "localRole=%d invalid", localRole);
        return NULL;
    }

    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(type);
}

static void MergeInterfaceInfo(struct InterfaceInfo *dstArray, size_t dstArraySize,
                               struct InterfaceInfo *srcArray, size_t srcArraySize)
{
    for (size_t i = 0; i < dstArraySize; i++) {
        struct InterfaceInfo *dst = dstArray + i;
        char *dstName = dst->getName(dst);
        for (size_t j = 0; j < srcArraySize; j++) {
            struct InterfaceInfo *src = srcArray + j;
            char *srcName = src->getName(src);
            if (!strcmp(dstName, srcName)) {
                bool isAvailable = src->getBoolean(src, II_KEY_IS_AVAILABLE, false);
                int32_t deviceCount = src->getInt(src, II_KEY_CONNECTED_DEVICE_COUNT, 0);
                dst->putBoolean(dst, II_KEY_IS_AVAILABLE, isAvailable);
                dst->putInt(dst, II_KEY_CONNECTED_DEVICE_COUNT, deviceCount);
                CLOGI(LOG_LABEL "name=%s isAvailable=%d deviceCount=%d", dstName, isAvailable, deviceCount);
            }
        }
    }
}

static bool IsLinkModeSupportedOnCap(uint32_t local, uint32_t remote, int32_t mode)
{
    if (mode == LINK_MODE_HML_HML) {
        return (local & WIFI_DIRECT_API_ROLE_HML) && (remote & WIFI_DIRECT_API_ROLE_HML);
    } else if (mode == LINK_MODE_GC_GO) {
        return (local & WIFI_DIRECT_API_ROLE_GC) && (remote & WIFI_DIRECT_API_ROLE_GO);
    } else if (mode == LINK_MODE_GO_GC) {
        return (local & WIFI_DIRECT_API_ROLE_GO) && (remote & WIFI_DIRECT_API_ROLE_GC);
    } else {
        CLOGE(LOG_LABEL "unhandled link mode=%d", mode);
        return false;
    }
}

static bool IsLinkModeSupportedOnRole(uint32_t local, uint32_t remote, int32_t mode)
{
    if (mode == LINK_MODE_GC_GO) {
        return (local != WIFI_DIRECT_API_ROLE_GO) && (remote != WIFI_DIRECT_API_ROLE_GC);
    } else if (mode == LINK_MODE_GO_GC) {
        return (local != WIFI_DIRECT_API_ROLE_GC) && (remote != WIFI_DIRECT_API_ROLE_GO);
    } else {
        CLOGE(LOG_LABEL "unhandled link mode=%d", mode);
        return false;
    }
}

static inline bool IsInterfaceUnavailable(struct InterfaceInfo *info)
{
    return info->getInt(info, II_KEY_CONNECTED_DEVICE_COUNT, 0) >= MAX_CONNECTED_DEVICE_COUNT ||
        info->getBoolean(info, II_KEY_IS_AVAILABLE, false) == false;
}

static void AddToAvailableLinkList(struct InterfaceInfo *local, struct InterfaceInfo *remote,
                                   const char *remoteDeviceId, ListNode *linkList)
{
    char *localName = local->getName(local);
    uint32_t localCap = (uint32_t)(local->getInt(local, II_KEY_CONNECT_CAPABILITY, WIFI_DIRECT_API_ROLE_NONE));
    uint32_t localMode = (uint32_t)(local->getInt(local, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    char *remoteName = remote->getName(remote);
    uint32_t remoteCap = (uint32_t)(remote->getInt(remote, II_KEY_CONNECT_CAPABILITY, WIFI_DIRECT_API_ROLE_NONE));
    uint32_t remoteMode = (uint32_t)(remote->getInt(remote, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE));
    int32_t rate = MIN(local->getInt(local, II_KEY_PHYSICAL_RATE, 0),
                       remote->getInt(remote, II_KEY_PHYSICAL_RATE, 0));
    char *remoteMac = remote->getString(remote, II_KEY_BASE_MAC, "");

    struct LinkInfo *link = NULL;
    if (IsLinkModeSupportedOnCap(localCap, remoteCap, LINK_MODE_HML_HML)) {
        CLOGI(LOG_LABEL "LINK_MODE_HML_HML");
        link = LinkInfoNewWithNameAndMode(localName, remoteName, WIFI_DIRECT_API_ROLE_HML, WIFI_DIRECT_API_ROLE_HML);
        if (link) {
            link->putInt(link, LI_KEY_MAX_PHYSICAL_RATE, rate);
            link->putString(link, LI_KEY_REMOTE_DEVICE, remoteDeviceId);
            link->putString(link, LI_KEY_REMOTE_BASE_MAC, remoteMac);
            ListTailInsert(linkList, &link->node);
        }
    }
    if (IsLinkModeSupportedOnCap(localCap, remoteCap, LINK_MODE_GC_GO) &&
        IsLinkModeSupportedOnRole(localMode, remoteMode, LINK_MODE_GC_GO)) {
        CLOGI(LOG_LABEL "LINK_MODE_GC_GO");
        link = LinkInfoNewWithNameAndMode(localName, remoteName, WIFI_DIRECT_API_ROLE_GC, WIFI_DIRECT_API_ROLE_GO);
        if (link) {
            link->putInt(link, LI_KEY_MAX_PHYSICAL_RATE, rate);
            link->putString(link, LI_KEY_REMOTE_DEVICE, remoteDeviceId);
            link->putString(link, LI_KEY_REMOTE_BASE_MAC, remoteMac);
            ListTailInsert(linkList, &link->node);
        }
    }
    if (IsLinkModeSupportedOnCap(localCap, remoteCap, LINK_MODE_GO_GC) &&
        IsLinkModeSupportedOnRole(localMode, remoteMode, LINK_MODE_GO_GC)) {
        CLOGI(LOG_LABEL "LINK_MODE_GO_GC");
        link = LinkInfoNewWithNameAndMode(localName, remoteName, WIFI_DIRECT_API_ROLE_GO, WIFI_DIRECT_API_ROLE_GC);
        if (link) {
            link->putInt(link, LI_KEY_MAX_PHYSICAL_RATE, rate);
            link->putString(link, LI_KEY_REMOTE_DEVICE, remoteDeviceId);
            link->putString(link, LI_KEY_REMOTE_BASE_MAC, remoteMac);
            ListTailInsert(linkList, &link->node);
        }
    }
}

static void GetAvailableLinkList(struct InterfaceInfo *localArray, size_t localSize,
                                 struct InterfaceInfo *remoteArray, size_t remoteSize, const char *remoteDeviceId,
                                 ListNode *linkList)
{
    for (size_t i = 0; i < localSize; i++) {
        struct InterfaceInfo *local = localArray + i;
        if (IsInterfaceUnavailable(local)) {
            continue;
        }
        for (size_t j = 0; j < remoteSize; j++) {
            struct InterfaceInfo *remote = remoteArray +j;
            if (IsInterfaceUnavailable(remote)) {
                continue;
            }
            AddToAvailableLinkList(local, remote, remoteDeviceId, linkList);
        }
    }
}

static bool LinkCompare(struct LinkInfo *left, struct LinkInfo *right)
{
    int32_t rate1 = left->getInt(left, LI_KEY_MAX_PHYSICAL_RATE, 0);
    int32_t rate2 = right->getInt(right, LI_KEY_MAX_PHYSICAL_RATE, 0);
    if (rate1 > rate2) {
        return true;
    }

    int32_t localMode1 = left->getInt(left, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE);
    int32_t localMode2 = right->getInt(right, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE);
    if (localMode1 == localMode2) {
        return false;
    }
    if (localMode1 == WIFI_DIRECT_API_ROLE_HML) {
        return true;
    }
    if (localMode2 == WIFI_DIRECT_API_ROLE_HML) {
        return false;
    }
    if (localMode1 == WIFI_DIRECT_API_ROLE_GC) {
        return true;
    }
    return false;
}

static void SortLinkList(ListNode *list)
{
    ListNode sortList;
    ListInit(&sortList);

    struct LinkInfo *link = NULL;
    struct LinkInfo *nextLink = NULL;
    while (!IsListEmpty(list)) {
        struct LinkInfo *first = LIST_ENTRY(GET_LIST_HEAD(list), struct LinkInfo, node);
        ListDelete(&first->node);
        struct LinkInfo *best = first;
        LIST_FOR_EACH_ENTRY_SAFE(link, nextLink, list, struct LinkInfo, node) {
            if (LinkCompare(link, best)) {
                best = link;
            }
        }
        if (best != first) {
            ListDelete(&best->node);
            ListTailInsert(&sortList, &best->node);
            ListTailInsert(list, &first->node);
        } else {
            ListTailInsert(&sortList, &first->node);
        }
    }

    LIST_FOR_EACH_ENTRY_SAFE(link, nextLink, &sortList, struct LinkInfo, node) {
        ListDelete(&link->node);
        ListTailInsert(list, &link->node);
    }
}

static void FreeLinkList(ListNode *list)
{
    struct LinkInfo *link = NULL;
    struct LinkInfo *nextLink = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(link, nextLink, list, struct LinkInfo, node) {
        ListDelete(&link->node);
        LinkInfoDestructor(link);
    }
}

static void MergeLinkList(ListNode *target, ListNode *source)
{
    struct LinkInfo *link = NULL;
    struct LinkInfo *nextLink = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(link, nextLink, source, struct LinkInfo, node) {
        ListDelete(&link->node);
        ListTailInsert(target, &link->node);
    }
}

static void GetFilterLinkList(ListNode *inList, uint32_t preferMode, bool isStrict, ListNode *outList)
{
    struct LinkInfo *link = NULL;
    struct LinkInfo *nextLink = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(link, nextLink, inList, struct LinkInfo, node) {
        bool match = false;
        if (preferMode & WIFI_DIRECT_API_ROLE_HML) {
            if (link->getInt(link, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE) == WIFI_DIRECT_API_ROLE_HML) {
                match = true;
            }
        }
        if (preferMode & WIFI_DIRECT_API_ROLE_GC) {
            if (link->getInt(link, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE) == WIFI_DIRECT_API_ROLE_GC) {
                match = true;
            }
        }
        if (preferMode & WIFI_DIRECT_API_ROLE_GO) {
            if (link->getInt(link, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE) == WIFI_DIRECT_API_ROLE_GO) {
                match = true;
            }
        }
        if (match) {
            ListDelete(&link->node);
            ListTailInsert(outList, &link->node);
        }
    }

    SortLinkList(outList);
    if (isStrict) {
        FreeLinkList(inList);
    } else {
        SortLinkList(inList);
        MergeLinkList(outList, inList);
    }
}

static int32_t ConvertLinkListToString(ListNode *list, char *string, size_t stringSize)
{
    cJSON *jsonArray = cJSON_CreateArray();
    CONN_CHECK_AND_RETURN_RET_LOG(jsonArray, SOFTBUS_MALLOC_ERR, LOG_LABEL "crate json array failed");
    struct LinkInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, list, struct LinkInfo, node) {
        cJSON *infoJsonObject = info->toJsonObject(info);
        if (infoJsonObject) {
            cJSON_AddItemToArray(jsonArray, infoJsonObject);
        }
    }

    bool ret = cJSON_PrintPreallocated(jsonArray, string, (int32_t)stringSize, false);
    CONN_CHECK_AND_RETURN_RET_LOG(ret, SOFTBUS_ERR, LOG_LABEL "copy string failed");
    cJSON_Delete(jsonArray);
    return SOFTBUS_OK;
}

static struct LinkInfo *GetFinalLinkInfo(ListNode *linkList)
{
    char linkListJsonString[LINK_LIST_STRING_MAX_SIZE] = {0};
    int32_t ret = ConvertLinkListToString(linkList, linkListJsonString, sizeof(linkListJsonString));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "convert link list to string failed");

    char result[COMMON_BUFFER_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->getRecommendChannelV2(linkListJsonString, result, sizeof(result));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get recommend channel result failed");
    CLOGD(LOG_LABEL "%s", result);

    cJSON *resultObject = cJSON_ParseWithLength(result, sizeof(result));
    CONN_CHECK_AND_RETURN_RET_LOG(resultObject, NULL, "create result json object failed");

    int32_t index = 0;
    if (!GetJsonObjectSignedNumberItem(resultObject, "KEY_INDEX", &index)) {
        CLOGE(LOG_LABEL "get index failed");
        cJSON_Delete(resultObject);
        return NULL;
    }
    CLOGI(LOG_LABEL "index=%d", index);
    int32_t recommendFreq = 0;
    if (!GetJsonObjectSignedNumberItem(resultObject, "KEY_CENTER_20M", &recommendFreq)) {
        CLOGE(LOG_LABEL "get recommend freq failed");
        cJSON_Delete(resultObject);
        return NULL;
    }

    int32_t i = 0;
    struct LinkInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, linkList, struct LinkInfo, node) {
        if (i == index) {
            ListDelete(&info->node);
            int32_t freq1 = 0;
            GetJsonObjectSignedNumberItem(resultObject, "KEY_CENTER_FREQ1", &freq1);
            int32_t freq2 = 0;
            GetJsonObjectSignedNumberItem(resultObject, "KEY_CENTER_FREQ2", &freq2);
            int32_t bw = WIFI_P2P_DEFAULT_BANDWIDTH;
            GetJsonObjectSignedNumberItem(resultObject, "KEY_BW", &bw);
            info->putInt(info, LI_KEY_CENTER_20M, recommendFreq);
            info->putInt(info, LI_KEY_CENTER_FREQUENCY1, freq1);
            info->putInt(info, LI_KEY_CENTER_FREQUENCY2, freq2);
            info->putInt(info, LI_KEY_BANDWIDTH, bw);
            CLOGI(LOG_LABEL "recommendFreq=%d freq1=%d freq2=%d bw=%d", recommendFreq, freq1, freq2, bw);
            cJSON_Delete(resultObject);
            return info;
        }
        i++;
    }

    CLOGE(LOG_LABEL "get final link info failed");
    cJSON_Delete(resultObject);
    return NULL;
}

static int32_t GetRemoteWifiConfigInfo(struct NegotiateMessage *msg, struct WifiConfigInfo *configInfo)
{
    size_t configSize = 0;
    uint8_t *config = msg->getRawData(msg, NM_KEY_WIFI_CFG_INFO, &configSize, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(configInfo, SOFTBUS_ERR, LOG_LABEL "remote config is null");

    int32_t ret = GetWifiDirectP2pAdapter()->setPeerWifiConfigInfoV2(config, configSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "set remote wifi config failed");

    ret = WifiConfigInfoConstruct(configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "create remote wifi config info failed");

    return SOFTBUS_OK;
}

static int32_t GetLocalWifiConfigInfo(struct WifiConfigInfo *configInfo)
{
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, "get local wifi config failed");

    ret = WifiConfigInfoConstruct(configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "create local wifi config info failed");

    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, IF_NAME_WLAN);
    info.putRawData(&info, II_KEY_WIFI_CFG_INFO, config, configSize);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);

    return SOFTBUS_OK;
}

static int32_t MergeRemoteInterfaceInfo(struct WifiConfigInfo *configInfo, struct NegotiateMessage *msg,
                                        struct InterfaceInfo **interfaceInfoArray, size_t *interfaceInfoArraySize)
{
    *interfaceInfoArray =
        configInfo->getContainerArray(configInfo, WC_KEY_INTERFACE_INFO_ARRAY, interfaceInfoArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(*interfaceInfoArray, SOFTBUS_ERR, LOG_LABEL "get config interface info array failed");

    size_t msgInfoArraySize = 0;
    struct InterfaceInfo *msgInfoArray = msg->getContainerArray(msg, NM_KEY_INTERFACE_INFO_ARRAY, &msgInfoArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(msgInfoArray, SOFTBUS_ERR, LOG_LABEL "get interface info array failed");

    MergeInterfaceInfo(*interfaceInfoArray, *interfaceInfoArraySize, msgInfoArray, msgInfoArraySize);
    return SOFTBUS_OK;
}

static int32_t MergeLocalInterfaceInfo(struct WifiConfigInfo *configInfo, struct InterfaceInfo **interfaceInfoArray,
                                       size_t *interfaceInfoArraySize)
{
    *interfaceInfoArray =
        configInfo->getContainerArray(configInfo, WC_KEY_INTERFACE_INFO_ARRAY, interfaceInfoArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(*interfaceInfoArray, SOFTBUS_ERR, LOG_LABEL "get config interface info array failed");

    int32_t infoArraySize = 0;
    struct InterfaceInfo *infoArray = NULL;
    int32_t ret = GetResourceManager()->getAllInterfacesInfo(&infoArray, &infoArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "get interface info array failed");

    MergeInterfaceInfo(*interfaceInfoArray, *interfaceInfoArraySize, infoArray, infoArraySize);
    InterfaceInfoDeleteArray(infoArray, infoArraySize);
    return SOFTBUS_OK;
}

static struct LinkInfo* CreateLinkInfo(struct NegotiateMessage *msg)
{
    struct LinkInfo *finalLink = NULL;
    struct WifiConfigInfo remoteConfigInfo;
    remoteConfigInfo.msg = msg;
    int32_t ret = GetRemoteWifiConfigInfo(msg, &remoteConfigInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, NULL, LOG_LABEL "get remote config info failed");

    struct WifiConfigInfo localConfigInfo;
    localConfigInfo.msg = msg;
    if (GetLocalWifiConfigInfo(&localConfigInfo) != SOFTBUS_OK) {
        goto OUT1;
    }

    size_t remoteArraySize = 0;
    struct InterfaceInfo *remoteArray = NULL;
    if (MergeRemoteInterfaceInfo(&remoteConfigInfo, msg, &remoteArray, &remoteArraySize) != SOFTBUS_OK) {
        goto OUT2;
    }

    size_t localArraySize = 0;
    struct InterfaceInfo *localArray = NULL;
    if (MergeLocalInterfaceInfo(&localConfigInfo, &localArray, &localArraySize) != SOFTBUS_OK) {
        goto OUT2;
    }

    ListNode availableLinkList;
    ListInit(&availableLinkList);
    char *remoteDevice = remoteConfigInfo.getString(&remoteConfigInfo, WC_KEY_DEVICE_ID, "");
    GetAvailableLinkList(localArray, localArraySize, remoteArray, remoteArraySize, remoteDevice, &availableLinkList);
    if (IsListEmpty(&availableLinkList)) {
        CLOGE(LOG_LABEL "availableLinkList empty");
        goto OUT2;
    }
    GetWifiDirectUtils()->showLinkInfoList("availableLinkList", &availableLinkList);

    ListNode filterLinkList;
    ListInit(&filterLinkList);
    int32_t remotePreferRole = msg->getInt(msg, NM_KEY_PREFER_LINK_MODE, WIFI_DIRECT_API_ROLE_NONE);
    bool isStrict = msg->getBoolean(msg, NM_KEY_IS_MODE_STRICT, false);
    CLOGI(LOG_LABEL "remotePreferRole=%d isStrict=%d", remotePreferRole, isStrict);
    GetFilterLinkList(&availableLinkList, remotePreferRole, isStrict, &filterLinkList);
    if (IsListEmpty(&filterLinkList)) {
        CLOGE(LOG_LABEL "filterLinkList empty");
        goto OUT2;
    }

    GetWifiDirectUtils()->showLinkInfoList("filterLinkList", &filterLinkList);
    finalLink = GetFinalLinkInfo(&filterLinkList);
    FreeLinkList(&filterLinkList);

OUT2:
    WifiConfigInfoDestruct(&localConfigInfo);
OUT1:
    WifiConfigInfoDestruct(&remoteConfigInfo);
    return finalLink;
}

/* static public method */
static struct WifiDirectDecisionCenter g_decisionCenter = {
    .getProtocol = GetProtocol,
    .putProtocol = PutProtocol,
    .getProcessorByNegoChannel = GetProcessorByNegoChannel,
    .getProcessorByNegoChannelAndConnectType = GetProcessorByNegoChannelAndConnectType,
    .getProcessorByNegotiateMessage = GetProcessorByNegotiateMessage,
};

struct WifiDirectDecisionCenter *GetWifiDirectDecisionCenter(void)
{
    return &g_decisionCenter;
}