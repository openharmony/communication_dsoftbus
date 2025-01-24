/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "disc_manager.h"
#include "bus_center_event.h"
#include "common_list.h"
#include "disc_ble_dispatcher.h"
#include "disc_coap.h"
#include "disc_event.h"
#include "disc_log.h"
#include "disc_usb_dispatcher.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "lnn_devicename_info.h"
#include "softbus_utils.h"

#define DEVICE_TYPE_SIZE_MAX 3
#define DUMP_STR_LEN 256
#define DISC_INFO_LIST_SIZE_MAX 50
#define DISPLAY_NAME_BUF_LEN 128
#define DISPLAY_NAME_LEN_24 24
#define DISPLAY_NAME_LEN_21 21
#define DISPLAY_NAME_LEN_18 18
#define JSON_KEY_RAW_NAME        "raw"
#define JSON_KEY_NAME_LEN_24     "name24"
#define JSON_KEY_NAME_LEN_21     "name21"
#define JSON_KEY_NAME_LEN_18     "name18"

static bool g_isInited = false;

static SoftBusList *g_publishInfoList = NULL;
static SoftBusList *g_discoveryInfoList = NULL;

static DiscoveryFuncInterface *g_discCoapInterface = NULL;
static DiscoveryFuncInterface *g_discBleInterface = NULL;
static DiscoveryFuncInterface *g_discUsbInterface = NULL;

static DiscInnerCallback g_discMgrMediumCb;

static ListNode g_capabilityList[CAPABILITY_MAX_BITNUM];

typedef struct {
    char raw[DISPLAY_NAME_BUF_LEN];
    char name18[DISPLAY_NAME_LEN_18 + 1];
    char name21[DISPLAY_NAME_LEN_21 + 1];
    char name24[DISPLAY_NAME_LEN_24 + 1];
} DisplayNameList;

static DisplayNameList g_displayName = { 0 };

static const char *g_discModuleMap[] = {
    "MODULE_LNN",
    "MODULE_CONN",
};

typedef enum {
    MIN_SERVICE = 0,
    PUBLISH_SERVICE = MIN_SERVICE,
    PUBLISH_INNER_SERVICE = 1,
    SUBSCRIBE_SERVICE = 2,
    SUBSCRIBE_INNER_SERVICE = 3,
    MAX_SERVICE = SUBSCRIBE_INNER_SERVICE,
} ServiceType;

typedef union {
    PublishOption publishOption;
    SubscribeOption subscribeOption;
} InnerOption;

typedef union  {
    IServerDiscInnerCallback serverCb;
    DiscInnerCallback innerCb;
} InnerCallback;

typedef struct {
    ListNode node;
    char packageName[PKG_NAME_SIZE_MAX];
    InnerCallback callback;
    uint32_t infoNum;
    ListNode InfoList;
} DiscItem;

typedef struct {
    ListNode node;
    int32_t id;
    DiscoverMode mode;
    ExchangeMedium medium;
    ListNode capNode;
    DiscItem *item;
    DiscoveryStatistics statistics;
    InnerOption option;
} DiscInfo;

typedef struct {
    ListNode node;
    int32_t id;
    char *pkgName;
} IdContainer;

#define DFX_RECORD_DISC_CALL_START(infoNode, packageName, interfaceType)   \
    do {                                                                   \
        DiscEventExtra extra = { 0 };                                      \
        DiscEventExtraInit(&extra);                                        \
        BuildDiscCallEvent(&extra, infoNode, packageName, interfaceType);  \
        DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_CALL_INTERFACE, extra);   \
    } while (0)

static void UpdateDiscEventAndReport(DiscEventExtra *extra, const DeviceInfo *device)
{
    if (device == NULL) {
        DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_DEVICE_FOUND, *extra);
        DISC_LOGI(DISC_CONTROL, "device info is null");
        return;
    }
    if (device->addrNum <= CONNECTION_ADDR_WLAN || device->addrNum > CONNECTION_ADDR_MAX) {
        DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_DEVICE_FOUND, *extra);
        DISC_LOGI(DISC_CONTROL, "unknown device info");
        return;
    }

    for (uint32_t i = 0; i < device->addrNum; i++) {
        switch (device->addr[i].type) {
            case CONNECTION_ADDR_BR:
                extra->peerBrMac = device->addr[i].info.br.brMac;
                break;
            case CONNECTION_ADDR_BLE:
                extra->peerBleMac = device->addr[i].info.ble.bleMac;
                break;
            case CONNECTION_ADDR_WLAN:
                /* fall-through */
            case CONNECTION_ADDR_ETH:
                extra->peerIp = device->addr[i].info.ip.ip;
                break;
            default:
                DISC_LOGI(DISC_CONTROL, "unknown param type!");
                break;
        }
    }

    char *deviceType = SoftBusCalloc(DEVICE_TYPE_SIZE_MAX + 1);
    DISC_CHECK_AND_RETURN_LOGE(deviceType != NULL, DISC_CONTROL, "SoftBusCalloc failed");
    if (snprintf_s(deviceType, DEVICE_TYPE_SIZE_MAX + 1, DEVICE_TYPE_SIZE_MAX, "%03X", device->devType) >= 0) {
        extra->peerDeviceType = deviceType;
    }
    DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_DEVICE_FOUND, *extra);
    SoftBusFree(deviceType);
    extra->peerDeviceType = NULL;
}

static void DfxRecordStartDiscoveryDevice(DiscInfo *infoNode)
{
    infoNode->statistics.startTime = SoftBusGetSysTimeMs();
    infoNode->statistics.repTimes = 0;
    infoNode->statistics.devNum = 0;
    infoNode->statistics.discTimes = 0;
}

static void UpdateDdmpStartDiscoveryTime(DiscInfo *info)
{
    if (info->medium != AUTO && info->medium != COAP) {
        DISC_LOGD(DISC_CONTROL, "no need update ddmp start discovery time");
        return;
    }

    DiscInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &(g_capabilityList[DDMP_CAPABILITY_BITMAP]), DiscInfo, capNode) {
        if (infoNode->statistics.repTimes == 0) {
            DISC_LOGD(DISC_CONTROL, "update ddmp callback id=%{public}d", infoNode->id);
            infoNode->statistics.startTime = info->statistics.startTime;
        }
    }
}

static void DfxRecordDeviceFound(DiscInfo *infoNode, const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    DISC_LOGD(DISC_CONTROL, "record device found");
    if (infoNode->statistics.repTimes == 0) {
        uint64_t costTime = 0;
        uint64_t sysTime = SoftBusGetSysTimeMs();
        if (sysTime >= infoNode->statistics.startTime) {
            costTime = sysTime - infoNode->statistics.startTime;
        } else {
            DISC_LOGE(DISC_CONTROL, "CurTime < startTime");
        }
        SoftbusRecordFirstDiscTime((SoftBusDiscMedium)additions->medium, costTime);
        DiscEventExtra extra = { 0 };
        DiscEventExtraInit(&extra);
        extra.discMode = infoNode == NULL ? 0 : infoNode->mode;
        extra.discType = additions == NULL ? 0 : additions->medium + 1;
        extra.costTime = (int32_t)costTime;
        extra.result = EVENT_STAGE_RESULT_OK;
        UpdateDiscEventAndReport(&extra, device);
    }
    infoNode->statistics.repTimes++;
    infoNode->statistics.devNum++;
}

static void DfxRecordStopDiscoveryDevice(const char *packageName, DiscInfo *infoNode)
{
    DiscoveryStatistics *statistics = &infoNode->statistics;
    uint64_t totalTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordBleDiscDetails((char *)packageName, totalTime, statistics->repTimes, statistics->devNum,
                                statistics->discTimes);
}

static void BitmapSet(uint32_t *bitMap, uint32_t pos)
{
    *bitMap |= 1U << pos;
}

static bool IsBitmapSet(const uint32_t *bitMap, uint32_t pos)
{
    return ((1U << pos) & (*bitMap)) ? true : false;
}

static void BuildDiscCallEvent(DiscEventExtra *extra, const DiscInfo *info, const char *packageName,
    const InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_LOGE(extra != NULL, DISC_CONTROL, "discEventExtra is null");

    if (info != NULL) {
        extra->discType = info->medium + 1;
        extra->discMode = info->mode;
    }
    if (IsValidString(packageName, PKG_NAME_SIZE_MAX - 1)) {
        extra->callerPkg = packageName;
    }
    extra->interFuncType = type + 1;
}

static int32_t CallSpecificInterfaceFunc(const InnerOption *option,
    const DiscoveryFuncInterface *interface, const DiscoverMode mode, InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL,
        DISC_CONTROL, "interface is null");
    switch (type) {
        case PUBLISH_FUNC:
            return ((mode == DISCOVER_MODE_ACTIVE) ? (interface->Publish(&(option->publishOption))) :
                (interface->StartScan(&(option->publishOption))));
        case UNPUBLISH_FUNC:
            return ((mode == DISCOVER_MODE_ACTIVE) ? (interface->Unpublish(&(option->publishOption))) :
                (interface->StopScan(&(option->publishOption))));
        case STARTDISCOVERTY_FUNC:
            return ((mode == DISCOVER_MODE_ACTIVE) ? (interface->StartAdvertise(&(option->subscribeOption))) :
                (interface->Subscribe(&(option->subscribeOption))));
        case STOPDISCOVERY_FUNC:
            return ((mode == DISCOVER_MODE_ACTIVE) ? (interface->StopAdvertise(&(option->subscribeOption))) :
                (interface->Unsubscribe(&(option->subscribeOption))));
        default:
            return SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL;
    }
}

static void DfxCallInterfaceByMedium(
    const DiscInfo *infoNode, const char *packageName, const InterfaceFuncType type, int32_t reason)
{
    DiscEventExtra extra = {0};
    DiscEventExtraInit(&extra);
    extra.errcode = reason;
    BuildDiscCallEvent(&extra, infoNode, packageName, type);
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_CALL_INTERFACE, extra);
}

static int32_t CallInterfaceByMedium(const DiscInfo *info, const char *packageName, const InterfaceFuncType type)
{
    int32_t ret = SOFTBUS_OK;
    switch (info->medium) {
        case COAP:
            ret = CallSpecificInterfaceFunc(&(info->option), g_discCoapInterface, info->mode, type);
            DfxCallInterfaceByMedium(info, packageName, type, ret);
            return ret;
        case BLE:
            ret = CallSpecificInterfaceFunc(&(info->option), g_discBleInterface, info->mode, type);
            DfxCallInterfaceByMedium(info, packageName, type, ret);
            return ret;
        case AUTO: {
            int32_t coapRet = CallSpecificInterfaceFunc(&(info->option), g_discCoapInterface, info->mode, type);
            DfxCallInterfaceByMedium(info, packageName, type, coapRet);
            int32_t bleRet = CallSpecificInterfaceFunc(&(info->option), g_discBleInterface, info->mode, type);
            DfxCallInterfaceByMedium(info, packageName, type, bleRet);

            DISC_CHECK_AND_RETURN_RET_LOGE(coapRet == SOFTBUS_OK || bleRet == SOFTBUS_OK,
                SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL, DISC_CONTROL, "all medium failed");
            return SOFTBUS_OK;
        }
        case USB:
            ret = CallSpecificInterfaceFunc(&(info->option), g_discUsbInterface, info->mode, type);
            DfxCallInterfaceByMedium(info, packageName, type, ret);
            return ret;
        default:
            return SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL;
    }
}

static int32_t TransferStringCapToBitmap(const char *capability)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(capability != NULL, SOFTBUS_DISCOVER_MANAGER_CAPABILITY_INVALID,
        DISC_CONTROL, "capability is null");

    for (uint32_t i = 0; i < sizeof(g_capabilityMap) / sizeof(g_capabilityMap[0]); i++) {
        if (strcmp(capability, g_capabilityMap[i].capability) == 0) {
            DISC_LOGD(DISC_CONTROL, "capability=%{public}s", capability);
            return g_capabilityMap[i].bitmap;
        }
    }

    return SOFTBUS_DISCOVER_MANAGER_CAPABILITY_INVALID;
}

static void AddDiscInfoToCapabilityList(DiscInfo *info, const ServiceType type)
{
    if (type != SUBSCRIBE_SERVICE && type != SUBSCRIBE_INNER_SERVICE) {
        DISC_LOGD(DISC_CONTROL, "publish no need to add");
        return;
    }

    for (uint32_t tmp = 0; tmp < CAPABILITY_MAX_BITNUM; tmp++) {
        if (IsBitmapSet(&(info->option.subscribeOption.capabilityBitmap[0]), tmp) == true) {
            if (type == SUBSCRIBE_SERVICE) {
                ListTailInsert(&(g_capabilityList[tmp]), &(info->capNode));
            } else {
                ListNodeInsert(&(g_capabilityList[tmp]), &(info->capNode));
            }
            break;
        }
    }
}

static void RemoveDiscInfoFromCapabilityList(DiscInfo *info, const ServiceType type)
{
    if (type != SUBSCRIBE_SERVICE && type != SUBSCRIBE_INNER_SERVICE) {
        DISC_LOGD(DISC_CONTROL, "publish no need to delete");
        return;
    }
    ListDelete(&(info->capNode));
}

static void FreeDiscInfo(DiscInfo *info, const ServiceType type)
{
    if ((type == PUBLISH_SERVICE) || (type == PUBLISH_INNER_SERVICE)) {
        SoftBusFree(info->option.publishOption.capabilityData);
        info->option.publishOption.capabilityData = NULL;
    }

    if ((type == SUBSCRIBE_SERVICE) || (type == SUBSCRIBE_INNER_SERVICE)) {
        SoftBusFree(info->option.subscribeOption.capabilityData);
        info->option.subscribeOption.capabilityData = NULL;
    }
    SoftBusFree(info);
    info = NULL;
}

static bool IsInnerModule(const DiscInfo *infoNode)
{
    for (uint32_t i = 0; i < MODULE_MAX; i++) {
        DISC_LOGD(DISC_CONTROL, "packageName=%{public}s", infoNode->item->packageName);
        if (strcmp(infoNode->item->packageName, g_discModuleMap[i]) == 0) {
            DISC_LOGD(DISC_CONTROL, "true");
            return true;
        }
    }
    DISC_LOGD(DISC_CONTROL, "false");
    return false;
}

static void InnerDeviceFound(DiscInfo *infoNode, const DeviceInfo *device,
                                                const InnerDeviceInfoAddtions *additions)
{
    if (infoNode->item != NULL && infoNode->item->callback.serverCb.OnServerDeviceFound != NULL &&
        !IsInnerModule(infoNode)) {
        (void)infoNode->item->callback.serverCb.OnServerDeviceFound(infoNode->item->packageName, device, additions);
        return;
    }

    DISC_LOGD(DISC_CONTROL, "call from inner module.");
    if (infoNode->item != NULL && infoNode->item->callback.innerCb.OnDeviceFound != NULL) {
        DfxRecordDeviceFound(infoNode, device, additions);
        infoNode->item->callback.innerCb.OnDeviceFound(device, additions);
    }
}

static void DiscOnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    DISC_CHECK_AND_RETURN_LOGE(device != NULL, DISC_CONTROL, "device is null");
    DISC_CHECK_AND_RETURN_LOGE(additions != NULL, DISC_CONTROL, "additions is null");

    DISC_LOGD(DISC_CONTROL,
        "capabilityBitmap=%{public}d, medium=%{public}d", device->capabilityBitmap[0], additions->medium);
    for (uint32_t tmp = 0; tmp < CAPABILITY_MAX_BITNUM; tmp++) {
        if (IsBitmapSet((uint32_t *)device->capabilityBitmap, tmp) == false) {
            continue;
        }

        if (SoftBusMutexLock(&(g_discoveryInfoList->lock)) != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "lock failed");
            return;
        }
        DiscInfo *infoNode = NULL;
        LIST_FOR_EACH_ENTRY(infoNode, &(g_capabilityList[tmp]), DiscInfo, capNode) {
            DISC_LOGD(DISC_CONTROL, "find callback id=%{public}d", infoNode->id);
            infoNode->statistics.discTimes++;
            InnerDeviceFound(infoNode, device, additions);
        }
        (void)SoftBusMutexUnlock(&(g_discoveryInfoList->lock));
    }
}

static int32_t CheckPublishInfo(const PublishInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_PASSIVE || info->mode == DISCOVER_MODE_ACTIVE,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->medium >= AUTO && info->medium <= COAP,
        SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM, DISC_CONTROL, "mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->freq >= LOW && info->freq < FREQ_BUTT,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "freq is invalid");

    if (info->capabilityData == NULL) {
        if (info->dataLen == 0) {
            return SOFTBUS_OK;
        } else {
            DISC_LOGE(DISC_CONTROL, "capabilityData is NULL, dataLen != 0");
            return SOFTBUS_INVALID_PARAM;
        }
    } else {
        if (info->dataLen == 0) {
            DISC_LOGE(DISC_CONTROL, "capabilityData is not NULL, dataLen == 0");
            return SOFTBUS_INVALID_PARAM;
        }
        if (info->dataLen > MAX_CAPABILITYDATA_LEN) {
            DISC_LOGE(DISC_CONTROL, "dataLen > max length. dataLen=%{public}u", info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
        uint32_t len = strlen((char *)info->capabilityData);
        if (info->capabilityData[info->dataLen] != '\0') {
            DISC_LOGE(DISC_CONTROL, "capabilityData is not c-string format: len=%{public}u, dataLen=%{public}u",
                len, info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
        if (len != info->dataLen) {
            DISC_LOGE(DISC_CONTROL, "capabilityData len != dataLen. len=%{public}u, dataLen=%{public}u",
                len, info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    return SOFTBUS_OK;
}

static int32_t CheckSubscribeInfo(const SubscribeInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_PASSIVE || info->mode == DISCOVER_MODE_ACTIVE,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->medium >= AUTO && info->medium <= USB,
        SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM, DISC_CONTROL, "medium is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->freq >= LOW && info->freq < FREQ_BUTT,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "freq is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(!(info->medium == USB && info->mode == DISCOVER_MODE_ACTIVE),
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "usb is not support active mode");

    if (info->capabilityData == NULL) {
        if (info->dataLen == 0) {
            return SOFTBUS_OK;
        } else {
            DISC_LOGE(DISC_CONTROL, "capabilityData is NULL, dataLen != 0");
            return SOFTBUS_INVALID_PARAM;
        }
    } else {
        if (info->dataLen == 0) {
            DISC_LOGE(DISC_CONTROL, "capabilityData is not NULL, dataLen == 0");
            return SOFTBUS_INVALID_PARAM;
        }
        if (info->dataLen > MAX_CAPABILITYDATA_LEN) {
            DISC_LOGE(DISC_CONTROL, "dataLen > max length. dataLen=%{public}u", info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
        uint32_t len = strlen((char *)info->capabilityData);
        if (info->capabilityData[info->dataLen] != '\0') {
            DISC_LOGE(DISC_CONTROL, "capabilityData is not c-string format: len=%{public}u, dataLen=%{public}u",
                len, info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
        if (len != info->dataLen) {
            DISC_LOGE(DISC_CONTROL, "capabilityData len != dataLen. len=%{public}u, dataLen=%{public}u",
                len, info->dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    return SOFTBUS_OK;
}

static void SetDiscItemCallback(DiscItem *itemNode, const InnerCallback *cb, const ServiceType type)
{
    if ((type != SUBSCRIBE_INNER_SERVICE && type != SUBSCRIBE_SERVICE) || cb == NULL) {
        return;
    }
    if (type == SUBSCRIBE_SERVICE) {
        itemNode->callback.serverCb.OnServerDeviceFound = cb->serverCb.OnServerDeviceFound;
        return;
    }
    if ((itemNode->callback.innerCb.OnDeviceFound != NULL) && (cb->innerCb.OnDeviceFound == NULL)) {
        return;
    }
    itemNode->callback.innerCb.OnDeviceFound = cb->innerCb.OnDeviceFound;
}

static DiscItem *CreateDiscItem(SoftBusList *serviceList, const char *packageName, const InnerCallback *cb,
                                const ServiceType type)
{
    DiscItem *itemNode = (DiscItem *)SoftBusCalloc(sizeof(DiscItem));
    DISC_CHECK_AND_RETURN_RET_LOGE(itemNode != NULL, NULL, DISC_CONTROL, "calloc item node failed");

    if (strcpy_s(itemNode->packageName, PKG_NAME_SIZE_MAX, packageName) != EOK) {
        SoftBusFree(itemNode);
        return NULL;
    }

    if ((type == PUBLISH_INNER_SERVICE) || (type == SUBSCRIBE_INNER_SERVICE)) {
        ListNodeInsert(&(serviceList->list), &(itemNode->node));
    } else if ((type == PUBLISH_SERVICE) || (type == SUBSCRIBE_SERVICE)) {
        ListTailInsert(&(serviceList->list), &(itemNode->node));
    }

    SetDiscItemCallback(itemNode, cb, type);

    serviceList->cnt++;
    ListInit(&(itemNode->InfoList));
    return itemNode;
}

static DiscInfo *CreateDiscInfoForPublish(const PublishInfo *info)
{
    DiscInfo *infoNode = (DiscInfo *)SoftBusCalloc(sizeof(DiscInfo));
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, NULL, DISC_CONTROL, "calloc info node failed");

    ListInit(&(infoNode->node));
    ListInit(&(infoNode->capNode));

    infoNode->id = info->publishId;
    infoNode->medium = info->medium;
    infoNode->mode = info->mode;

    PublishOption *option = &infoNode->option.publishOption;
    option->freq = info->freq;
    option->ranging = info->ranging;
    option->dataLen = info->dataLen;

    if (info->dataLen != 0) {
        option->capabilityData = (uint8_t *)SoftBusCalloc(info->dataLen + 1);
        if (option->capabilityData == NULL) {
            DISC_LOGE(DISC_CONTROL, "alloc capability data failed");
            SoftBusFree(infoNode);
            return NULL;
        }
        if (memcpy_s(option->capabilityData, info->dataLen, info->capabilityData, info->dataLen) != EOK) {
            DISC_LOGE(DISC_CONTROL, "memcpy_s failed");
            FreeDiscInfo(infoNode, PUBLISH_SERVICE);
            return NULL;
        }
    }

    int32_t bitmap = TransferStringCapToBitmap(info->capability);
    if (bitmap < 0) {
        DISC_LOGE(DISC_CONTROL, "capability not found");
        FreeDiscInfo(infoNode, PUBLISH_SERVICE);
        return NULL;
    }
    BitmapSet(option->capabilityBitmap, (uint32_t)bitmap);

    return infoNode;
}

static DiscInfo *CreateDiscInfoForSubscribe(const SubscribeInfo *info)
{
    DiscInfo *infoNode = (DiscInfo *)SoftBusCalloc(sizeof(DiscInfo));
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, NULL, DISC_CONTROL, "alloc info node failed");

    ListInit(&(infoNode->node));
    ListInit(&(infoNode->capNode));

    infoNode->id = info->subscribeId;
    infoNode->medium = info->medium;
    infoNode->mode = info->mode;

    SubscribeOption *option = &infoNode->option.subscribeOption;
    option->freq = info->freq;
    option->dataLen = info->dataLen;
    option->isSameAccount = info->isSameAccount;
    option->isWakeRemote = info->isWakeRemote;

    if (info->dataLen != 0) {
        option->capabilityData = (uint8_t *)SoftBusCalloc(info->dataLen + 1);
        if (option->capabilityData == NULL) {
            DISC_LOGE(DISC_CONTROL, "alloc capability data failed");
            SoftBusFree(infoNode);
            return NULL;
        }
        if (memcpy_s(option->capabilityData, info->dataLen, info->capabilityData, info->dataLen) != EOK) {
            DISC_LOGE(DISC_CONTROL, "memcpy_s failed");
            FreeDiscInfo(infoNode, SUBSCRIBE_SERVICE);
            return NULL;
        }
    }

    int32_t bimap = TransferStringCapToBitmap(info->capability);
    if (bimap < 0) {
        DISC_LOGE(DISC_CONTROL, "capability not found");
        FreeDiscInfo(infoNode, SUBSCRIBE_SERVICE);
        return NULL;
    }
    BitmapSet(option->capabilityBitmap, (uint32_t)bimap);
    DfxRecordStartDiscoveryDevice(infoNode);
    return infoNode;
}

static void DumpDiscInfoList(const DiscItem *itemNode)
{
    char dumpStr[DUMP_STR_LEN] = {0};
    int32_t dumpStrPos = 0;
    int32_t itemStrLen = 0;
    DiscInfo *infoNode = NULL;

    LIST_FOR_EACH_ENTRY(infoNode, &(itemNode->InfoList), DiscInfo, node) {
        itemStrLen = sprintf_s(&dumpStr[dumpStrPos], DUMP_STR_LEN - dumpStrPos, "%d,", infoNode->id);
        if (itemStrLen <= 0) {
            DISC_LOGI(DISC_CONTROL, "info id=%{public}s", dumpStr);
            dumpStrPos = 0;
            itemStrLen = sprintf_s(&dumpStr[dumpStrPos], DUMP_STR_LEN - dumpStrPos, "%d,", infoNode->id);
            DISC_CHECK_AND_RETURN_LOGW(itemStrLen > 0, DISC_CONTROL, "sprintf_s failed");
        }
        dumpStrPos += itemStrLen;
    }

    if (dumpStrPos > 0) {
        DISC_LOGI(DISC_CONTROL, "info id=%{public}s", dumpStr);
    }
}

static int32_t AddDiscInfoToList(SoftBusList *serviceList, const char *packageName, const InnerCallback *cb,
                                 DiscInfo *info, ServiceType type)
{
    bool isDumpable = (strcmp(g_discModuleMap[0], packageName) != 0);
    if (isDumpable) {
        DISC_LOGI(DISC_CONTROL, "packageName=%{public}s, id=%{public}d", packageName, info->id);
    }

    DiscItem *itemNode = NULL;
    bool exist = false;
    LIST_FOR_EACH_ENTRY(itemNode, &(serviceList->list), DiscItem, node) {
        if (strcmp(itemNode->packageName, packageName) != 0) {
            continue;
        }

        if (isDumpable) {
            DumpDiscInfoList(itemNode);
        }

        DiscInfo *infoNode = NULL;
        LIST_FOR_EACH_ENTRY(infoNode, &(itemNode->InfoList), DiscInfo, node) {
            if (infoNode->id == info->id) {
                DISC_LOGI(DISC_CONTROL, "id already existed");
                return SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM;
            }
        }
        DISC_CHECK_AND_RETURN_RET_LOGE(
            itemNode->infoNum < DISC_INFO_LIST_SIZE_MAX, SOFTBUS_DISCOVER_MANAGER_ID_MAX_ERR,
            DISC_CONTROL, "infolist size limit reached, packageName=%{public}s", packageName);

        SetDiscItemCallback(itemNode, cb, type);
        exist = true;
        itemNode->infoNum++;
        info->item = itemNode;
        ListTailInsert(&(itemNode->InfoList), &(info->node));
        AddDiscInfoToCapabilityList(info, type);
        break;
    }

    if (exist == false) {
        itemNode = CreateDiscItem(serviceList, packageName, cb, type);
        if (itemNode == NULL) {
            DISC_LOGE(DISC_CONTROL, "itemNode create failed");
            return SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE;
        }

        itemNode->infoNum++;
        info->item = itemNode;
        ListTailInsert(&(itemNode->InfoList), &(info->node));
        AddDiscInfoToCapabilityList(info, type);
    }

    return SOFTBUS_OK;
}

static int32_t AddDiscInfoToPublishList(const char *packageName, const InnerCallback *cb, DiscInfo *info,
                                        ServiceType type)
{
    return AddDiscInfoToList(g_publishInfoList, packageName, cb, info, type);
}

static int32_t AddDiscInfoToDiscoveryList(const char *packageName, const InnerCallback *cb, DiscInfo *info,
                                          ServiceType type)
{
    return AddDiscInfoToList(g_discoveryInfoList, packageName, cb, info, type);
}

static DiscInfo *RemoveInfoFromList(SoftBusList *serviceList, const char *packageName, const int32_t id,
                                    const ServiceType type)
{
    bool isDumpable = (strcmp(g_discModuleMap[0], packageName) != 0);
    if (isDumpable) {
        DISC_LOGI(DISC_CONTROL, "packageName=%{public}s, id=%{public}d", packageName, id);
    }

    bool isIdExist = false;
    DiscItem *itemNode = NULL;
    DiscInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(itemNode, &(serviceList->list), DiscItem, node) {
        if (strcmp(itemNode->packageName, packageName) != 0) {
            continue;
        }

        if (isDumpable) {
            DumpDiscInfoList(itemNode);
        }

        if (itemNode->infoNum == 0) {
            serviceList->cnt--;
            ListDelete(&(itemNode->node));
            SoftBusFree(itemNode);
            return NULL;
        }

        LIST_FOR_EACH_ENTRY(infoNode, &(itemNode->InfoList), DiscInfo, node) {
            if (infoNode->id != id) {
                continue;
            }
            isIdExist = true;
            itemNode->infoNum--;
            RemoveDiscInfoFromCapabilityList(infoNode, type);
            ListDelete(&(infoNode->node));

            if (itemNode->infoNum == 0) {
                serviceList->cnt--;
                ListDelete(&(itemNode->node));
                SoftBusFree(itemNode);
            }
            break;
        }
        break;
    }

    if (isIdExist == false) {
        DISC_LOGD(DISC_CONTROL, "can not find publishId");
        return NULL;
    }
    return infoNode;
}

static DiscInfo *RemoveInfoFromPublishList(const char *packageName, const int32_t id, const ServiceType type)
{
    return RemoveInfoFromList(g_publishInfoList, packageName, id, type);
}

static DiscInfo *RemoveInfoFromDiscoveryList(const char *packageName, const int32_t id, const ServiceType type)
{
    return RemoveInfoFromList(g_discoveryInfoList, packageName, id, type);
}

static int32_t InnerPublishService(const char *packageName, DiscInfo *info, const ServiceType type)
{
    int32_t ret = SoftBusMutexLock(&g_publishInfoList->lock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_CONTROL, "lock failed");

    do {
        ret = AddDiscInfoToPublishList(packageName, NULL, info, type);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "add info to list failed");
            break;
        }

        DFX_RECORD_DISC_CALL_START(info, packageName, PUBLISH_FUNC);
        ret = CallInterfaceByMedium(info, packageName, PUBLISH_FUNC);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "call interface by medium failed");
            ListDelete(&(info->node));
            info->item->infoNum--;
        }
    } while (false);

    SoftBusMutexUnlock(&g_publishInfoList->lock);
    return ret;
}

static int32_t InnerUnPublishService(const char *packageName, int32_t publishId, const ServiceType type)
{
    int32_t ret = SoftBusMutexLock(&g_publishInfoList->lock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_CONTROL, "lock failed");

    DiscInfo *infoNode = NULL;
    do {
        infoNode = RemoveInfoFromPublishList(packageName, publishId, type);
        if (infoNode == NULL) {
            DISC_LOGE(DISC_CONTROL, "delete info from list failed");
            ret = SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE;
            break;
        }

        DFX_RECORD_DISC_CALL_START(infoNode, packageName, UNPUBLISH_FUNC);
        ret = CallInterfaceByMedium(infoNode, packageName, UNPUBLISH_FUNC);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "call interface by medium failed");
        }
        FreeDiscInfo(infoNode, type);
    } while (false);

    SoftBusMutexUnlock(&g_publishInfoList->lock);
    return ret;
}

static int32_t InnerStartDiscovery(const char *packageName, DiscInfo *info, const IServerDiscInnerCallback *cb,
                                   const ServiceType type)
{
    InnerCallback callback;
    callback.serverCb.OnServerDeviceFound = NULL;
    if (cb != NULL) {
        callback.serverCb.OnServerDeviceFound = cb->OnServerDeviceFound;
    }

    int32_t ret = SoftBusMutexLock(&g_discoveryInfoList->lock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_CONTROL, "lock failed");

    do {
        ret = AddDiscInfoToDiscoveryList(packageName, &callback, info, type);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "add info to list failed");
            break;
        }

        UpdateDdmpStartDiscoveryTime(info);
        DFX_RECORD_DISC_CALL_START(info, packageName, STARTDISCOVERTY_FUNC);
        ret = CallInterfaceByMedium(info, packageName, STARTDISCOVERTY_FUNC);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "call interface by medium failed");
            RemoveDiscInfoFromCapabilityList(info, type);
            ListDelete(&(info->node));
            info->item->infoNum--;
        }
    } while (false);

    SoftBusMutexUnlock(&g_discoveryInfoList->lock);
    return ret;
}

static int32_t InnerStopDiscovery(const char *packageName, int32_t subscribeId, const ServiceType type)
{
    int32_t ret = SoftBusMutexLock(&g_discoveryInfoList->lock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_CONTROL, "lock failed");

    DiscInfo *infoNode = NULL;
    do {
        infoNode = RemoveInfoFromDiscoveryList(packageName, subscribeId, type);
        if (infoNode == NULL) {
            DISC_LOGE(DISC_CONTROL, "delete info from list failed");
            ret = SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE;
            break;
        }

        DFX_RECORD_DISC_CALL_START(infoNode, packageName, STOPDISCOVERY_FUNC);
        ret = CallInterfaceByMedium(infoNode, packageName, STOPDISCOVERY_FUNC);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_CONTROL, "call interface by medium failed");
        } else {
            DfxRecordStopDiscoveryDevice(packageName, infoNode);
        }
        FreeDiscInfo(infoNode, type);
    } while (false);

    SoftBusMutexUnlock(&g_discoveryInfoList->lock);
    return ret;
}

static const char* TransferModuleIdToPackageName(DiscModule moduleId)
{
    return g_discModuleMap[moduleId - 1];
}

static int32_t InnerSetDiscoveryCallback(const char *packageName, const DiscInnerCallback *cb)
{
    if (SoftBusMutexLock(&(g_discoveryInfoList->lock)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    bool isIdExist = false;
    DiscItem *itemNode = NULL;
    InnerCallback callback;
    LIST_FOR_EACH_ENTRY(itemNode, &(g_discoveryInfoList->list), DiscItem, node) {
        if (strcmp(itemNode->packageName, packageName) != 0) {
            continue;
        }
        itemNode->callback.innerCb.OnDeviceFound = cb->OnDeviceFound;
        isIdExist = true;
        break;
    }
    if (isIdExist == false) {
        callback.innerCb.OnDeviceFound = cb->OnDeviceFound;
        itemNode = CreateDiscItem(g_discoveryInfoList, packageName, &callback, SUBSCRIBE_INNER_SERVICE);
        if (itemNode == NULL) {
            DISC_LOGE(DISC_CONTROL, "itemNode create failed");
            (void)SoftBusMutexUnlock(&(g_discoveryInfoList->lock));
            return SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE;
        }
    }
    (void)SoftBusMutexUnlock(&(g_discoveryInfoList->lock));
    return SOFTBUS_OK;
}

int32_t DiscSetDiscoverCallback(DiscModule moduleId, const DiscInnerCallback *callback)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX && callback != NULL,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");
    return InnerSetDiscoveryCallback(TransferModuleIdToPackageName(moduleId), callback);
}

int32_t DiscPublish(DiscModule moduleId, const PublishInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX && info != NULL,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_ACTIVE, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "mode is not active");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckPublishInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    DiscInfo *infoNode = CreateDiscInfoForPublish(info);
    DISC_CHECK_AND_RETURN_RET_LOGW(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerPublishService(TransferModuleIdToPackageName(moduleId), infoNode, PUBLISH_INNER_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, PUBLISH_INNER_SERVICE);
    }
    return ret;
}

int32_t DiscStartScan(DiscModule moduleId, const PublishInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX && info != NULL,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_PASSIVE, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "mode is not passive");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckPublishInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    DiscInfo *infoNode = CreateDiscInfoForPublish(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerPublishService(TransferModuleIdToPackageName(moduleId), infoNode, PUBLISH_INNER_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, PUBLISH_INNER_SERVICE);
    }
    return ret;
}

int32_t DiscUnpublish(DiscModule moduleId, int32_t publishId)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid moduleId");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    return InnerUnPublishService(TransferModuleIdToPackageName(moduleId), publishId, PUBLISH_INNER_SERVICE);
}

int32_t DiscStartAdvertise(DiscModule moduleId, const SubscribeInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX && info != NULL,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_ACTIVE, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "mode is not active");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckSubscribeInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    DiscInfo *infoNode = CreateDiscInfoForSubscribe(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerStartDiscovery(TransferModuleIdToPackageName(moduleId), infoNode, NULL, SUBSCRIBE_INNER_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, SUBSCRIBE_INNER_SERVICE);
    }
    return ret;
}

int32_t DiscSubscribe(DiscModule moduleId, const SubscribeInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX && info != NULL,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(info->mode == DISCOVER_MODE_PASSIVE, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "mode is not passive");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckSubscribeInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    DiscInfo *infoNode = CreateDiscInfoForSubscribe(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerStartDiscovery(TransferModuleIdToPackageName(moduleId), infoNode, NULL, SUBSCRIBE_INNER_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, SUBSCRIBE_INNER_SERVICE);
    }
    return ret;
}

int32_t DiscStopAdvertise(DiscModule moduleId, int32_t subscribeId)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(moduleId >= MODULE_MIN && moduleId <= MODULE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid moduleId");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    return InnerStopDiscovery(TransferModuleIdToPackageName(moduleId), subscribeId, SUBSCRIBE_INNER_SERVICE);
}

int32_t DiscPublishService(const char *packageName, const PublishInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(packageName != NULL && info != NULL, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(strlen(packageName) < PKG_NAME_SIZE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "package name too long");
    DISC_CHECK_AND_RETURN_RET_LOGW(CheckPublishInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    DiscInfo *infoNode = CreateDiscInfoForPublish(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerPublishService(packageName, infoNode, PUBLISH_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, PUBLISH_SERVICE);
    }
    return ret;
}

int32_t DiscUnPublishService(const char *packageName, int32_t publishId)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(packageName != NULL && strlen(packageName) < PKG_NAME_SIZE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    return InnerUnPublishService(packageName, publishId, PUBLISH_SERVICE);
}

int32_t DiscStartDiscovery(const char *packageName, const SubscribeInfo *info,
    const IServerDiscInnerCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(packageName != NULL && strlen(packageName) < PKG_NAME_SIZE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid package name");
    DISC_CHECK_AND_RETURN_RET_LOGW(info != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckSubscribeInfo(info) == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, DISC_CONTROL,
        "invalid info");

    DiscInfo *infoNode = CreateDiscInfoForSubscribe(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(infoNode != NULL, SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE, DISC_CONTROL,
        "create info failed");

    int32_t ret = InnerStartDiscovery(packageName, infoNode, cb, SUBSCRIBE_SERVICE);
    if (ret != SOFTBUS_OK) {
        FreeDiscInfo(infoNode, SUBSCRIBE_SERVICE);
    }
    return ret;
}

int32_t DiscStopDiscovery(const char *packageName, int32_t subscribeId)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(packageName != NULL && strlen(packageName) < PKG_NAME_SIZE_MAX,
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid parameters");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isInited == true, SOFTBUS_DISCOVER_MANAGER_NOT_INIT, DISC_CONTROL,
        "manager is not inited");

    return InnerStopDiscovery(packageName, subscribeId, SUBSCRIBE_SERVICE);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium)
{
    if (medium == COAP) {
        if (g_discCoapInterface != NULL) {
            g_discCoapInterface->LinkStatusChanged(status);
        }
    } else {
        DISC_LOGE(DISC_CONTROL, "not support medium=%{public}d", medium);
    }
}

void DiscDeviceInfoChanged(InfoTypeChanged type)
{
    DISC_LOGI(DISC_CONTROL, "type=%{public}d", type);
    if (g_discBleInterface != NULL && g_discBleInterface->UpdateLocalDeviceInfo != NULL) {
        g_discBleInterface->UpdateLocalDeviceInfo(type);
    }
    if (g_discCoapInterface != NULL && g_discCoapInterface->UpdateLocalDeviceInfo != NULL) {
        g_discCoapInterface->UpdateLocalDeviceInfo(type);
    }
}

static IdContainer* CreateIdContainer(int32_t id, const char *pkgName)
{
    IdContainer *container = SoftBusCalloc(sizeof(IdContainer));
    if (container == NULL) {
        DISC_LOGE(DISC_CONTROL, "container calloc failed");
        return NULL;
    }

    ListInit(&container->node);
    container->id = id;

    uint32_t nameLen = strlen(pkgName) + 1;
    container->pkgName = SoftBusCalloc(nameLen);
    if (container->pkgName == NULL) {
        DISC_LOGE(DISC_CONTROL, "Container pkgName calloc failed");
        SoftBusFree(container);
        return NULL;
    }

    if (strcpy_s(container->pkgName, nameLen, pkgName) != EOK) {
        DISC_LOGE(DISC_CONTROL, "strcpy_s failed");
        SoftBusFree(container->pkgName);
        container->pkgName = NULL;
        SoftBusFree(container);
        return NULL;
    }

    return container;
}

static void DestroyIdContainer(IdContainer* container)
{
    SoftBusFree(container->pkgName);
    SoftBusFree(container);
}

static void CleanupPublishDiscovery(ListNode *ids, ServiceType type)
{
    IdContainer *it = NULL;
    int32_t ret = SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE;

    LIST_FOR_EACH_ENTRY(it, ids, IdContainer, node) {
        if (type == PUBLISH_SERVICE) {
            ret = DiscUnPublishService(it->pkgName, it->id);
            DISC_LOGI(DISC_CONTROL, "clean publish pkgName=%{public}s, id=%{public}d, ret=%{public}d",
                it->pkgName, it->id, ret);
        } else if (type == SUBSCRIBE_SERVICE) {
            ret = DiscStopDiscovery(it->pkgName, it->id);
            DISC_LOGI(DISC_CONTROL, "clean subscribe pkgName=%{public}s, id=%{public}d, ret=%{public}d",
                it->pkgName, it->id, ret);
        }
    }
}

static void RemoveDiscInfoByPackageName(SoftBusList *itemList, const ServiceType type, const char *pkgName)
{
    ListNode ids;
    ListInit(&ids);

    if (SoftBusMutexLock(&itemList->lock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "lock failed");
        return;
    }

    DiscItem *itemNode = NULL;
    IdContainer *container = NULL;
    LIST_FOR_EACH_ENTRY(itemNode, &itemList->list, DiscItem, node) {
        if (pkgName != NULL) {
            if (strcmp(itemNode->packageName, pkgName) != 0) {
                continue;
            }
        }

        DiscInfo *infoNode = NULL;
        LIST_FOR_EACH_ENTRY(infoNode, &itemNode->InfoList, DiscInfo, node) {
            container = CreateIdContainer(infoNode->id, itemNode->packageName);
            if (container == NULL) {
                DISC_LOGE(DISC_CONTROL, "CreateIdContainer failed");
                (void)SoftBusMutexUnlock(&itemList->lock);
                goto CLEANUP;
            }
            ListTailInsert(&ids, &container->node);
        }
    }

    (void)SoftBusMutexUnlock(&itemList->lock);
    CleanupPublishDiscovery(&ids, type);

CLEANUP:
    while (!IsListEmpty(&ids)) {
        container = LIST_ENTRY(ids.next, IdContainer, node);
        ListDelete(&container->node);
        DestroyIdContainer(container);
    }
}

static void RemoveAllDiscInfoForPublish(void)
{
    RemoveDiscInfoByPackageName(g_publishInfoList, PUBLISH_SERVICE, NULL);
    DestroySoftBusList(g_publishInfoList);
    g_publishInfoList = NULL;
}

static void RemoveAllDiscInfoForDiscovery(void)
{
    RemoveDiscInfoByPackageName(g_discoveryInfoList, SUBSCRIBE_SERVICE, NULL);
    DestroySoftBusList(g_discoveryInfoList);
    g_discoveryInfoList = NULL;
}

static void RemoveDiscInfoForPublish(const char *pkgName)
{
    RemoveDiscInfoByPackageName(g_publishInfoList, PUBLISH_SERVICE, pkgName);
}

static void RemoveDiscInfoForDiscovery(const char *pkgName)
{
    RemoveDiscInfoByPackageName(g_discoveryInfoList, SUBSCRIBE_SERVICE, pkgName);
}

void DiscMgrDeathCallback(const char *pkgName)
{
    DISC_CHECK_AND_RETURN_LOGE(pkgName != NULL, DISC_CONTROL, "pkgName is null");
    DISC_CHECK_AND_RETURN_LOGE(g_isInited == true, DISC_CONTROL, "disc manager is not inited");

    DISC_LOGD(DISC_CONTROL, "pkg is dead. pkgName=%{public}s", pkgName);
    RemoveDiscInfoForPublish(pkgName);
    RemoveDiscInfoForDiscovery(pkgName);
}

int32_t DiscMgrInit(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_isInited == false, SOFTBUS_OK, DISC_INIT, "already inited");

    g_discMgrMediumCb.OnDeviceFound = DiscOnDeviceFound;

    g_discCoapInterface = DiscCoapInit(&g_discMgrMediumCb);
    g_discBleInterface = DiscBleInit(&g_discMgrMediumCb);
    g_discUsbInterface = DiscUsbDispatcherInit(&g_discMgrMediumCb);

    DISC_CHECK_AND_RETURN_RET_LOGE(g_discBleInterface != NULL || g_discCoapInterface != NULL ||
        g_discUsbInterface != NULL, SOFTBUS_DISCOVER_MANAGER_INIT_FAIL, DISC_INIT, "ble coap and usb init failed");

    g_publishInfoList = CreateSoftBusList();
    DISC_CHECK_AND_RETURN_RET_LOGE(g_publishInfoList != NULL, SOFTBUS_DISCOVER_MANAGER_INIT_FAIL, DISC_INIT,
        "init publish info list failed");
    g_discoveryInfoList = CreateSoftBusList();
    if (g_discoveryInfoList == NULL) {
        DISC_LOGE(DISC_INIT, "init discovery Info List failed");
        DestroySoftBusList(g_publishInfoList);
        g_publishInfoList = NULL;
        return SOFTBUS_DISCOVER_MANAGER_INIT_FAIL;
    }

    for (int32_t i = 0; i < CAPABILITY_MAX_BITNUM; i++) {
        ListInit(&g_capabilityList[i]);
    }

    g_isInited = true;
    return SOFTBUS_OK;
}

void DiscMgrDeinit(void)
{
    DISC_CHECK_AND_RETURN_LOGW(g_isInited == true, DISC_INIT, "disc manager is not inited");

    RemoveAllDiscInfoForPublish();
    RemoveAllDiscInfoForDiscovery();

    g_discCoapInterface = NULL;
    g_discBleInterface = NULL;
    g_discUsbInterface = NULL;

    DiscCoapDeinit();
    DiscBleDeinit();
    DiscUsbDispatcherDeinit();

    g_isInited = false;
    DISC_LOGI(DISC_INIT, "disc manager deinit success");
}

int32_t DiscSetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(
        (pkgName != NULL && nameData != NULL), SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid param");
    int ret = SOFTBUS_PARSE_JSON_ERR;
    if (memset_s(&g_displayName, sizeof(g_displayName), 0, sizeof(g_displayName)) != EOK) {
        DISC_LOGE(DISC_CONTROL, "DiscSetDisplayName failed");
        return SOFTBUS_MEM_ERR;
    }
    cJSON *json = cJSON_ParseWithLength(nameData, len);
    DISC_CHECK_AND_RETURN_RET_LOGE(json != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_CONTROL, "parse cJSON failed");

    if (!GetJsonObjectStringItem(json, JSON_KEY_RAW_NAME, g_displayName.raw, DISPLAY_NAME_BUF_LEN)) {
        DISC_LOGE(DISC_CONTROL, "GetJsonObjectStringItem raw name failed. displayName=%{public}s", g_displayName.raw);
        goto CLEANUP;
    }

    if (LnnSetLocalDeviceName(g_displayName.raw) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "LnnSetLocalDeviceName fail");
        goto CLEANUP;
    }

    if (!GetJsonObjectStringItem(json, JSON_KEY_NAME_LEN_18, g_displayName.name18, sizeof(g_displayName.name18))) {
        DISC_LOGE(DISC_CONTROL, "GetJsonObjectStringItem name18 failed. displayName=%{public}s", g_displayName.name18);
        goto CLEANUP;
    }

    if (!GetJsonObjectStringItem(json, JSON_KEY_NAME_LEN_21, g_displayName.name21, sizeof(g_displayName.name21))) {
        DISC_LOGE(DISC_CONTROL, "GetJsonObjectStringItem name21 failed. displayName=%{public}s", g_displayName.name21);
        goto CLEANUP;
    }

    if (!GetJsonObjectStringItem(json, JSON_KEY_NAME_LEN_24, g_displayName.name24, sizeof(g_displayName.name24))) {
        DISC_LOGE(DISC_CONTROL, "GetJsonObjectStringItem name24 failed. displayName=%{public}s", g_displayName.name24);
        goto CLEANUP;
    }
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
    ret = SOFTBUS_OK;
CLEANUP:
    cJSON_Delete(json);
    return ret;
}

int32_t DiscGetDisplayName(char *displayName, uint32_t length, uint32_t remainLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGE((displayName != NULL && remainLen > 0 && remainLen <= DISPLAY_NAME_BUF_LEN),
        SOFTBUS_INVALID_PARAM, DISC_CONTROL, "invalid param");
    char *source = NULL;
    uint32_t len = 0;
    if (remainLen > strlen(g_displayName.raw)) {
        source = g_displayName.raw;
        len = strlen(g_displayName.raw);
        goto END;
    }
    if (remainLen >= DISPLAY_NAME_LEN_24) {
        source = g_displayName.name24;
        len = DISPLAY_NAME_LEN_24;
        goto END;
    }
    if (remainLen >= DISPLAY_NAME_LEN_21) {
        source = g_displayName.name21;
        len = DISPLAY_NAME_LEN_21;
        goto END;
    }
    if (remainLen >= DISPLAY_NAME_LEN_18) {
        source = g_displayName.name18;
        len = DISPLAY_NAME_LEN_18;
        goto END;
    } else {
        source = g_displayName.name18;
        len = remainLen;
    }

END:
    DISC_CHECK_AND_RETURN_RET_LOGW(len < length, SOFTBUS_INVALID_PARAM, DISC_CONTROL, "length too long");
    if (memcpy_s(displayName, length, source, len) != EOK) {
        DISC_LOGE(DISC_CONTROL, "memcpy reply fail");
        return SOFTBUS_MEM_ERR;
    }
    displayName[len] = '\0';
    return SOFTBUS_OK;
}
