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

#include "resource_manager.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "interface_info.h"
#include "wifi_direct_coexist_rule.h"
#include "wifi_direct_p2p_adapter.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_network_utils.h"

/* private method forward declare */
static int32_t InitInterfaceInfo(const char *interface);
static int32_t InitInterfacesByCoexistCap(const char *coexistCap);
static void OnInterfaceInfoChange(struct InterfaceInfo *info);

/* public interface */
static int32_t InitWifiDirectInfo(void)
{
    char *coexistCap = NULL;
    int32_t ret = GetWifiDirectP2pAdapter()->getInterfaceCoexistCap(&coexistCap);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_INIT, "get interface coexist cap failed");

    if (coexistCap == NULL || strlen(coexistCap) == 0) {
        CONN_LOGD(CONN_INIT, "coexistCap is empty, only init p2p0 interface");
        GetWifiDirectCoexistRule()->setBypass();
        ret = InitInterfaceInfo(IF_NAME_P2P);
        CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_INIT, "init p2p interface info failed");
        return ret;
    }

    CONN_LOGI(CONN_INIT, "cap=%{public}s", coexistCap);
    ret = GetWifiDirectCoexistRule()->setCoexistRule(coexistCap);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "set coexist rule failed");
    }

    ret = InitInterfacesByCoexistCap(coexistCap);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init InterfacesByCoexistCap failed");
    }
    SoftBusFree(coexistCap);
    return ret;
}

static struct InterfaceInfo *GetInterfaceInfo(const char *interface)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->isInited, NULL, CONN_WIFI_DIRECT, "not inited");
    SoftBusMutexLock(&self->mutex);
    struct InterfaceInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &self->interfaces, struct InterfaceInfo, node) {
        if (!strcmp(interface, info->getName(info))) {
            SoftBusMutexUnlock(&self->mutex);
            return info;
        }
    }

    SoftBusMutexUnlock(&self->mutex);
    CONN_LOGE(CONN_WIFI_DIRECT, "not find interface. interface=%{public}s", interface);
    return NULL;
}

static void NotifyInterfaceInfoChange(struct InterfaceInfo *info)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_LOGW(self->isInited, CONN_WIFI_DIRECT, "not inited");
    bool isChanged = false;
    char *name = info->getName(info);
    CONN_CHECK_AND_RETURN_LOGW(strlen(name) > 0, CONN_WIFI_DIRECT, "name is emtpy");
    SoftBusMutexLock(&self->mutex);
    struct InterfaceInfo *old = self->getInterfaceInfo(name);
    if (old == NULL) {
        struct InterfaceInfo *newInfo = InterfaceInfoNew();
        CONN_CHECK_AND_RETURN_LOGW(newInfo, CONN_WIFI_DIRECT, "new interface failed");
        newInfo->deepCopy(newInfo, info);
        ListTailInsert(&self->interfaces, &newInfo->node);
        self->count++;

        OnInterfaceInfoChange(newInfo);
        SoftBusMutexUnlock(&self->mutex);
        return;
    }

    for (size_t key = 0; key < II_KEY_MAX; key++) {
        struct InfoContainerKeyProperty *property = &info->keyProperties[key];
        size_t size = 0;
        size_t count = 0;
        void *data = info->get(info, key, &size, &count);
        if (data != NULL) {
            if (property->flag == CONTAINER_FLAG) {
                old->putContainer(old, key, data, size);
            } else if (property->flag == CONTAINER_ARRAY_FLAG) {
                old->putContainerArray(old, key, data, count, size / count);
            } else {
                old->putRawData(old, key, data, size);
            }
            isChanged = true;
        } else if (info->entries[key].remove) {
            old->remove(old, key);
            isChanged = true;
        }
    }

    if (isChanged) {
        OnInterfaceInfoChange(old);
    }
    SoftBusMutexUnlock(&self->mutex);
}

static void AddUsingInterfaceToList(ListNode *list, const char *interface)
{
    struct CombinationEntry *entry = SoftBusCalloc(sizeof(*entry));
    if (entry != NULL) {
        ListInit(&entry->node);
        int32_t ret = strcpy_s(entry->interface, sizeof(entry->interface), interface);
        if (ret != EOK) {
            SoftBusFree(entry);
            return;
        }
        ListTailInsert(list, &entry->node);
    }
}

static ListNode *GetUsingInterfaces(bool forShare)
{
    ListNode *list = SoftBusCalloc(sizeof(*list));
    CONN_CHECK_AND_RETURN_RET_LOGE(list, NULL, CONN_WIFI_DIRECT, "malloc list failed");
    ListInit(list);

    if (GetWifiDirectP2pAdapter()->isWifiConnected()) {
        AddUsingInterfaceToList(list, IF_NAME_WLAN);
    }
    if (forShare) {
        if (GetWifiDirectP2pAdapter()->isWifiApEnabled()) {
            AddUsingInterfaceToList(list, IF_NAME_WLAN1);
        }
    }

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (info != NULL) {
        enum WifiDirectApiRole myRole =
            (enum WifiDirectApiRole)info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
        if (myRole == WIFI_DIRECT_API_ROLE_GC || myRole == WIFI_DIRECT_API_ROLE_GO) {
            AddUsingInterfaceToList(list, IF_NAME_P2P);
        }
    }

    info = GetResourceManager()->getInterfaceInfo(IF_NAME_HML);
    if (info != NULL) {
        enum WifiDirectApiRole myRole =
            (enum WifiDirectApiRole)info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
        if (myRole == WIFI_DIRECT_API_ROLE_HML) {
            AddUsingInterfaceToList(list, IF_NAME_HML);
        }
    }

    return list;
}

static void FreeUsingInterfaces(ListNode *list)
{
    struct CombinationEntry *entry = NULL;
    struct CombinationEntry *entryNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(entry, entryNext, list, struct CombinationEntry, node) {
        ListDelete(&entry->node);
        SoftBusFree(entry);
    }
    SoftBusFree(list);
}

static bool IsStationAndHmlDBAC(void)
{
    int32_t staFreq = GetWifiDirectP2pAdapter()->getStationFrequency();
    int32_t hmlFreq = -1;
    struct InterfaceInfo *hmlInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_HML);
    if (hmlInfo != NULL) {
        enum WifiDirectApiRole hmlRole = hmlInfo->getInt(hmlInfo, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
        if (hmlRole == WIFI_DIRECT_API_ROLE_HML) {
            hmlFreq = hmlInfo->getInt(hmlInfo, II_KEY_CENTER_20M, -1);
        }
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "staFreq=%{public}d, hmlFreq=%{public}d", staFreq, hmlFreq);
    if (staFreq != -1 && hmlFreq != -1 && staFreq != hmlFreq) {
        struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
        if ((netWorkUtils->is2GBand(staFreq) && netWorkUtils->is2GBand(hmlFreq)) ||
            (netWorkUtils->is5GBand(staFreq) && netWorkUtils->is5GBand(hmlFreq))) {
            return true;
        }
    }
    return false;
}

static bool IsInterfaceAvailable(const char *interface, bool forShare)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(interface, false, CONN_WIFI_DIRECT, "name is null");

    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->isInited, false, CONN_WIFI_DIRECT, "not inited");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, false, CONN_WIFI_DIRECT, "interface info is null");

    if (!info->getBoolean(info, II_KEY_IS_ENABLE, false)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "IS_ENABLE=0 interface=%{public}s", interface);
        return false;
    }

    if (info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE) == WIFI_DIRECT_API_ROLE_GC) {
        CONN_LOGE(CONN_WIFI_DIRECT, "already gc");
        return false;
    }

    ListNode *usingInterfaces = GetUsingInterfaces(forShare);
    if (usingInterfaces != NULL) {
        AddUsingInterfaceToList(usingInterfaces, interface);
        bool ret = GetWifiDirectCoexistRule()->isCombinationAvailable(usingInterfaces);
        FreeUsingInterfaces(usingInterfaces);
        if (ret && strcmp(interface, IF_NAME_P2P) == 0) {
            ret = !IsStationAndHmlDBAC();
        }
        return ret;
    }
    return true;
}

static void RegisterListener(struct ResourceManagerListener *listener)
{
    GetResourceManager()->listener = *listener;
}

static bool IsAvailableByProperty(const char *interface, bool available)
{
    if (strcmp(interface, IF_NAME_HML) != 0) {
        return available;
    }
    if (GetWifiDirectUtils()->supportHml()) {
        return available;
    }
    return false;
}

static int32_t GetAllInterfacesSimpleInfo(struct InterfaceInfo **infoArray, int32_t *infoArraySize)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->isInited, SOFTBUS_ERR, CONN_WIFI_DIRECT, "not inited");
    struct InterfaceInfo *array = InterfaceInfoNewArray(self->count);
    CONN_CHECK_AND_RETURN_RET_LOGW(array, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "new interface array failed");

    int32_t i = 0;
    struct InterfaceInfo *info = NULL;

    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(info, &self->interfaces, struct InterfaceInfo, node) {
        char *name = info->getName(info);
        bool isAvailable = self->isInterfaceAvailable(name, false);
        isAvailable = IsAvailableByProperty(name, isAvailable);
        int32_t deviceCount = info->getInt(info, II_KEY_CONNECTED_DEVICE_COUNT, 0);
        CONN_LOGI(CONN_WIFI_DIRECT,
            "name=%{public}s, available=%{public}d, deviceCount=%{public}d", name, isAvailable, deviceCount);

        array[i].putName(array + i, name);
        array[i].putBoolean(array + i, II_KEY_IS_AVAILABLE, isAvailable);
        array[i].putInt(array + i, II_KEY_CONNECTED_DEVICE_COUNT, deviceCount);
        i++;
    }
    SoftBusMutexUnlock(&self->mutex);

    *infoArray = array;
    *infoArraySize = i;
    return SOFTBUS_OK;
}

static int32_t GetAllInterfacesInfo(struct InterfaceInfo **infoArray, int32_t *infoArraySize)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->isInited, SOFTBUS_ERR, CONN_WIFI_DIRECT, "not inited");
    struct InterfaceInfo *array = InterfaceInfoNewArray(self->count);
    CONN_CHECK_AND_RETURN_RET_LOGW(array, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "new interface array failed");

    int32_t i = 0;
    struct InterfaceInfo *info = NULL;

    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(info, &self->interfaces, struct InterfaceInfo, node) {
        array[i].deepCopy(array + i, info);
        const char *name = array[i].getName(array + i);
        bool isAvailable = self->isInterfaceAvailable(name, false);
        isAvailable = IsAvailableByProperty(name, isAvailable);
        array[i].putBoolean(array + i, II_KEY_IS_AVAILABLE, isAvailable);
        int32_t deviceCount = info->getInt(info, II_KEY_CONNECTED_DEVICE_COUNT, 0);

        CONN_LOGI(CONN_WIFI_DIRECT,
            "name=%{public}s, available=%{public}d, deviceCount=%{public}d", name, isAvailable, deviceCount);
        i++;
    }
    SoftBusMutexUnlock(&self->mutex);

    *infoArray = array;
    *infoArraySize = i;
    return SOFTBUS_OK;
}

static int32_t GetAllInterfacesNameAndMac(struct InterfaceInfo **infoArray, int32_t *infoArraySize)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->isInited, SOFTBUS_ERR, CONN_WIFI_DIRECT, "not inited");
    CONN_LOGI(CONN_WIFI_DIRECT, "count=%{public}d", self->count);
    struct InterfaceInfo *array = InterfaceInfoNewArray(self->count);
    CONN_CHECK_AND_RETURN_RET_LOGW(array, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "new interface array failed");

    int32_t i = 0;
    struct InterfaceInfo *info = NULL;

    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(info, &self->interfaces, struct InterfaceInfo, node) {
        char *name = info->getName(info);
        char *mac = info->getString(info, II_KEY_BASE_MAC, "");
        CONN_LOGD(CONN_WIFI_DIRECT, "name=%{public}s, mac=%{public}s", name, WifiDirectAnonymizeMac(mac));
        array[i].putName(array + i, name);
        array[i].putString(array + i, II_KEY_BASE_MAC, mac);
        i++;
    }
    SoftBusMutexUnlock(&self->mutex);

    *infoArray = array;
    *infoArraySize = i;
    return SOFTBUS_OK;
}

static void Dump(int32_t fd)
{
    struct ResourceManager *self = GetResourceManager();
    CONN_CHECK_AND_RETURN_LOGW(self->isInited, CONN_WIFI_DIRECT, "not inited");
    struct InterfaceInfo *interfaceInfo = NULL;

    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(interfaceInfo, &self->interfaces, struct InterfaceInfo, node) {
        interfaceInfo->dump(interfaceInfo, fd);
    }
    SoftBusMutexUnlock(&self->mutex);
}

/* private method implement */
static int32_t InitInterfaceInfo(const char *interface)
{
    struct InterfaceInfo info;
    InterfaceInfoConstructor(&info);
    info.putName(&info, interface);

    CONN_LOGI(CONN_INIT, "interface=%{public}s", interface);
    if (strcmp(interface, IF_NAME_P2P) == 0) {
        char macString[MAC_ADDR_STR_LEN];
        int32_t ret = GetWifiDirectP2pAdapter()->getMacAddress(macString, sizeof(macString));
        if (ret == SOFTBUS_OK) {
            info.putString(&info, II_KEY_BASE_MAC, macString);
        }

        int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
        size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
        ret = GetWifiDirectP2pAdapter()->getChannel5GListIntArray(channelArray, &channelArraySize);
        if (ret == SOFTBUS_OK) {
            info.putIntArray(&info, II_KEY_CHANNEL_5G_LIST, channelArray, channelArraySize);
        }

        info.putInt(&info, II_KEY_CONNECT_CAPABILITY, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_GC);
        if (GetWifiDirectP2pAdapter()->isWifiP2pEnabled()) {
            info.putBoolean(&info, II_KEY_IS_ENABLE, true);
        } else {
            info.putBoolean(&info, II_KEY_IS_ENABLE, false);
        }

        GetResourceManager()->notifyInterfaceInfoChange(&info);
        InterfaceInfoDestructor(&info);
        return SOFTBUS_OK;
    }

    if (strcmp(interface, IF_NAME_HML) == 0) {
        info.putInt(&info, II_KEY_CONNECT_CAPABILITY, WIFI_DIRECT_API_ROLE_HML);
        InterfaceInfoDestructor(&info);
        return SOFTBUS_OK;
    }

    CONN_LOGE(CONN_INIT, "invalid interface name");
    return SOFTBUS_INVALID_PARAM;
}

static void UpdateInterfaceWithMode(const char *interface, int cap)
{
    struct InterfaceInfo info;
    InterfaceInfoConstructor(&info);
    info.putName(&info, interface);
    info.putInt(&info, II_KEY_CONNECT_CAPABILITY, cap);
    info.putInt(&info, II_KEY_REUSE_COUNT, 0);

    CONN_LOGI(CONN_INIT, "interface=%{public}s, cap=0x%{public}x", interface, cap);
    if (((uint32_t)cap & WIFI_DIRECT_API_ROLE_GO) || ((uint32_t)cap & WIFI_DIRECT_API_ROLE_GC)) {
        int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
        size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
        int ret = GetWifiDirectP2pAdapter()->getChannel5GListIntArray(channelArray, &channelArraySize);
        if (ret == SOFTBUS_OK) {
            info.putIntArray(&info, II_KEY_CHANNEL_5G_LIST, channelArray, channelArraySize);
        }
    }

    if (GetWifiDirectP2pAdapter()->isWifiP2pEnabled()) {
        CONN_LOGI(CONN_INIT, "set interface enable=true, interface=%{public}s", interface);
        info.putBoolean(&info, II_KEY_IS_ENABLE, true);
        char baseMac[MAC_ADDR_STR_LEN] = {0};
        if (GetWifiDirectP2pAdapter()->getBaseMac(interface, (uint32_t)cap, baseMac, sizeof(baseMac)) == SOFTBUS_OK) {
            info.putString(&info, II_KEY_BASE_MAC, baseMac);
        }
    } else {
        CONN_LOGI(CONN_INIT, "set interface enable=false, interface=%{public}s", interface);
        info.putBoolean(&info, II_KEY_IS_ENABLE, false);
    }

    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static int32_t InitInterfacesByCoexistCap(const char *coexistCap)
{
    cJSON *coexistObj = cJSON_ParseWithLength(coexistCap, strlen(coexistCap) + 1);
    CONN_CHECK_AND_RETURN_RET_LOGW(coexistObj, SOFTBUS_MALLOC_ERR, CONN_INIT, "create json object failed");
    if (!cJSON_IsArray(coexistObj)) {
        cJSON_Delete(coexistObj);
        CONN_LOGE(CONN_INIT, "coexistObj is not a array");
        return SOFTBUS_INVALID_PARAM;
    }

    for (int i = 0; i < cJSON_GetArraySize(coexistObj); i++) {
        cJSON *subItems = cJSON_GetArrayItem(coexistObj, i);
        if (!cJSON_IsArray(subItems)) {
            CONN_LOGW(CONN_INIT, "item is not array. i=%{public}d ", i);
            continue;
        }

        for (int j = 0; j < cJSON_GetArraySize(subItems); j++) {
            cJSON *subItem = cJSON_GetArrayItem(subItems, j);
            char interface[IF_NAME_LEN] = {0};
            if (!GetJsonObjectStringItem(subItem, "IF", interface, sizeof(interface))) {
                CONN_LOGW(CONN_INIT, "get if failed");
                continue;
            }

            int mode = 0;
            if (!GetJsonObjectInt32Item(subItem, "MODE", &mode)) {
                CONN_LOGW(CONN_INIT, "get mode failed. interface=%{public}s", interface);
                continue;
            }

            UpdateInterfaceWithMode(interface, mode);
        }
    }

    cJSON_Delete(coexistObj);
    return SOFTBUS_OK;
}

static void OnInterfaceInfoChange(struct InterfaceInfo *info)
{
    struct ResourceManager *self = GetResourceManager();
    if (self->listener.onInterfaceInfoChange) {
        self->listener.onInterfaceInfoChange(info);
    }
}

static struct ResourceManager g_manager = {
    .initWifiDirectInfo = InitWifiDirectInfo,
    .getInterfaceInfo = GetInterfaceInfo,
    .notifyInterfaceInfoChange = NotifyInterfaceInfoChange,
    .isInterfaceAvailable = IsInterfaceAvailable,
    .isStationAndHmlDBAC = IsStationAndHmlDBAC,
    .registerListener = RegisterListener,
    .getAllInterfacesSimpleInfo = GetAllInterfacesSimpleInfo,
    .getAllInterfacesInfo = GetAllInterfacesInfo,
    .getAllInterfacesNameAndMac = GetAllInterfacesNameAndMac,
    .dump = Dump,
    .count = 0,
    .isInited = false,
};

int32_t ResourceManagerInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    ListInit(&g_manager.interfaces);
    SoftBusMutexAttr attr;
    int32_t ret = SoftBusMutexAttrInit(&attr);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_INIT, "init mutex attr failed");
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    (void)SoftBusMutexInit(&g_manager.mutex, &attr);

    g_manager.isInited = true;
    ret = InitWifiDirectInfo();
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_INIT, "init interface info failed");

    g_manager.dump(0);
    return SOFTBUS_OK;
}

struct ResourceManager *GetResourceManager(void)
{
    return &g_manager;
}