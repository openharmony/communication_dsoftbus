/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "disc_nstackx_adapter.h"

#include <string.h>
#include "bus_center_manager.h"
#include "nstackx.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

#define JSON_WLAN_IP "wifiIpAddr"
#define JSON_HW_ACCOUNT "hwAccountHashVal"
#define JSON_SERVICE_DATA "serviceData"
#define SERVICE_DATA_PORT "port"
#define DEVICE_UDID "UDID"
#define AUTH_PORT_LEN 6
#define WLAN_IFACE_NAME_PREFIX "wlan"
#define INVALID_IP_ADDR "0.0.0.0"

static NSTACKX_LocalDeviceInfo *g_localDeviceInfo = NULL;
static DiscInnerCallback *g_discCoapInnerCb = NULL;
static char *g_capabilityData = NULL;

static void ParseWifiIpAddr(const cJSON *data, DeviceInfo *device)
{
    if (!GetJsonObjectStringItem(data, JSON_WLAN_IP, device->addr[0].info.ip.ip,
        sizeof(device->addr[0].info.ip.ip))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse wifi ip address failed.");
        return;
    }
}

static void ParseHwAccountHash(const cJSON *data, DeviceInfo *device)
{
    if (!GetJsonObjectStringItem(data, JSON_HW_ACCOUNT, device->hwAccountHash, sizeof(device->hwAccountHash))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse hw account hash value failed.");
        return;
    }
}

static void ParseItemDataFromServiceData(char *serviceData, const char *key, char *targetStr, int32_t len)
{
    const char *itemDelimit = ",";
    const char *keyStr = NULL;
    char *valueStr = NULL;
    char *itemStr = NULL;
    char *saveItemPtr = NULL;
    itemStr = strtok_s(serviceData, itemDelimit, &saveItemPtr);
    while (itemStr != NULL) {
        valueStr = strchr(itemStr, ':');
        if (valueStr == NULL) {
            continue;
        }
        *valueStr = '\0';
        valueStr++;
        keyStr = itemStr;
        if (!strcmp(keyStr, key)) {
            if (strcpy_s(targetStr, len, valueStr) != EOK) {
                SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strpcy_s failed.");
                break;
            }
            return;
        }
        itemStr = strtok_s(NULL, itemDelimit, &saveItemPtr);
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "not find key in service data.");
    return;
}

static void ParseServiceData(const cJSON *data, DeviceInfo *device)
{
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(data, JSON_SERVICE_DATA, serviceData, sizeof(serviceData))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse service data failed.");
        return;
    }
    char port[AUTH_PORT_LEN] = {0};
    ParseItemDataFromServiceData(serviceData, SERVICE_DATA_PORT, port, sizeof(port));
    int authPort = atoi(port);
    if (authPort == 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "not find auth port.");
        return;
    }
    device->addr[0].info.ip.port = (uint16_t)authPort;
}

static int32_t ParseReservedInfo(const NSTACKX_DeviceInfo *nstackxDevice, DeviceInfo *device)
{
    cJSON *reserveInfo = cJSON_Parse(nstackxDevice->reservedInfo);
    if (reserveInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse reserve data failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    ParseWifiIpAddr(reserveInfo, device);
    ParseHwAccountHash(reserveInfo, device);
    ParseServiceData(reserveInfo, device);
    cJSON_Delete(reserveInfo);
    return SOFTBUS_OK;
}

static int32_t ParseDeviceUdid(const NSTACKX_DeviceInfo *nstackxDevice, DeviceInfo *device)
{
    cJSON *deviceId = cJSON_Parse(nstackxDevice->deviceId);
    if (deviceId == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse device id failed.");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(deviceId, DEVICE_UDID, device->devId, sizeof(device->devId))) {
        cJSON_Delete(deviceId);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse udid from remote failed.");
        return SOFTBUS_ERR;
    }
    cJSON_Delete(deviceId);
    return SOFTBUS_OK;
}

static int32_t ParseDiscDevInfo(const NSTACKX_DeviceInfo *nstackxDevInfo, DeviceInfo *discDevInfo)
{
    if (strcpy_s(discDevInfo->devName, sizeof(discDevInfo->devName), nstackxDevInfo->deviceName) != EOK ||
        memcpy_s(discDevInfo->capabilityBitmap, sizeof(discDevInfo->capabilityBitmap),
                 nstackxDevInfo->capabilityBitmap, sizeof(nstackxDevInfo->capabilityBitmap)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strcpy_s or memcpy_s failed.");
        return SOFTBUS_ERR;
    }

    discDevInfo->addrNum = 1;
    discDevInfo->devType = nstackxDevInfo->deviceType;
    discDevInfo->capabilityBitmapNum = nstackxDevInfo->capabilityBitmapNum;

    if (strncmp(g_localDeviceInfo->networkName, WLAN_IFACE_NAME_PREFIX, strlen(WLAN_IFACE_NAME_PREFIX)) == 0) {
        discDevInfo->addr[0].type = CONNECTION_ADDR_WLAN;
    } else {
        discDevInfo->addr[0].type = CONNECTION_ADDR_ETH;
    }

    if (ParseDeviceUdid(nstackxDevInfo, discDevInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse device udid failed.");
        return SOFTBUS_ERR;
    }

    if (ParseReservedInfo(nstackxDevInfo, discDevInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse reserve information failed.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if ((deviceList == NULL) || (deviceCount == 0)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "invalid param.");
        return;
    }

    DeviceInfo *discDeviceInfo = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (discDeviceInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "malloc device info failed.");
        return;
    }

    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;
        if (((nstackxDeviceInfo->update) & 0x1) == 0) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "duplicate  device is not reported.");
            continue;
        }
        (void)memset_s(discDeviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
        if (ParseDiscDevInfo(nstackxDeviceInfo, discDeviceInfo) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "parse discovery device info failed.");
            continue;
        }
        if ((g_discCoapInnerCb != NULL) && (g_discCoapInnerCb->OnDeviceFound != NULL)) {
            g_discCoapInnerCb->OnDeviceFound(discDeviceInfo);
        }
    }

    SoftBusFree(discDeviceInfo);
}

static NSTACKX_Parameter g_nstackxCallBack = {
    .onDeviceListChanged = OnDeviceFound,
    .onDeviceFound = NULL,
    .onMsgReceived = NULL,
    .onDFinderMsgReceived = NULL
};

int32_t DiscCoapRegisterCb(const DiscInnerCallback *discCoapCb)
{
    if (discCoapCb == NULL || g_discCoapInnerCb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(g_discCoapInnerCb, sizeof(DiscInnerCallback), discCoapCb, sizeof(DiscInnerCallback)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    if (capabilityBitmapNum == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (NSTACKX_RegisterCapability(capabilityBitmapNum, capabilityBitmap) != 0) {
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    if (capabilityBitmapNum == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (NSTACKX_SetFilterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterServiceData(const unsigned char *serviceData, uint32_t dataLen)
{
    (void)serviceData;
    (void)dataLen;
    if (g_capabilityData == NULL) {
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }

    int32_t authPort = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get auth port from lnn failed.");
        return SOFTBUS_ERR;
    }
    (void)memset_s(g_capabilityData, NSTACKX_MAX_SERVICE_DATA_LEN, 0, NSTACKX_MAX_SERVICE_DATA_LEN);
    int32_t ret = sprintf_s(g_capabilityData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,", authPort);
    if (ret == -1) {
        return SOFTBUS_ERR;
    }
    if (NSTACKX_RegisterServiceData(g_capabilityData) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapStartDiscovery(DiscCoapMode mode)
{
    if (mode < ACTIVE_PUBLISH || mode > ACTIVE_DISCOVERY) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (mode) {
        case ACTIVE_PUBLISH:
            if (NSTACKX_StartDeviceFindAn(PUBLISH_MODE_PROACTIVE) != SOFTBUS_OK) {
                return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
            }
            break;
        case ACTIVE_DISCOVERY:
            if (NSTACKX_StartDeviceFind() != SOFTBUS_OK) {
                return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "unsupport coap mode.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapStopDiscovery(void)
{
    if (NSTACKX_StopDeviceFind() != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }

    return SOFTBUS_OK;
}

static char *GetDeviceId(void)
{
    char *formatString = NULL;
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get udid failed.");
        return NULL;
    }
    cJSON *deviceId = cJSON_CreateObject();
    if (deviceId == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "crate json object failed.");
        return NULL;
    }
    if (!AddStringToJsonObject(deviceId, DEVICE_UDID, udid)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "add udid to device id json object failed.");
        goto GET_DEVICE_ID_END;
    }
    formatString = cJSON_PrintUnformatted(deviceId);
    if (formatString == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "format device id json object failed.");
    }

GET_DEVICE_ID_END:
    cJSON_Delete(deviceId);
    return formatString;
}

static int32_t SetLocalDeviceInfo(void)
{
    if (g_localDeviceInfo == NULL) {
        return SOFTBUS_DISCOVER_COAP_NOT_INIT;
    }

    (void)memset_s(g_localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo), 0, sizeof(NSTACKX_LocalDeviceInfo));
    char *deviceIdStr = GetDeviceId();
    if (deviceIdStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get device id string failed.");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(g_localDeviceInfo->deviceId, sizeof(g_localDeviceInfo->deviceId), deviceIdStr) != EOK) {
        cJSON_free(deviceIdStr);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_ERR;
    }
    cJSON_free(deviceIdStr);
    int32_t deviceType = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get local device type failed.");
        return SOFTBUS_ERR;
    }
    g_localDeviceInfo->deviceType = (uint8_t)deviceType;
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, g_localDeviceInfo->name,
                           sizeof(g_localDeviceInfo->name)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, g_localDeviceInfo->networkIpAddr,
                           sizeof(g_localDeviceInfo->networkIpAddr)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, g_localDeviceInfo->version,
                           sizeof(g_localDeviceInfo->version)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, g_localDeviceInfo->networkName,
                           sizeof(g_localDeviceInfo->networkName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get local device info from lnn failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DiscCoapUpdateLocalIp(LinkStatus status)
{
    if (status == LINK_STATUS_UP) {
        int32_t ret = SetLocalDeviceInfo();
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "set local device info failed, ret = %d.", ret);
            return;
        }
    } else if (status == LINK_STATUS_DOWN) {
        if (strcpy_s(g_localDeviceInfo->networkIpAddr, sizeof(g_localDeviceInfo->networkIpAddr),
            INVALID_IP_ADDR) != EOK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
            return;
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "invlaid link status, status = %d.", status);
        return;
    }

    if (NSTACKX_RegisterDevice(g_localDeviceInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "register new ip to dfinder failed.");
    }
}

static void DeinitLocalInfo(void)
{
    if (g_localDeviceInfo != NULL) {
        SoftBusFree(g_localDeviceInfo);
        g_localDeviceInfo = NULL;
    }

    if (g_capabilityData != NULL) {
        SoftBusFree(g_capabilityData);
        g_capabilityData = NULL;
    }

    if (g_discCoapInnerCb != NULL) {
        SoftBusFree(g_discCoapInnerCb);
        g_discCoapInnerCb = NULL;
    }
}

static int32_t InitLocalInfo(void)
{
    if (g_localDeviceInfo == NULL) {
        g_localDeviceInfo = (NSTACKX_LocalDeviceInfo*)SoftBusCalloc(sizeof(NSTACKX_LocalDeviceInfo));
        if (g_localDeviceInfo == NULL) {
            return SOFTBUS_MEM_ERR;
        }
    }
    if (g_capabilityData == NULL) {
        g_capabilityData = (char*)SoftBusCalloc(NSTACKX_MAX_SERVICE_DATA_LEN);
        if (g_capabilityData == NULL) {
            DeinitLocalInfo();
            return SOFTBUS_MEM_ERR;
        }
    }
    if (g_discCoapInnerCb == NULL) {
        g_discCoapInnerCb = (DiscInnerCallback*)SoftBusCalloc(sizeof(DiscInnerCallback));
        if (g_discCoapInnerCb == NULL) {
            DeinitLocalInfo();
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t DiscNstackxInit(void)
{
    if (InitLocalInfo() != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }

    if (NSTACKX_Init(&g_nstackxCallBack) != SOFTBUS_OK) {
        DeinitLocalInfo();
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }

    return SOFTBUS_OK;
}

void DiscNstackxDeinit(void)
{
    NSTACKX_Deinit();
    DeinitLocalInfo();
}