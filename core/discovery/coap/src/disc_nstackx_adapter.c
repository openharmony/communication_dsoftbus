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

#include <stdio.h>
#include <string.h>
#include "bus_center_manager.h"
#include "nstackx.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hisysevt_discreporter.h"

#define JSON_WLAN_IP "wifiIpAddr"
#define JSON_HW_ACCOUNT "hwAccountHashVal"
#define JSON_SERVICE_DATA "serviceData"
#define SERVICE_DATA_PORT "port"
#define DEVICE_UDID "UDID"
#define AUTH_PORT_LEN 6
#define WLAN_IFACE_NAME_PREFIX "wlan"
#define INVALID_IP_ADDR "0.0.0.0"
#define DEFAULT_DEVICE_TYPE 0xAF
#define DISC_FREQ_COUNT_MASK 0xFFFF
#define DISC_FREQ_DURATION_BIT 16
#define DISC_USECOND 1000

#define NSTACKX_LOCAL_DEV_INFO "NstackxLocalDevInfo"

static NSTACKX_LocalDeviceInfo *g_localDeviceInfo = NULL;
static DiscInnerCallback *g_discCoapInnerCb = NULL;
static char *g_capabilityData = NULL;
static int32_t NstackxLocalDevInfoDump(int fd);

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
    if (!GetJsonObjectStringItem(data, JSON_HW_ACCOUNT, device->accountHash, sizeof(device->accountHash))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse hw account hash value failed.");
        return;
    }
}

static void ParseItemDataFromServiceData(char *serviceData, const char *key, char *targetStr, uint32_t len)
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
    if (authPort > UINT16_MAX || authPort <= 0) {
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
    cJSON *udid = cJSON_Parse(nstackxDevice->deviceId);
    if (udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse udid failed.");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(udid, DEVICE_UDID, device->devId, sizeof(device->devId))) {
        cJSON_Delete(udid);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse udid from remote failed.");
        return SOFTBUS_ERR;
    }
    cJSON_Delete(udid);
    return SOFTBUS_OK;
}

static bool IsReport(uint8_t mode, uint8_t discoveryType)
{
    if (discoveryType == NSTACKX_DISCOVERY_TYPE_ACTIVE) {
        return true;
    }
    if (mode == PUBLISH_MODE_PROACTIVE) {
        return true;
    }
    return false;
}

static int32_t ParseDiscDevInfo(const NSTACKX_DeviceInfo *nstackxDevInfo, DeviceInfo *discDevInfo)
{
    if (strcpy_s(discDevInfo->devName, sizeof(discDevInfo->devName), nstackxDevInfo->deviceName) != EOK ||
        memcpy_s(discDevInfo->capabilityBitmap, sizeof(discDevInfo->capabilityBitmap),
                 nstackxDevInfo->capabilityBitmap, sizeof(nstackxDevInfo->capabilityBitmap)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strcpy_s devName or memcpy_s capabilityBitmap failed.");
        return SOFTBUS_ERR;
    }

    discDevInfo->addrNum = 1;
    discDevInfo->devType = (DeviceType)nstackxDevInfo->deviceType;
    discDevInfo->capabilityBitmapNum = nstackxDevInfo->capabilityBitmapNum;
    if (!IsReport(nstackxDevInfo->mode, nstackxDevInfo->discoveryType)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "publishers do not need to report devices.");
        return SOFTBUS_ERR;
    }

    if (strncmp(nstackxDevInfo->networkName, WLAN_IFACE_NAME_PREFIX, strlen(WLAN_IFACE_NAME_PREFIX)) == 0) {
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
    // coap not support range now, just assign -1 as unknown
    discDevInfo->range = -1;

    return SOFTBUS_OK;
}

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if ((deviceList == NULL) || (deviceCount == 0)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "%s:invalid param.", __func__);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "Disc device found, count=%u", deviceCount);
    DeviceInfo *discDeviceInfo = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (discDeviceInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "malloc device info failed.");
        return;
    }

    InnerDeviceInfoAddtions addtions = {
        .medium = COAP,
    };

    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;

        if (((nstackxDeviceInfo->update) & 0x1) == 0) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "duplicate device is not reported.");
            continue;
        }
        (void)memset_s(discDeviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
        if (ParseDiscDevInfo(nstackxDeviceInfo, discDeviceInfo) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "parse discovery device info failed.");
            continue;
        }

        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "Disc device found, devName=%s, localNetIfName=%s",
            discDeviceInfo->devName, nstackxDeviceInfo->networkName);
        if ((g_discCoapInnerCb != NULL) && (g_discCoapInnerCb->OnDeviceFound != NULL)) {
            g_discCoapInnerCb->OnDeviceFound(discDeviceInfo, &addtions);
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
        SoftbusRecordDiscFault(COAP, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
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

static int32_t GetDiscFreq(int32_t freq, uint32_t *discFreq)
{
    uint32_t arrayFreq[FREQ_BUTT] = {0};
    if (SoftbusGetConfig(SOFTBUS_INT_DISC_FREQ, (unsigned char *)arrayFreq, sizeof(arrayFreq)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "disc get freq failed");
        return SOFTBUS_ERR;
    }
    *discFreq = arrayFreq[freq];
    return SOFTBUS_OK;
}

static int32_t ConvertDiscoverySettings(NSTACKX_DiscoverySettings *discSet, const DiscCoapOption *option)
{
    if (option->mode == ACTIVE_PUBLISH) {
        discSet->discoveryMode = PUBLISH_MODE_PROACTIVE;
    } else {
        discSet->discoveryMode = DISCOVER_MODE;
    }
    uint32_t discFreq;
    if (GetDiscFreq(option->freq, &discFreq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get discovery freq config failed");
        return SOFTBUS_ERR;
    }
    discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
    discSet->advertiseCount = discFreq & DISC_FREQ_COUNT_MASK;
    discSet->advertiseDuration = (discFreq >> DISC_FREQ_DURATION_BIT) * DISC_USECOND;
    return SOFTBUS_OK;
}

int32_t DiscCoapStartDiscovery(DiscCoapOption *option)
{
    if (option == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "invalid param: option");
        return SOFTBUS_INVALID_PARAM;
    }
    if (option->mode < ACTIVE_PUBLISH || option->mode > ACTIVE_DISCOVERY) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "invalid param: option->mode");
        return SOFTBUS_INVALID_PARAM;
    }
    NSTACKX_DiscoverySettings discSet;
    if (memset_s(&discSet, sizeof(NSTACKX_DiscoverySettings), 0, sizeof(NSTACKX_DiscoverySettings)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memset failed");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertDiscoverySettings(&discSet, option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "set discovery settings failed");
        return SOFTBUS_ERR;
    }
    if (NSTACKX_StartDeviceDiscovery(&discSet) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "start device discovery failed");
        if (option->mode == ACTIVE_PUBLISH) {
            return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
        } else {
            return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
        }
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
    g_localDeviceInfo->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, g_localDeviceInfo->name,
                           sizeof(g_localDeviceInfo->name)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, g_localDeviceInfo->localIfInfo[0].networkIpAddr,
                           sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, g_localDeviceInfo->version,
                           sizeof(g_localDeviceInfo->version)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, g_localDeviceInfo->localIfInfo[0].networkName,
                           sizeof(g_localDeviceInfo->localIfInfo[0].networkName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get local device info from lnn failed.");
        return SOFTBUS_ERR;
    }
    g_localDeviceInfo->ifNums = 1;

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
        if (strcpy_s(g_localDeviceInfo->localIfInfo[0].networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr), INVALID_IP_ADDR) != EOK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "strcpy_s networkIpAddr failed.");
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

void DiscCoapUpdateDevName(void)
{
    char localDevName[NSTACKX_MAX_DEVICE_NAME_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get local device name failed, ret = %d.", ret);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "register new local device name: %s", localDevName);
    ret = NSTACKX_RegisterDeviceName(localDevName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "register local device name failed, ret = %d.", ret);
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

    NSTACKX_DFinderRegisterLog(NstackxLog);
    if (NSTACKX_Init(&g_nstackxCallBack) != SOFTBUS_OK) {
        DeinitLocalInfo();
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }
    SoftBusRegDiscVarDump((char *)NSTACKX_LOCAL_DEV_INFO, &NstackxLocalDevInfoDump);
    return SOFTBUS_OK;
}

void DiscNstackxDeinit(void)
{
    NSTACKX_Deinit();
    DeinitLocalInfo();
}

static int32_t NstackxLocalDevInfoDump(int fd)
{
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN] = {0};
    char btMacAddr[NSTACKX_MAX_MAC_STRING_LEN] = {0};
    char wifiMacAddr[NSTACKX_MAX_MAC_STRING_LEN] = {0};
    char ip[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN] = {0};
    SOFTBUS_DPRINTF(fd, "\n-----------------NstackxLocalDevInfo-------------------\n");
    SOFTBUS_DPRINTF(fd, "name                                : %s\n", g_localDeviceInfo->name);
    DataMasking(g_localDeviceInfo->deviceId, NSTACKX_MAX_DEVICE_ID_LEN, ID_DELIMITER, deviceId);
    SOFTBUS_DPRINTF(fd, "deviceId                            : %s\n", deviceId);
    DataMasking(g_localDeviceInfo->btMacAddr, NSTACKX_MAX_MAC_STRING_LEN, MAC_DELIMITER, btMacAddr);
    SOFTBUS_DPRINTF(fd, "btMacAddr                           : %s\n", btMacAddr);
    DataMasking(g_localDeviceInfo->wifiMacAddr, NSTACKX_MAX_MAC_STRING_LEN, MAC_DELIMITER, wifiMacAddr);
    SOFTBUS_DPRINTF(fd, "wifiMacAddr                         : %s\n", wifiMacAddr);
    SOFTBUS_DPRINTF(fd, "localIfInfo networkName             : %s\n", g_localDeviceInfo->localIfInfo->networkName);
    DataMasking(g_localDeviceInfo->localIfInfo->networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, IP_DELIMITER, ip);
    SOFTBUS_DPRINTF(fd, "localIfInfo networkIpAddr           : %s\n", ip);
    SOFTBUS_DPRINTF(fd, "ifNums                              : %d\n", g_localDeviceInfo->ifNums);
    DataMasking(g_localDeviceInfo->networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, IP_DELIMITER, networkIpAddr);
    SOFTBUS_DPRINTF(fd, "networkIpAddr                       : %s\n", networkIpAddr);
    SOFTBUS_DPRINTF(fd, "networkName                         : %s\n", g_localDeviceInfo->networkName);
    SOFTBUS_DPRINTF(fd, "is5GHzBandSupported                 : %d\n", g_localDeviceInfo->is5GHzBandSupported);
    SOFTBUS_DPRINTF(fd, "deviceType                          : %d\n", g_localDeviceInfo->deviceType);
    SOFTBUS_DPRINTF(fd, "version                             : %s\n", g_localDeviceInfo->version);
    SOFTBUS_DPRINTF(fd, "businessType                        : %d\n", g_localDeviceInfo->businessType);
    SOFTBUS_DPRINTF(fd, "\n-----------------NstackxCapDataInfo-------------------\n");
    SOFTBUS_DPRINTF(fd, "capabilityData                      : %s\n", g_capabilityData);

    return SOFTBUS_OK;
}
