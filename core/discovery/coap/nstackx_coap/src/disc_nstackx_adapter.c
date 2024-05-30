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

#include "disc_nstackx_adapter.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#include "nstackx.h"

#include "bus_center_manager.h"
#include "disc_coap_capability.h"
#include "disc_coap_parser.h"
#include "disc_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hisysevt_discreporter.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define WLAN_IFACE_NAME_PREFIX "wlan"
#define INVALID_IP_ADDR        "0.0.0.0"
#define LOOPBACK_IP_ADDR       "127.0.0.1"
#define DISC_FREQ_COUNT_MASK   0xFFFF
#define DISC_FREQ_DURATION_BIT 16
#define DISC_USECOND           1000
#define MULTI_BYTE_CHAR_LEN    8
#define MAX_WIDE_STR_LEN       128
#define DEFAULT_MAX_DEVICE_NUM 20

#define NSTACKX_LOCAL_DEV_INFO "NstackxLocalDevInfo"

static NSTACKX_LocalDeviceInfo *g_localDeviceInfo = NULL;
static DiscInnerCallback *g_discCoapInnerCb = NULL;
static int32_t NstackxLocalDevInfoDump(int fd);

static int32_t FillRspSettings(NSTACKX_ResponseSettings *settings, const DeviceInfo *deviceInfo, uint8_t bType)
{
    settings->businessData = NULL;
    settings->length = 0;
    settings->businessType = bType;
    char localNetifName[NET_IF_NAME_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, localNetifName, sizeof(localNetifName));
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get local network name from LNN failed, ret=%{public}d", ret);
        goto EXIT;
    }
    if (strcpy_s(settings->localNetworkName, sizeof(settings->localNetworkName), localNetifName) != EOK) {
        DISC_LOGE(DISC_COAP, "copy disc response settings network name failed");
        goto EXIT;
    }
    if (strcpy_s(settings->remoteIp, sizeof(settings->remoteIp), deviceInfo->addr[0].info.ip.ip) != EOK) {
        DISC_LOGE(DISC_COAP, "copy disc response settings remote IP failed");
        goto EXIT;
    }
    return SOFTBUS_OK;
EXIT:
    return SOFTBUS_STRCPY_ERR;
}

int32_t DiscCoapSendRsp(const DeviceInfo *deviceInfo, uint8_t bType)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceInfo, SOFTBUS_INVALID_PARAM, DISC_COAP, "DiscRsp devInfo is null");
    NSTACKX_ResponseSettings *settings = (NSTACKX_ResponseSettings *)SoftBusCalloc(sizeof(NSTACKX_ResponseSettings));
    DISC_CHECK_AND_RETURN_RET_LOGE(settings, SOFTBUS_MALLOC_ERR, DISC_COAP, "malloc disc response settings failed");

    int32_t ret = FillRspSettings(settings, deviceInfo, bType);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "fill nstackx response settings failed");
        SoftBusFree(settings);
        return ret;
    }

    DISC_LOGI(DISC_COAP, "send rsp with bType=%{public}u", bType);
    ret = NSTACKX_SendDiscoveryRsp(settings);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "disc send response failed, ret=%{public}d", ret);
    }
    SoftBusFree(settings);
    return ret;
}

static int32_t ParseReservedInfo(const NSTACKX_DeviceInfo *nstackxDevice, DeviceInfo *device)
{
    cJSON *reserveInfo = cJSON_Parse(nstackxDevice->reservedInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(reserveInfo != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_COAP,
        "parse reserve data failed.");

    DiscCoapParseWifiIpAddr(reserveInfo, device);
    DiscCoapParseHwAccountHash(reserveInfo, device);
    if (DiscCoapParseServiceData(reserveInfo, device) != SOFTBUS_OK) {
        DISC_LOGD(DISC_COAP, "parse service data failed");
    }
    cJSON_Delete(reserveInfo);
    return SOFTBUS_OK;
}

static int32_t ParseDiscDevInfo(const NSTACKX_DeviceInfo *nstackxDevInfo, DeviceInfo *discDevInfo)
{
    if (strcpy_s(discDevInfo->devName, sizeof(discDevInfo->devName), nstackxDevInfo->deviceName) != EOK ||
        memcpy_s(discDevInfo->capabilityBitmap, sizeof(discDevInfo->capabilityBitmap),
                 nstackxDevInfo->capabilityBitmap, sizeof(nstackxDevInfo->capabilityBitmap)) != EOK) {
        DISC_LOGE(DISC_COAP, "strcpy_s devName or memcpy_s capabilityBitmap failed.");
        return SOFTBUS_MEM_ERR;
    }

    discDevInfo->devType = (DeviceType)nstackxDevInfo->deviceType;
    discDevInfo->capabilityBitmapNum = nstackxDevInfo->capabilityBitmapNum;

    if (strncmp(nstackxDevInfo->networkName, WLAN_IFACE_NAME_PREFIX, strlen(WLAN_IFACE_NAME_PREFIX)) == 0) {
        discDevInfo->addr[0].type = CONNECTION_ADDR_WLAN;
    } else {
        discDevInfo->addr[0].type = CONNECTION_ADDR_ETH;
    }

    int32_t ret = DiscCoapParseDeviceUdid(nstackxDevInfo->deviceId, discDevInfo);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "parse device udid failed.");
        return ret;
    }

    ret = ParseReservedInfo(nstackxDevInfo, discDevInfo);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "parse reserve information failed.");
        return ret;
    }
    // coap not support range now, just assign -1 as unknown
    discDevInfo->range = -1;

    return SOFTBUS_OK;
}

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    DISC_CHECK_AND_RETURN_LOGE(deviceList != NULL && deviceCount != 0, DISC_COAP, "invalid param.");
    DISC_LOGD(DISC_COAP, "Disc device found, count=%{public}u", deviceCount);
    DeviceInfo *discDeviceInfo = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    DISC_CHECK_AND_RETURN_LOGE(discDeviceInfo != NULL, DISC_COAP, "malloc device info failed.");

    int32_t ret;
    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;
        DISC_CHECK_AND_RETURN_LOGE(nstackxDeviceInfo, DISC_COAP, "device count from nstackx is invalid");

        if ((nstackxDeviceInfo->update & 0x1) == 0) {
            DISC_LOGI(DISC_COAP, "duplicate device do not need report. deviceName=%{public}s",
                nstackxDeviceInfo->deviceName);
            continue;
        }
        (void)memset_s(discDeviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
        ret = ParseDiscDevInfo(nstackxDeviceInfo, discDeviceInfo);
        if (ret != SOFTBUS_OK) {
            DISC_LOGW(DISC_COAP, "parse discovery device info failed.");
            continue;
        }
        ret = DiscCoapProcessDeviceInfo(nstackxDeviceInfo, discDeviceInfo, g_discCoapInnerCb);
        if (ret != SOFTBUS_OK) {
            DISC_LOGD(DISC_COAP, "DiscRecv: process device info failed, ret=%{public}d", ret);
        }
    }

    SoftBusFree(discDeviceInfo);
}

static void OnNotificationReceived(const NSTACKX_NotificationConfig *notification)
{
    DiscCoapReportNotification(notification);
}

static NSTACKX_Parameter g_nstackxCallBack = {
    .onDeviceListChanged = OnDeviceFound,
    .onDeviceFound = NULL,
    .onMsgReceived = NULL,
    .onDFinderMsgReceived = NULL,
    .onNotificationReceived = OnNotificationReceived,
};

int32_t DiscCoapRegisterCb(const DiscInnerCallback *discCoapCb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(discCoapCb != NULL && g_discCoapInnerCb != NULL, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid param");
    if (memcpy_s(g_discCoapInnerCb, sizeof(DiscInnerCallback), discCoapCb, sizeof(DiscInnerCallback)) != EOK) {
        DISC_LOGE(DISC_COAP, "memcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOGE(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "capabilityBitmapNum=0");

    if (NSTACKX_RegisterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "NSTACKX Register Capability failed");
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOGE(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "capabilityBitmapNum=0");

    if (NSTACKX_SetFilterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "NSTACKX SetFilter Capability failed");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterServiceData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability)
{
    int32_t authPort = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort);
    if (ret != SOFTBUS_OK) {
        DISC_LOGW(DISC_COAP, "get auth port from lnn failed. ret=%{public}d", ret);
    }

    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN] = {0};
    if (sprintf_s(serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,", authPort) == -1) {
        DISC_LOGE(DISC_COAP, "write auth port to service data failed.");
        return SOFTBUS_STRCPY_ERR;
    }
    // capabilityData can be NULL, it will be check in this func
    ret = DiscCoapFillServiceData(capability, (const char *)capabilityData, dataLen, serviceData,
        NSTACKX_MAX_SERVICE_DATA_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "fill service data failed. ret=%{public}d", ret);

    ret = NSTACKX_RegisterServiceData(serviceData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
        "register service data to nstackx failed. ret=%{public}d", ret);
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapabilityData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability)
{
    if (capabilityData == NULL || dataLen == 0) {
        // no capability data, no need to parse and register
        return SOFTBUS_OK;
    }
    char *registerCapaData = (char *)SoftBusCalloc(MAX_CAPABILITYDATA_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(registerCapaData, SOFTBUS_MALLOC_ERR, DISC_COAP, "malloc capability data failed");
    int32_t ret = DiscCoapAssembleCapData(capability, (const char *)capabilityData, dataLen, registerCapaData,
        DISC_MAX_CUST_DATA_LEN);
    if (ret == SOFTBUS_FUNC_NOT_SUPPORT) {
        DISC_LOGI(DISC_COAP, "the capability not support yet. capability=%{public}u", capability);
        SoftBusFree(registerCapaData);
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "assemble the data of capability failed. capability=%{public}u", capability);
        SoftBusFree(registerCapaData);
        return ret;
    }

    if (NSTACKX_RegisterExtendServiceData(registerCapaData) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "register extend service data to nstackx failed");
        SoftBusFree(registerCapaData);
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_DATA_FAIL;
    }
    DISC_LOGI(DISC_COAP, "register extend service data to nstackx succ. registerCapaData=%{public}s", registerCapaData);
    SoftBusFree(registerCapaData);
    return SOFTBUS_OK;
}

static bool IsNetworkValid(void)
{
    char localIp[IP_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get local ip failed");
        return false;
    }
    if (strcmp(localIp, LOOPBACK_IP_ADDR) == 0 ||
        strcmp(localIp, INVALID_IP_ADDR) == 0 ||
        strcmp(localIp, "") == 0) {
        DISC_LOGE(DISC_COAP, "invalid localIp: loopback or null");
        return false;
    }
    return true;
}

static int32_t GetDiscFreq(int32_t freq, uint32_t *discFreq)
{
    uint32_t arrayFreq[FREQ_BUTT] = {0};
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_DISC_FREQ, (unsigned char *)arrayFreq, sizeof(arrayFreq));
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "disc get freq failed");
        return ret;
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
    int32_t ret = GetDiscFreq(option->freq, &discFreq);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get discovery freq config failed");
        return ret;
    }
    discSet->advertiseCount = discFreq & DISC_FREQ_COUNT_MASK;
    discSet->advertiseDuration = (discFreq >> DISC_FREQ_DURATION_BIT) * DISC_USECOND;
    DiscFillBtype(option->capability, option->allCap, discSet);
    return SOFTBUS_OK;
}

static void FreeDiscSet(NSTACKX_DiscoverySettings *discSet)
{
    if (discSet != NULL) {
        SoftBusFree(discSet->businessData);
        SoftBusFree(discSet);
    }
}

int32_t DiscCoapStartDiscovery(DiscCoapOption *option)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "option=NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(option->mode >= ACTIVE_PUBLISH && option->mode <= ACTIVE_DISCOVERY,
        SOFTBUS_INVALID_PARAM, DISC_COAP, "option->mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGE(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq. freq=%{public}d", option->freq);
    DISC_CHECK_AND_RETURN_RET_LOGE(IsNetworkValid(), SOFTBUS_NETWORK_NOT_FOUND, DISC_COAP, "netif not works");

    NSTACKX_DiscoverySettings *discSet = (NSTACKX_DiscoverySettings *)SoftBusCalloc(sizeof(NSTACKX_DiscoverySettings));
    DISC_CHECK_AND_RETURN_RET_LOGE(discSet != NULL, SOFTBUS_MEM_ERR, DISC_COAP, "malloc disc settings failed");

    int32_t ret = ConvertDiscoverySettings(discSet, option);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "set discovery settings failed");
        FreeDiscSet(discSet);
        return ret;
    }
    if (NSTACKX_StartDeviceDiscovery(discSet) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "start device discovery failed");
        FreeDiscSet(discSet);
        return (option->mode == ACTIVE_PUBLISH) ? SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL :
            SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
    }
    FreeDiscSet(discSet);
    return SOFTBUS_OK;
}

int32_t DiscCoapStopDiscovery(void)
{
    if (NSTACKX_StopDeviceFind() != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "stop device discovery failed");
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }

    return SOFTBUS_OK;
}

static char *GetDeviceId(void)
{
    char *formatString = NULL;
    char udid[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, sizeof(udid));
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get udid failed, ret=%{public}d", ret);
        return NULL;
    }
    cJSON *deviceId = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOGW(deviceId != NULL, NULL, DISC_COAP, "create json object failed: deviceId=NULL");

    if (!AddStringToJsonObject(deviceId, DEVICE_UDID, udid)) {
        DISC_LOGE(DISC_COAP, "add udid to device id json object failed.");
        goto GET_DEVICE_ID_END;
    }
    formatString = cJSON_PrintUnformatted(deviceId);
    if (formatString == NULL) {
        DISC_LOGE(DISC_COAP, "format device id json object failed.");
    }

GET_DEVICE_ID_END:
    cJSON_Delete(deviceId);
    return formatString;
}

static int32_t SetLocalDeviceInfo(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_localDeviceInfo != NULL, SOFTBUS_DISCOVER_COAP_NOT_INIT, DISC_COAP,
        "disc coap not init");
    (void)memset_s(g_localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo), 0, sizeof(NSTACKX_LocalDeviceInfo));

    char *deviceIdStr = GetDeviceId();
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceIdStr != NULL, SOFTBUS_DISCOVER_COAP_GET_DEVICE_INFO_FAIL, DISC_COAP,
        "get device id string failed.");

    if (strcpy_s(g_localDeviceInfo->deviceId, sizeof(g_localDeviceInfo->deviceId), deviceIdStr) != EOK) {
        cJSON_free(deviceIdStr);
        DISC_LOGE(DISC_COAP, "strcpy_s deviceId failed.");
        return SOFTBUS_STRCPY_ERR;
    }
    cJSON_free(deviceIdStr);
    int32_t deviceType = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceType);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get local device type failed.");
        return ret;
    }
    g_localDeviceInfo->deviceType = (uint32_t)deviceType;
    g_localDeviceInfo->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, g_localDeviceInfo->localIfInfo[0].networkIpAddr,
                           sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, g_localDeviceInfo->version, sizeof(g_localDeviceInfo->version)) !=
        SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, g_localDeviceInfo->localIfInfo[0].networkName,
                           sizeof(g_localDeviceInfo->localIfInfo[0].networkName)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get local device info from lnn failed.");
        return SOFTBUS_DISCOVER_GET_LOCAL_STR_FAILED;
    }
    g_localDeviceInfo->ifNums = 1;

    return SOFTBUS_OK;
}

void DiscCoapUpdateLocalIp(LinkStatus status)
{
    DISC_CHECK_AND_RETURN_LOGE(status == LINK_STATUS_UP || status == LINK_STATUS_DOWN, DISC_COAP,
        "invlaid link status, status=%{public}d.", status);
    
    if (status == LINK_STATUS_DOWN) {
        if (strcpy_s(g_localDeviceInfo->localIfInfo[0].networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr), INVALID_IP_ADDR) != EOK) {
            DISC_LOGE(DISC_COAP, "link status down: strcpy_s networkIpAddr failed.");
            return;
        }
    } else {
        DISC_CHECK_AND_RETURN_LOGE(SetLocalDeviceInfo() == SOFTBUS_OK, DISC_COAP,
            "link status up: set local device info failed");
    }

    int64_t accountId = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "get local account failed");
    DISC_LOGI(DISC_COAP, "register local device info. status=%{public}s, accountInfo=%{public}s",
        status == LINK_STATUS_UP ? "up" : "down", accountId == 0 ? "without" : "with");
    ret = NSTACKX_RegisterDeviceAn(g_localDeviceInfo, (uint64_t)accountId);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "register local device info to dfinder failed");
    DiscCoapUpdateDevName();
}

static int32_t SetLocale(char **localeBefore)
{
    *localeBefore = setlocale(LC_CTYPE, NULL);
    if (*localeBefore == NULL) {
        DISC_LOGW(DISC_COAP, "get locale failed");
    }

    char *localeAfter = setlocale(LC_CTYPE, "C.UTF-8");
    return (localeAfter != NULL) ? SOFTBUS_OK : SOFTBUS_DISCOVER_SET_LOCALE_FAILED;
}

static void RestoreLocale(const char *localeBefore)
{
    if (setlocale(LC_CTYPE, localeBefore) == NULL) {
        DISC_LOGW(DISC_COAP, "restore locale failed");
    }
}

static int32_t CalculateMbsTruncateSize(const char *multiByteStr, uint32_t capacity, uint32_t *truncatedSize)
{
    size_t multiByteStrLen = strlen(multiByteStr);
    if (multiByteStrLen == 0) {
        *truncatedSize = 0;
        return SOFTBUS_OK;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE(multiByteStrLen <= MAX_WIDE_STR_LEN, SOFTBUS_INVALID_PARAM, DISC_COAP,
        "multi byte str too long: %zu", multiByteStrLen);

    char *localeBefore = NULL;
    int32_t ret = SetLocale(&localeBefore);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "set locale failed");

    // convert multi byte str to wide str
    wchar_t wideStr[MAX_WIDE_STR_LEN] = {0};
    size_t numConverted = mbstowcs(wideStr, multiByteStr, multiByteStrLen);
    if (numConverted <= 0 || numConverted > INT32_MAX) {
        DISC_LOGE(DISC_COAP, "mbstowcs failed");
        RestoreLocale(localeBefore);
        return SOFTBUS_DISCOVER_CHAR_CONVERT_FAILED;
    }

    uint32_t truncateTotal = 0;
    int32_t truncateIndex = (int32_t)numConverted - 1;
    char multiByteChar[MULTI_BYTE_CHAR_LEN] = {0};
    while (capacity < multiByteStrLen - truncateTotal && truncateIndex >= 0) {
        int32_t truncateCharLen = wctomb(multiByteChar, wideStr[truncateIndex]);
        if (truncateCharLen <= 0) {
            DISC_LOGE(DISC_COAP, "wctomb failed");
            RestoreLocale(localeBefore);
            return SOFTBUS_DISCOVER_CHAR_CONVERT_FAILED;
        }
        truncateTotal += (uint32_t)truncateCharLen;
        truncateIndex--;
    }

    *truncatedSize = (multiByteStrLen >= truncateTotal) ? (multiByteStrLen - truncateTotal) : 0;
    RestoreLocale(localeBefore);
    return SOFTBUS_OK;
}

void DiscCoapUpdateDevName(void)
{
    char localDevName[DEVICE_NAME_BUF_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "get local device name failed, ret=%{public}d.", ret);

    uint32_t truncateLen = 0;
    if (CalculateMbsTruncateSize((const char *)localDevName, NSTACKX_MAX_DEVICE_NAME_LEN - 1, &truncateLen)
        != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "truncate device name failed");
        return;
    }
    localDevName[truncateLen] = '\0';
    DISC_LOGI(DISC_COAP, "register new local device name. localDevName=%{public}s", localDevName);
    ret = NSTACKX_RegisterDeviceName(localDevName);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "register local device name failed, ret=%{public}d.", ret);
}

void DiscCoapUpdateAccount(void)
{
    DiscCoapUpdateLocalIp(LINK_STATUS_UP);
}

static void DeinitLocalInfo(void)
{
    if (g_localDeviceInfo != NULL) {
        SoftBusFree(g_localDeviceInfo);
        g_localDeviceInfo = NULL;
    }

    if (g_discCoapInnerCb != NULL) {
        SoftBusFree(g_discCoapInnerCb);
        g_discCoapInnerCb = NULL;
    }
}

static int32_t InitLocalInfo(void)
{
    if (g_localDeviceInfo == NULL) {
        g_localDeviceInfo = (NSTACKX_LocalDeviceInfo *)SoftBusCalloc(sizeof(NSTACKX_LocalDeviceInfo));
        if (g_localDeviceInfo == NULL) {
            return SOFTBUS_MEM_ERR;
        }
    }
    if (g_discCoapInnerCb == NULL) {
        g_discCoapInnerCb = (DiscInnerCallback *)SoftBusCalloc(sizeof(DiscInnerCallback));
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

    NSTACKX_DFinderRegisterLog(NstackxLogInnerImpl);
    if (SoftbusGetConfig(SOFTBUS_INT_DISC_COAP_MAX_DEVICE_NUM, (unsigned char *)&g_nstackxCallBack.maxDeviceNum,
        sizeof(g_nstackxCallBack.maxDeviceNum)) != SOFTBUS_OK) {
        DISC_LOGI(DISC_COAP, "get disc max device num config failed, use default %{public}u", DEFAULT_MAX_DEVICE_NUM);
        g_nstackxCallBack.maxDeviceNum = DEFAULT_MAX_DEVICE_NUM;
    }
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
    SOFTBUS_DPRINTF(fd, "\n-----------------NstackxLocalDevInfo-------------------\n");
    SOFTBUS_DPRINTF(fd, "name                                : %s\n", g_localDeviceInfo->name);
    DataMasking(g_localDeviceInfo->deviceId, NSTACKX_MAX_DEVICE_ID_LEN, ID_DELIMITER, deviceId);
    SOFTBUS_DPRINTF(fd, "deviceId                            : %s\n", deviceId);
    SOFTBUS_DPRINTF(fd, "localIfInfo networkName             : %s\n", g_localDeviceInfo->localIfInfo->networkName);
    SOFTBUS_DPRINTF(fd, "ifNums                              : %d\n", g_localDeviceInfo->ifNums);
    SOFTBUS_DPRINTF(fd, "networkName                         : %s\n", g_localDeviceInfo->networkName);
    SOFTBUS_DPRINTF(fd, "is5GHzBandSupported                 : %d\n", g_localDeviceInfo->is5GHzBandSupported);
    SOFTBUS_DPRINTF(fd, "deviceType                          : %d\n", g_localDeviceInfo->deviceType);
    SOFTBUS_DPRINTF(fd, "version                             : %s\n", g_localDeviceInfo->version);
    SOFTBUS_DPRINTF(fd, "businessType                        : %d\n", g_localDeviceInfo->businessType);

    return SOFTBUS_OK;
}
