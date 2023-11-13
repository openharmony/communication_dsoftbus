/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "nstackx.h"

#include "bus_center_manager.h"
#include "disc_coap_capability.h"
#include "disc_coap_parser.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hisysevt_discreporter.h"
#include "softbus_json_utils.h"
#include "softbus_log_old.h"
#include "softbus_utils.h"

#define WLAN_IFACE_NAME_PREFIX "wlan"
#define INVALID_IP_ADDR        "0.0.0.0"
#define DISC_FREQ_COUNT_MASK   0xFFFF
#define DISC_FREQ_DURATION_BIT 16
#define DISC_USECOND           1000

#define NSTACKX_LOCAL_DEV_INFO "NstackxLocalDevInfo"

static NSTACKX_LocalDeviceInfo *g_localDeviceInfo = NULL;
static DiscInnerCallback *g_discCoapInnerCb = NULL;
static char *g_capabilityData = NULL;
static int32_t NstackxLocalDevInfoDump(int fd);

static int32_t FillRspSettings(NSTACKX_ResponseSettings *settings, const DeviceInfo *deviceInfo, uint8_t bType)
{
    settings->businessData = NULL;
    settings->length = 0;
    settings->businessType = bType;
    char localNetifName[NET_IF_NAME_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, localNetifName, sizeof(localNetifName));
    if (ret != SOFTBUS_OK) {
        DLOGE("get local network name from LNN failed, ret=%d", ret);
        goto EXIT;
    }
    if (strcpy_s(settings->localNetworkName, sizeof(settings->localNetworkName), localNetifName) != EOK) {
        DLOGE("copy disc response settings network name failed");
        goto EXIT;
    }
    if (strcpy_s(settings->remoteIp, sizeof(settings->remoteIp), deviceInfo->addr[0].info.ip.ip) != EOK) {
        DLOGE("copy disc response settings remote IP failed");
        goto EXIT;
    }
    return SOFTBUS_OK;
EXIT:
    SoftBusFree(settings->businessData);
    settings->businessData = NULL;
    return SOFTBUS_STRCPY_ERR;
}

int32_t DiscCoapSendRsp(const DeviceInfo *deviceInfo, uint8_t bType)
{
    DISC_CHECK_AND_RETURN_RET_LOG(deviceInfo, SOFTBUS_INVALID_PARAM, "DiscRsp devInfo is null");
    NSTACKX_ResponseSettings *settings = (NSTACKX_ResponseSettings *)SoftBusCalloc(sizeof(NSTACKX_ResponseSettings));
    DISC_CHECK_AND_RETURN_RET_LOG(settings, SOFTBUS_MALLOC_ERR, "malloc disc response settings failed");

    if (FillRspSettings(settings, deviceInfo, bType) != SOFTBUS_OK) {
        DLOGE("fill nstackx response settings failed");
        SoftBusFree(settings);
        return SOFTBUS_ERR;
    }

    DLOGI("send rsp with bType: %u", bType);
    int32_t ret = NSTACKX_SendDiscoveryRsp(settings);
    if (ret != SOFTBUS_OK) {
        DLOGE("disc send response failed, ret=%d", ret);
    }
    SoftBusFree(settings->businessData);
    settings->businessData = NULL;
    SoftBusFree(settings);
    return ret;
}

static int32_t ParseReservedInfo(const NSTACKX_DeviceInfo *nstackxDevice, DeviceInfo *device)
{
    cJSON *reserveInfo = cJSON_Parse(nstackxDevice->reservedInfo);
    DISC_CHECK_AND_RETURN_RET_LOG(reserveInfo != NULL, SOFTBUS_PARSE_JSON_ERR, "parse reserve data failed.");

    DiscCoapParseWifiIpAddr(reserveInfo, device);
    DiscCoapParseHwAccountHash(reserveInfo, device);
    (void)DiscCoapParseServiceData(reserveInfo, device);
    if (DiscCoapParseExtendServiceData(reserveInfo, device) != SOFTBUS_OK) {
        DLOGW("parse extend service data failed");
    }
    cJSON_Delete(reserveInfo);
    return SOFTBUS_OK;
}

static int32_t ParseDiscDevInfo(const NSTACKX_DeviceInfo *nstackxDevInfo, DeviceInfo *discDevInfo)
{
    if (strcpy_s(discDevInfo->devName, sizeof(discDevInfo->devName), nstackxDevInfo->deviceName) != EOK ||
        memcpy_s(discDevInfo->capabilityBitmap, sizeof(discDevInfo->capabilityBitmap),
                 nstackxDevInfo->capabilityBitmap, sizeof(nstackxDevInfo->capabilityBitmap)) != EOK) {
        DLOGE("strcpy_s devName or memcpy_s capabilityBitmap failed.");
        return SOFTBUS_ERR;
    }

    discDevInfo->devType = (DeviceType)nstackxDevInfo->deviceType;
    discDevInfo->capabilityBitmapNum = nstackxDevInfo->capabilityBitmapNum;

    if (strncmp(nstackxDevInfo->networkName, WLAN_IFACE_NAME_PREFIX, strlen(WLAN_IFACE_NAME_PREFIX)) == 0) {
        discDevInfo->addr[0].type = CONNECTION_ADDR_WLAN;
    } else {
        discDevInfo->addr[0].type = CONNECTION_ADDR_ETH;
    }

    if (DiscCoapParseDeviceUdid(nstackxDevInfo->deviceId, discDevInfo) != SOFTBUS_OK) {
        DLOGE("parse device udid failed.");
        return SOFTBUS_ERR;
    }

    if (ParseReservedInfo(nstackxDevInfo, discDevInfo) != SOFTBUS_OK) {
        DLOGE("parse reserve information failed.");
        return SOFTBUS_ERR;
    }
    // coap not support range now, just assign -1 as unknown
    discDevInfo->range = -1;

    return SOFTBUS_OK;
}

static void BroadcastRsp(uint8_t bType, DeviceInfo *deviceInfo)
{
    if (bType == NSTACKX_BUSINESS_TYPE_NULL) {
        DLOGI("receive a discovery broadcast from %s, do not need report", deviceInfo->devName);
        return;
    }
    DiscVerifyBroadcastType(deviceInfo, bType);
}

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    DISC_CHECK_AND_RETURN_LOG(deviceList != NULL && deviceCount != 0, "invalid param.");
    DLOGI("Disc device found, count=%u", deviceCount);
    DeviceInfo *discDeviceInfo = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    DISC_CHECK_AND_RETURN_LOG(discDeviceInfo != NULL, "malloc device info failed.");

    InnerDeviceInfoAddtions addtions = {
        .medium = COAP,
    };

    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;
        DISC_CHECK_AND_RETURN_LOG(nstackxDeviceInfo, "device count from nstackx is invalid");

        if ((nstackxDeviceInfo->update & 0x1) == 0) {
            DLOGI("duplicate device(%s) do not need report", nstackxDeviceInfo->deviceName);
            continue;
        }
        (void)memset_s(discDeviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
        if (ParseDiscDevInfo(nstackxDeviceInfo, discDeviceInfo) != SOFTBUS_OK) {
            DLOGW("parse discovery device info failed.");
            continue;
        }

        if (nstackxDeviceInfo->discoveryType == NSTACKX_DISCOVERY_TYPE_ACTIVE ||
            nstackxDeviceInfo->mode == PUBLISH_MODE_PROACTIVE) {
            DLOGI("Disc device found, devName=%s, localNetIfName=%s", discDeviceInfo->devName,
                nstackxDeviceInfo->networkName);
            DiscCheckBtype(discDeviceInfo, nstackxDeviceInfo->businessType);
            if (g_discCoapInnerCb != NULL && g_discCoapInnerCb->OnDeviceFound != NULL) {
                g_discCoapInnerCb->OnDeviceFound(discDeviceInfo, &addtions);
            }
            continue;
        }
        BroadcastRsp(nstackxDeviceInfo->businessType, discDeviceInfo);
    }

    SoftBusFree(discDeviceInfo);
}

static NSTACKX_Parameter g_nstackxCallBack = {
    .onDeviceListChanged = OnDeviceFound,
    .onDeviceFound = NULL,
    .onMsgReceived = NULL,
    .onDFinderMsgReceived = NULL,
};

int32_t DiscCoapRegisterCb(const DiscInnerCallback *discCoapCb)
{
    DISC_CHECK_AND_RETURN_RET_LOG(discCoapCb != NULL && g_discCoapInnerCb != NULL, SOFTBUS_INVALID_PARAM,
        "invalid param");
    if (memcpy_s(g_discCoapInnerCb, sizeof(DiscInnerCallback), discCoapCb, sizeof(DiscInnerCallback)) != EOK) {
        DLOGE("memcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOG(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM, "capabilityBitmapNum=0");

    if (NSTACKX_RegisterCapability(capabilityBitmapNum, capabilityBitmap) != 0) {
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOG(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM, "capabilityBitmapNum=0");

    if (NSTACKX_SetFilterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterServiceData(const unsigned char *serviceData, uint32_t dataLen)
{
    (void)serviceData;
    (void)dataLen;
    DISC_CHECK_AND_RETURN_RET_LOG(g_capabilityData != NULL, SOFTBUS_DISCOVER_COAP_INIT_FAIL, "g_capabilityData=NULL");

    int32_t authPort = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        DLOGE("get auth port from lnn failed.");
    }
    (void)memset_s(g_capabilityData, NSTACKX_MAX_SERVICE_DATA_LEN, 0, NSTACKX_MAX_SERVICE_DATA_LEN);
    if (sprintf_s(g_capabilityData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,", authPort) == -1) {
        DLOGE("write auth port to service data failed.");
        return SOFTBUS_ERR;
    }
    if (NSTACKX_RegisterServiceData(g_capabilityData) != SOFTBUS_OK) {
        DLOGE("register service data to nstackx failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapabilityData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability)
{
    if (capabilityData == NULL || dataLen == 0) {
        // no capability data, no need to parse and register
        return SOFTBUS_OK;
    }
    char *registerCapaData = (char *)SoftBusCalloc(dataLen);
    DISC_CHECK_AND_RETURN_RET_LOG(registerCapaData, SOFTBUS_MALLOC_ERR, "malloc capability data failed");
    int32_t ret = DiscCoapAssembleCapData(capability, (const char *)capabilityData, dataLen, registerCapaData);
    if (ret == SOFTBUS_FUNC_NOT_SUPPORT) {
        DLOGI("the capability(%u) not support yet", capability);
        SoftBusFree(registerCapaData);
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        DLOGE("assemble the data of capability(%u) failed", capability);
        SoftBusFree(registerCapaData);
        return SOFTBUS_ERR;
    }

    if (NSTACKX_RegisterExtendServiceData(registerCapaData) != SOFTBUS_OK) {
        DLOGE("register extend service data to nstackx failed");
        SoftBusFree(registerCapaData);
        return SOFTBUS_ERR;
    }
    DLOGI("register extend service data to nstackx succ: %s", registerCapaData);
    SoftBusFree(registerCapaData);
    return SOFTBUS_OK;
}

static int32_t GetDiscFreq(int32_t freq, uint32_t *discFreq)
{
    uint32_t arrayFreq[FREQ_BUTT] = {0};
    if (SoftbusGetConfig(SOFTBUS_INT_DISC_FREQ, (unsigned char *)arrayFreq, sizeof(arrayFreq)) != SOFTBUS_OK) {
        DLOGE("disc get freq failed");
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
        DLOGE("get discovery freq config failed");
        return SOFTBUS_ERR;
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
    DISC_CHECK_AND_RETURN_RET_LOG(option != NULL, SOFTBUS_INVALID_PARAM, "option=NULL");
    DISC_CHECK_AND_RETURN_RET_LOG(option->mode >= ACTIVE_PUBLISH && option->mode <= ACTIVE_DISCOVERY,
        SOFTBUS_INVALID_PARAM, "option->mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOG(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        "invalid freq: %d", option->freq);

    NSTACKX_DiscoverySettings *discSet = (NSTACKX_DiscoverySettings *)SoftBusCalloc(sizeof(NSTACKX_DiscoverySettings));
    DISC_CHECK_AND_RETURN_RET_LOG(discSet != NULL, SOFTBUS_MEM_ERR, "malloc disc settings failed");

    if (ConvertDiscoverySettings(discSet, option) != SOFTBUS_OK) {
        DLOGE("set discovery settings failed");
        FreeDiscSet(discSet);
        return SOFTBUS_ERR;
    }
    if (NSTACKX_StartDeviceDiscovery(discSet) != SOFTBUS_OK) {
        DLOGE("start device discovery failed");
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
        DLOGE("stop device discovery failed");
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }

    return SOFTBUS_OK;
}

static char *GetDeviceId(void)
{
    char *formatString = NULL;
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        DLOGE("get udid failed.");
        return NULL;
    }
    cJSON *deviceId = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOG(deviceId != NULL, NULL, "crate json object failed: deviceId=NULL");

    if (!AddStringToJsonObject(deviceId, DEVICE_UDID, udid)) {
        DLOGE("add udid to device id json object failed.");
        goto GET_DEVICE_ID_END;
    }
    formatString = cJSON_PrintUnformatted(deviceId);
    if (formatString == NULL) {
        DLOGE("format device id json object failed.");
    }

GET_DEVICE_ID_END:
    cJSON_Delete(deviceId);
    return formatString;
}

static int32_t SetLocalDeviceInfo(void)
{
    DISC_CHECK_AND_RETURN_RET_LOG(g_localDeviceInfo != NULL, SOFTBUS_DISCOVER_COAP_NOT_INIT, "disc coap not init");
    (void)memset_s(g_localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo), 0, sizeof(NSTACKX_LocalDeviceInfo));

    char *deviceIdStr = GetDeviceId();
    DISC_CHECK_AND_RETURN_RET_LOG(deviceIdStr != NULL, SOFTBUS_ERR, "get device id string failed.");

    if (strcpy_s(g_localDeviceInfo->deviceId, sizeof(g_localDeviceInfo->deviceId), deviceIdStr) != EOK) {
        cJSON_free(deviceIdStr);
        DLOGE("strcpy_s deviceId failed.");
        return SOFTBUS_ERR;
    }
    cJSON_free(deviceIdStr);
    int32_t deviceType = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceType) != SOFTBUS_OK) {
        DLOGE("get local device type failed.");
        return SOFTBUS_ERR;
    }
    g_localDeviceInfo->deviceType = (uint8_t)deviceType;
    g_localDeviceInfo->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, g_localDeviceInfo->name, sizeof(g_localDeviceInfo->name)) !=
            SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, g_localDeviceInfo->localIfInfo[0].networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr)) != SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_HICE_VERSION, g_localDeviceInfo->version, sizeof(g_localDeviceInfo->version)) !=
            SOFTBUS_OK ||
        LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, g_localDeviceInfo->localIfInfo[0].networkName,
            sizeof(g_localDeviceInfo->localIfInfo[0].networkName)) != SOFTBUS_OK) {
        DLOGE("get local device info from lnn failed.");
        return SOFTBUS_ERR;
    }
    g_localDeviceInfo->ifNums = 1;

    return SOFTBUS_OK;
}

void DiscCoapUpdateLocalIp(LinkStatus status)
{
    DISC_CHECK_AND_RETURN_LOG(status == LINK_STATUS_UP || status == LINK_STATUS_DOWN,
        "invlaid link status, status=%d.", status);
    
    if (status == LINK_STATUS_DOWN) {
        if (strcpy_s(g_localDeviceInfo->localIfInfo[0].networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo[0].networkIpAddr), INVALID_IP_ADDR) != EOK) {
            DLOGE("link status down: strcpy_s networkIpAddr failed.");
            return;
        }
    } else {
        DISC_CHECK_AND_RETURN_LOG(SetLocalDeviceInfo() == SOFTBUS_OK, "link status up: set local device info failed");
    }

    int64_t accountId = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId);
    DISC_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "get local account failed");
    DLOGI("link status[%s], register local device info %s account", status == LINK_STATUS_UP ? "up" : "down",
        accountId == 0 ? "without" : "with");
    ret = NSTACKX_RegisterDeviceAn(g_localDeviceInfo, (uint64_t)accountId);
    DISC_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "register local device info to dfinder failed");
}

void DiscCoapUpdateDevName(void)
{
    char localDevName[NSTACKX_MAX_DEVICE_NAME_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    DISC_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "get local device name failed, ret=%d.", ret);

    DLOGI("register new local device name: %s", localDevName);
    ret = NSTACKX_RegisterDeviceName(localDevName);
    DISC_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "register local device name failed, ret=%d.", ret);
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
        g_localDeviceInfo = (NSTACKX_LocalDeviceInfo *)SoftBusCalloc(sizeof(NSTACKX_LocalDeviceInfo));
        if (g_localDeviceInfo == NULL) {
            return SOFTBUS_MEM_ERR;
        }
    }
    if (g_capabilityData == NULL) {
        g_capabilityData = (char *)SoftBusCalloc(NSTACKX_MAX_SERVICE_DATA_LEN);
        if (g_capabilityData == NULL) {
            DeinitLocalInfo();
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