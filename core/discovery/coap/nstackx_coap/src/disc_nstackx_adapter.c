/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "anonymizer.h"
#include "bus_center_manager.h"
#include "disc_coap_capability_public.h"
#include "disc_coap_parser.h"
#include "disc_coap.h"
#include "disc_log.h"
#include "g_enhance_disc_func_pack.h"
#include "lnn_ohos_account.h"
#include "locale_config_wrapper.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hidumper_disc.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define WLAN_IFACE_NAME_PREFIX            "wlan"
#define NCM_LINK_NAME_PREFIX              "ncm0"
#define NCM_HOST_NAME_PREFIX              "wwan0"
#define DISC_FREQ_COUNT_MASK              0xFFFF
#define DISC_FREQ_DURATION_BIT            16
#define DISC_USECOND                      1000
#define DEFAULT_MAX_DEVICE_NUM            20
#define IPV4_MAX_LEN                      16

#define NSTACKX_LOCAL_DEV_INFO            "NstackxLocalDevInfo"
#define HYPHEN_ZH                         "的"
#define HYPHEN_EXCEPT_ZH                  "-"
#define EMPTY_STRING                      ""
#define DEFAULT_LINK_IFNAME               "lo"

#define IPV4_LOOP_IP                      "127.0.0.1"
#define IPV6_LOOP_IP                      "::1"

static NSTACKX_LocalDeviceInfoV2 *g_localDeviceInfo = NULL;
static DiscInnerCallback *g_discCoapInnerCb = NULL;
static SoftBusMutex g_localDeviceInfoLock = {0};
static SoftBusMutex g_discCoapInnerCbLock = {0};
static int32_t NstackxLocalDevInfoDump(int fd);
static int32_t g_currentLinkUpNums = 0;
static char g_serviceData[NSTACKX_MAX_SERVICE_DATA_LEN] = {0};

typedef struct {
    char netWorkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    LinkStatus status;
} DiscLinkInfo;

static DiscLinkInfo g_linkInfo[MAX_IF + 1] = {
    {DEFAULT_LINK_IFNAME, LINK_STATUS_DOWN},
    {DEFAULT_LINK_IFNAME, LINK_STATUS_DOWN},
};

#if defined(DSOFTBUS_FEATURE_DISC_LNN_COAP) || defined(DSOFTBUS_FEATURE_DISC_SHARE_COAP)
static int32_t FillRspSettings(NSTACKX_ResponseSettings *settings,
    const DeviceInfo *deviceInfo, uint8_t bType, bool isRemoveShareCap)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(settings != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "settings is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "deviceInfo is nullptr");

    settings->businessData = NULL;
    settings->length = 0;
    settings->businessType = bType;

    char localNetifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};
    if (g_linkInfo[USB_IF].status == LINK_STATUS_UP && strlen(deviceInfo->addr[0].info.ip.ip) > IPV4_MAX_LEN) {
        LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, localNetifName, NSTACKX_MAX_INTERFACE_NAME_LEN, USB_IF);
    }
    if (g_linkInfo[WLAN_IF].status == LINK_STATUS_UP && strlen(deviceInfo->addr[0].info.ip.ip) <= IPV4_MAX_LEN) {
        LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, localNetifName, NSTACKX_MAX_INTERFACE_NAME_LEN, WLAN_IF);
    }
    DISC_CHECK_AND_RETURN_RET_LOGE(strlen(localNetifName) != 0, SOFTBUS_INVALID_PARAM, DISC_COAP,
        "get localNetifName fail");
    if (strcpy_s(settings->localNetworkName, sizeof(settings->localNetworkName), localNetifName) != EOK) {
        DISC_LOGE(DISC_COAP, "copy disc response settings network name fail");
        goto EXIT;
    }
    if (strcpy_s(settings->remoteIp, sizeof(settings->remoteIp), deviceInfo->addr[0].info.ip.ip) != EOK) {
        DISC_LOGE(DISC_COAP, "copy disc response settings remote IP fail");
        goto EXIT;
    }
    uint32_t capabilityBitmap[CAPABILITY_NUM] = {0};
    capabilityBitmap[0] = GetDiscPublishCapability();
    if (isRemoveShareCap) {
        DISC_LOGI(DISC_COAP, "remove share capability");
        capabilityBitmap[0] &= (~(0x1 << (SHARE_CAPABILITY_BITMAP % INT32_MAX_BIT_NUM)));
    }
    settings->capBitmapNum = CAPABILITY_NUM;
    DISC_CHECK_AND_RETURN_RET_LOGE(memcpy_s(settings->capBitmap, sizeof(settings->capBitmap),
        capabilityBitmap, sizeof(capabilityBitmap)) == EOK,
        SOFTBUS_STRCPY_ERR, DISC_COAP, "copy capBitMap fail");
    return SOFTBUS_OK;
EXIT:
    return SOFTBUS_STRCPY_ERR;
}
#endif /* DSOFTBUS_FEATURE_DISC_LNN_COAP || DSOFTBUS_FEATURE_DISC_SHARE_COAP */

int32_t DiscCoapSendRsp(const DeviceInfo *deviceInfo, uint8_t bType, bool isRemoveShareCap)
{
#if defined(DSOFTBUS_FEATURE_DISC_LNN_COAP) || defined(DSOFTBUS_FEATURE_DISC_SHARE_COAP)
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceInfo, SOFTBUS_INVALID_PARAM, DISC_COAP, "DiscRsp devInfo is null");
    NSTACKX_ResponseSettings *settings = (NSTACKX_ResponseSettings *)SoftBusCalloc(sizeof(NSTACKX_ResponseSettings));
    DISC_CHECK_AND_RETURN_RET_LOGE(settings, SOFTBUS_MALLOC_ERR, DISC_COAP, "malloc disc response settings fail");

    int32_t ret = FillRspSettings(settings, deviceInfo, bType, isRemoveShareCap);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "fill nstackx response settings fail");
        SoftBusFree(settings);
        return ret;
    }

    DISC_LOGI(DISC_COAP, "send rsp with bType=%{public}u isRemoveShareCap=%{public}d", bType, isRemoveShareCap);
    ret = NSTACKX_SendDiscoveryRsp(settings);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "disc send response fail, ret=%{public}d", ret);
    }
    SoftBusFree(settings);
    return ret;
#else
    return SOFTBUS_OK;
#endif /* DSOFTBUS_FEATURE_DISC_LNN_COAP || DSOFTBUS_FEATURE_DISC_SHARE_COAP */
}

static int32_t ParseReservedInfo(const NSTACKX_DeviceInfo *nstackxDevice, DeviceInfo *device, char *nickName)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(nstackxDevice != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "nstackxDevice is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(nickName != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "nickName is nullptr");

    cJSON *reserveInfo = cJSON_Parse(nstackxDevice->reservedInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(reserveInfo != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_COAP,
        "parse reserve data fail.");

    DiscCoapParseWifiIpAddr(reserveInfo, device);
    DiscCoapParseHwAccountHash(reserveInfo, device);
    DiscCoapParseNickname(reserveInfo, nickName, DISC_MAX_NICKNAME_LEN);
    if (DiscCoapParseServiceData(reserveInfo, device) != SOFTBUS_OK) {
        DISC_LOGD(DISC_COAP, "parse service data fail");
    }
    cJSON_Delete(reserveInfo);
    return SOFTBUS_OK;
}

static int32_t SpliceCoapDisplayName(char *devName, char *nickName, DeviceInfo *device)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(devName != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "devName is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(device != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "device is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(nickName != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "nickName is nullptr");

    char *hyphen = NULL;
    bool isSameAccount = false;
    bool isZH = IsZHLanguage();
    char accountIdStr[MAX_ACCOUNT_HASH_LEN] = { 0 };
    char accountHash[MAX_ACCOUNT_HASH_LEN] = { 0 };
    int32_t ret = SOFTBUS_OK;

    if (!LnnIsDefaultOhosAccount()) {
        int64_t accountId = 0;
        ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "get local account fail");

        ret = sprintf_s(accountIdStr, MAX_ACCOUNT_HASH_LEN, "%ju", (uint64_t)accountId);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret >= 0, SOFTBUS_STRCPY_ERR, DISC_COAP,
            "set accountIdStr error, ret=%{public}d", ret);
        ret = SoftBusGenerateStrHash((const unsigned char *)accountIdStr, strlen(accountIdStr),
            (unsigned char *)accountHash);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
            "generate account hash fail, ret=%{public}d", ret);

        if (memcmp(device->accountHash, accountHash, MAX_ACCOUNT_HASH_LEN) == 0) {
            isSameAccount = true;
        }
    }
    if (!isSameAccount && strlen(nickName) > 0) {
        hyphen = isZH ? (char *)HYPHEN_ZH : (char *)HYPHEN_EXCEPT_ZH;
    } else {
        hyphen = (char *)EMPTY_STRING;
    }

    ret = sprintf_s(device->devName, DISC_MAX_DEVICE_NAME_LEN, "%s%s%s",
        isSameAccount ? EMPTY_STRING : nickName, hyphen, devName);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret >= 0, SOFTBUS_STRCPY_ERR, DISC_COAP,
        "splice displayname fail, ret=%{public}d", ret);

    return SOFTBUS_OK;
}

static int32_t ParseDiscDevInfo(const NSTACKX_DeviceInfo *nstackxDevInfo, DeviceInfo *discDevInfo)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(nstackxDevInfo != NULL, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "nstackxDevInfo is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(discDevInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "discDevInfo is nullptr");

    char devName[DISC_MAX_DEVICE_NAME_LEN] = { 0 };
    char nickName[DISC_MAX_NICKNAME_LEN] = { 0 };
    if (strcpy_s(devName, DISC_MAX_DEVICE_NAME_LEN, nstackxDevInfo->deviceName) != EOK ||
        memcpy_s(discDevInfo->capabilityBitmap, sizeof(discDevInfo->capabilityBitmap),
                 nstackxDevInfo->capabilityBitmap, sizeof(nstackxDevInfo->capabilityBitmap)) != EOK) {
        DISC_LOGE(DISC_COAP, "strcpy_s devName or memcpy_s capabilityBitmap fail.");
        return SOFTBUS_MEM_ERR;
    }

    discDevInfo->devType = (DeviceType)nstackxDevInfo->deviceType;
    discDevInfo->capabilityBitmapNum = nstackxDevInfo->capabilityBitmapNum;

    if (strncmp(nstackxDevInfo->networkName, WLAN_IFACE_NAME_PREFIX, strlen(WLAN_IFACE_NAME_PREFIX)) == 0) {
        discDevInfo->addr[0].type = CONNECTION_ADDR_WLAN;
    } else if (strncmp(nstackxDevInfo->networkName, NCM_LINK_NAME_PREFIX, strlen(NCM_LINK_NAME_PREFIX)) == 0 ||
        strncmp(nstackxDevInfo->networkName, NCM_HOST_NAME_PREFIX, strlen(NCM_HOST_NAME_PREFIX)) == 0) {
        discDevInfo->addr[0].type = CONNECTION_ADDR_NCM;
    } else {
        discDevInfo->addr[0].type = CONNECTION_ADDR_ETH;
    }

    int32_t ret = DiscCoapParseDeviceUdid(nstackxDevInfo->deviceId, discDevInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
        "parse device udid fail, ret=%{public}d", ret);

    ret = ParseReservedInfo(nstackxDevInfo, discDevInfo, nickName);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
        "parse reserve information fail, ret=%{public}d", ret);

    // coap not support range now, just assign -1 as unknown
    discDevInfo->range = -1;
    ret = SpliceCoapDisplayName(devName, nickName, discDevInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
        "parse display name fail, ret=%{public}d", ret);

    return SOFTBUS_OK;
}

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    DISC_CHECK_AND_RETURN_LOGE(deviceList != NULL && deviceCount != 0, DISC_COAP, "invalid param.");
    DISC_LOGD(DISC_COAP, "Disc device found, count=%{public}u", deviceCount);
    int32_t ret = SoftBusMutexLock(&g_discCoapInnerCbLock);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "lock cb mutex err");
    if (g_discCoapInnerCb == NULL) {
        DISC_LOGE(DISC_COAP, "g_discCoapInnerCb is null");
        (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
        return;
    }
    const DiscInnerCallback cb = *g_discCoapInnerCb;
    (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
    DeviceInfo *discDeviceInfo = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    DISC_CHECK_AND_RETURN_LOGE(discDeviceInfo != NULL, DISC_COAP, "malloc device info fail.");

    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;
        if (nstackxDeviceInfo == NULL) {
            DISC_LOGE(DISC_COAP, "device count from nstackx is invalid");
            SoftBusFree(discDeviceInfo);
            return;
        }

        if ((nstackxDeviceInfo->update & 0x1) == 0) {
            char *anonymizedName = NULL;
            AnonymizeDeviceName(nstackxDeviceInfo->deviceName, &anonymizedName);
            DISC_LOGI(DISC_COAP, "duplicate device do not need report. deviceName=%{public}s",
                AnonymizeWrapper(anonymizedName));
            AnonymizeFree(anonymizedName);
            continue;
        }
        (void)memset_s(discDeviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
        ret = ParseDiscDevInfo(nstackxDeviceInfo, discDeviceInfo);
        if (ret != SOFTBUS_OK) {
            DISC_LOGW(DISC_COAP, "parse discovery device info fail.");
            continue;
        }
        ret = DiscCoapProcessDeviceInfoPacked(nstackxDeviceInfo, discDeviceInfo, cb);
        if (ret != SOFTBUS_OK) {
            DISC_LOGD(DISC_COAP, "DiscRecv: process device info fail, ret=%{public}d", ret);
        }
    }

    SoftBusFree(discDeviceInfo);
}

static void OnNotificationReceived(const NSTACKX_NotificationConfig *notification)
{
    DiscCoapReportNotificationPacked(notification);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(discCoapCb != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_discCoapInnerCbLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    if (g_discCoapInnerCb == NULL) {
        DISC_LOGE(DISC_COAP, "coap inner callback not init.");
        (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
        return SOFTBUS_DISCOVER_COAP_NOT_INIT;
    }
    if (memcpy_s(g_discCoapInnerCb, sizeof(DiscInnerCallback), discCoapCb, sizeof(DiscInnerCallback)) != EOK) {
        DISC_LOGE(DISC_COAP, "memcpy_s fail.");
        (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOGE(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "capabilityBitmapNum=0");

    if (NSTACKX_RegisterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "NSTACKX Register Capability fail");
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DISC_CHECK_AND_RETURN_RET_LOGE(capabilityBitmapNum != 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "capabilityBitmapNum=0");

    if (NSTACKX_SetFilterCapability(capabilityBitmapNum, capabilityBitmap) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "NSTACKX SetFilter Capability fail");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t RegisterServiceData()
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_discCoapInnerCbLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");

    if (g_currentLinkUpNums == 0) {
        DISC_LOGW(DISC_COAP, "no link up, not register service data");
        (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);

    int32_t ret = 0;
    int32_t port = 0;
    char ip[IP_STR_MAX_LEN] = {0};
    int32_t cnt = 0;
    struct NSTACKX_ServiceData serviceData[MAX_IF + 1] = {0};
    for (uint32_t index = 0; index <= MAX_IF; index++) {
        if (g_linkInfo[index].status == LINK_STATUS_DOWN) {
            continue;
        }

        ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &port, index);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "get local port fail");
        ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ip, IP_STR_MAX_LEN, index);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "get local ip fail");

        if (strcpy_s(serviceData[cnt].ip, IP_STR_MAX_LEN, ip) != EOK) {
            DISC_LOGE(DISC_COAP, "strcpy ip error.");
            return SOFTBUS_STRCPY_ERR;
        }
        DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
            DISC_COAP, "lock fail");
        if (sprintf_s(serviceData[cnt].serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,%s",
            port, g_serviceData) < 0) {
            DISC_LOGE(DISC_COAP, "write service data fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_STRCPY_ERR;
        }
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        cnt++;
    }
    ret = NSTACKX_RegisterServiceDataV2(serviceData, cnt);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "register servicedata to dfinder fail");
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterServiceData(const PublishOption *option, uint32_t allCap)
{
#ifdef DSOFTBUS_FEATURE_DISC_COAP
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    int32_t ret = DiscCoapFillServiceDataPacked(option, g_serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, allCap);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        DISC_LOGE(DISC_COAP, "fill castJson fail. ret=%{public}d", ret);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
    int32_t result = RegisterServiceData();
    DISC_CHECK_AND_RETURN_RET_LOGE(result == SOFTBUS_OK, result, DISC_COAP,
        "register service data to nstackx fail. result=%{public}d", result);
    return SOFTBUS_OK;
}

int32_t DiscCoapRegisterBusinessData(const unsigned char *capabilityData, uint32_t dataLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGD(capabilityData != NULL && dataLen > 0, SOFTBUS_OK, DISC_COAP,
        "no capability data, no need to parse and register");
    char businessData[NSTACKX_MAX_BUSINESS_DATA_LEN] = { 0 };
    int32_t ret = DiscCoapAssembleBdataPacked(capabilityData, dataLen, businessData, sizeof(businessData));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "assemble bdata fail, ret=%{public}d", ret);
    ret = NSTACKX_RegisterBusinessData(businessData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "register bdata fail, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
int32_t DiscCoapRegisterCapabilityData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability)
{
    if (capabilityData == NULL || dataLen == 0) {
        // no capability data, no need to parse and register
        return SOFTBUS_OK;
    }
    char *registerCapaData = (char *)SoftBusCalloc(MAX_CAPABILITYDATA_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(registerCapaData, SOFTBUS_MALLOC_ERR, DISC_COAP, "malloc capability data fail");
    int32_t ret = DiscCoapAssembleCapDataPacked(capability, (const char *)capabilityData, dataLen, registerCapaData,
        DISC_MAX_CUST_DATA_LEN);
    if (ret == SOFTBUS_FUNC_NOT_SUPPORT) {
        DISC_LOGI(DISC_COAP, "the capability not support yet. capability=%{public}u", capability);
        SoftBusFree(registerCapaData);
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "assemble the data of capability fail. capability=%{public}u", capability);
        SoftBusFree(registerCapaData);
        return ret;
    }

    if (NSTACKX_RegisterExtendServiceData(registerCapaData) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "register extend service data to nstackx fail");
        SoftBusFree(registerCapaData);
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_DATA_FAIL;
    }
    DISC_LOGI(DISC_COAP, "register extend service data to nstackx succ.");
    SoftBusFree(registerCapaData);
    return SOFTBUS_OK;
}
#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */

static int32_t GetDiscFreq(int32_t freq, uint32_t *discFreq)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(discFreq != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "discFreq is nullptr");

    uint32_t arrayFreq[FREQ_BUTT] = { 0 };
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_DISC_FREQ, (unsigned char *)arrayFreq, sizeof(arrayFreq));
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "disc get freq fail");
        return ret;
    }
    *discFreq = arrayFreq[freq];
    return SOFTBUS_OK;
}

static int32_t ConvertDiscoverySettings(NSTACKX_DiscoverySettings *discSet, const DiscCoapOption *option)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(discSet != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "discSet is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "option is nullptr");

    if (option->mode == ACTIVE_PUBLISH) {
        discSet->discoveryMode = PUBLISH_MODE_PROACTIVE;
    } else {
        discSet->discoveryMode = DISCOVER_MODE;
    }
    uint32_t discFreq;
    int32_t ret = GetDiscFreq(option->freq, &discFreq);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "get disc freq fail");
    discSet->advertiseCount = discFreq & DISC_FREQ_COUNT_MASK;
    discSet->advertiseDuration = (discFreq >> DISC_FREQ_DURATION_BIT) * DISC_USECOND;
    ret = DiscFillBtypePacked(option->capability, option->allCap, discSet);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP, "unsupport capability");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "option is null.");
    DISC_CHECK_AND_RETURN_RET_LOGE(option->mode >= ACTIVE_PUBLISH && option->mode <= ACTIVE_DISCOVERY,
        SOFTBUS_INVALID_PARAM, DISC_COAP, "option->mode is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGE(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq. freq=%{public}d", option->freq);
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");

    if (g_currentLinkUpNums == 0) {
        DISC_LOGE(DISC_COAP, "netif not works");
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return SOFTBUS_NETWORK_NOT_FOUND;
    }
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);

    NSTACKX_DiscoverySettings *discSet = (NSTACKX_DiscoverySettings *)SoftBusCalloc(sizeof(NSTACKX_DiscoverySettings));
    DISC_CHECK_AND_RETURN_RET_LOGE(discSet != NULL, SOFTBUS_MEM_ERR, DISC_COAP, "malloc disc settings fail");

    int32_t ret = ConvertDiscoverySettings(discSet, option);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "set discovery settings fail");
        FreeDiscSet(discSet);
        return ret;
    }
    if (NSTACKX_StartDeviceDiscovery(discSet) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "start device discovery fail");
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
        DISC_LOGE(DISC_COAP, "stop device discovery fail");
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }

    return SOFTBUS_OK;
}

static char *GetDeviceId(void)
{
    char *formatString = NULL;
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, sizeof(udid));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, DISC_COAP, "get udid fail, ret=%{public}d", ret);

    cJSON *deviceId = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOGW(deviceId != NULL, NULL, DISC_COAP, "create json object fail: deviceId=NULL");

    if (!AddStringToJsonObject(deviceId, DEVICE_UDID, udid)) {
        DISC_LOGE(DISC_COAP, "add udid to device id json object fail.");
        goto GET_DEVICE_ID_END;
    }
    formatString = cJSON_PrintUnformatted(deviceId);
    if (formatString == NULL) {
        DISC_LOGE(DISC_COAP, "format device id json object fail.");
    }

GET_DEVICE_ID_END:
    cJSON_Delete(deviceId);
    return formatString;
}

static int32_t SetLocalLinkInfo(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    if (g_localDeviceInfo == NULL) {
        DISC_LOGE(DISC_COAP, "disc coap not init");
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return SOFTBUS_DISCOVER_COAP_NOT_INIT;
    }

    (void)memset_s(g_localDeviceInfo->localIfInfo, sizeof(NSTACKX_InterfaceInfo), 0,
        sizeof(NSTACKX_InterfaceInfo));
    if (status == LINK_STATUS_DOWN) {
        if (strcpy_s(g_localDeviceInfo->localIfInfo->networkName, sizeof(g_localDeviceInfo->localIfInfo->networkName),
            g_linkInfo[ifnameIdx].netWorkName) != EOK) {
            DISC_LOGE(DISC_COAP, "strcpy networkname fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_STRCPY_ERR;
        }
        // Set IpAddr to loop IP assuming the link is down.
        char *networkIpAddr = (ifnameIdx == WLAN_IF) ? IPV4_LOOP_IP : IPV6_LOOP_IP;
        if (strcpy_s(g_localDeviceInfo->localIfInfo->networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo->networkIpAddr), networkIpAddr) != EOK) {
            DISC_LOGE(DISC_COAP, "strcpy networkIpAddr fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_STRCPY_ERR;
        }
    } else {
        if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, g_localDeviceInfo->localIfInfo->networkName,
            sizeof(g_localDeviceInfo->localIfInfo->networkName), ifnameIdx) != SOFTBUS_OK) {
            DISC_LOGE(DISC_COAP, "get local device info from lnn fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_DISCOVER_GET_LOCAL_STR_FAILED;
        }
        if (strcpy_s(g_linkInfo[ifnameIdx].netWorkName, sizeof(g_localDeviceInfo->localIfInfo->networkName),
            g_localDeviceInfo->localIfInfo->networkName) != EOK) {
            DISC_LOGE(DISC_COAP, "strcpy networkname fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_STRCPY_ERR;
        }
        if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, g_localDeviceInfo->localIfInfo->networkIpAddr,
            sizeof(g_localDeviceInfo->localIfInfo->networkIpAddr), ifnameIdx) != SOFTBUS_OK) {
            DISC_LOGE(DISC_COAP, "get local device info from lnn fail.");
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            return SOFTBUS_DISCOVER_GET_LOCAL_STR_FAILED;
        }
    }
    
    g_localDeviceInfo->ifNums = 1;
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
    return SOFTBUS_OK;
}

static int32_t SetLocalDeviceInfo(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    if (g_localDeviceInfo == NULL) {
        DISC_LOGE(DISC_COAP, "disc coap not init");
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return SOFTBUS_DISCOVER_COAP_NOT_INIT;
    }

    int32_t deviceType = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceType);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "get local device type fail.");
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return ret;
    }
    g_localDeviceInfo->name = "";
    g_localDeviceInfo->deviceType = (uint32_t)deviceType;
    g_localDeviceInfo->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
    g_localDeviceInfo->hasDeviceHash = true;
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);

    ret = SetLocalLinkInfo(status, ifnameIdx);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_COAP,
        "set local linkInfo fail, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

void DiscCoapRecordLinkStatus(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_LOGE(status == LINK_STATUS_UP || status == LINK_STATUS_DOWN, DISC_COAP,
        "invlaid link status, status=%{public}d.", status);
    DISC_CHECK_AND_RETURN_LOGE(ifnameIdx >= 0 && ifnameIdx <= MAX_IF, DISC_COAP,
        "invlaid ifnameIdx, ifnameIdx=%{public}d.", ifnameIdx);
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, DISC_COAP, "lock fail");

    g_linkInfo[ifnameIdx].status = status;
    int32_t cnt = 0;
    for (int32_t i = 0; i <= MAX_IF; i++) {
        if (g_linkInfo[i].status == LINK_STATUS_UP) {
            cnt++;
        }
    }
    g_currentLinkUpNums = cnt;
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
}

void DiscCoapModifyNstackThread(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_LOGE(status == LINK_STATUS_UP || status == LINK_STATUS_DOWN, DISC_COAP,
        "invlaid link status, status=%{public}d.", status);
    DISC_CHECK_AND_RETURN_LOGE(ifnameIdx >= 0 && ifnameIdx <= MAX_IF, DISC_COAP,
        "invlaid ifnameIdx, ifnameIdx=%{public}d.", ifnameIdx);
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, DISC_COAP, "lock fail");

    if (status == LINK_STATUS_UP && g_currentLinkUpNums == 1) {
        int32_t ret = NSTACKX_ThreadInit();
        if (ret != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            DISC_LOGE(DISC_COAP, "init nstack thread fail, ret=%{public}d", ret);
            return;
        }
    } else if (status == LINK_STATUS_DOWN && g_currentLinkUpNums == 0) {
        NSTACKX_ThreadDeinit();
    }
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
}

static void FreeLocalDeviceInfo(NSTACKX_LocalDeviceInfoV2 *info)
{
    DISC_CHECK_AND_RETURN_LOGE(info != NULL, DISC_COAP, "info is null");
    SoftBusFree(info->name);
    SoftBusFree(info->deviceId);
    SoftBusFree(info->localIfInfo);
    SoftBusFree(info);
}

static NSTACKX_LocalDeviceInfoV2 *DupLocalDeviceInfo(NSTACKX_LocalDeviceInfoV2 *info)
{
    NSTACKX_LocalDeviceInfoV2 *dup = (NSTACKX_LocalDeviceInfoV2 *)SoftBusCalloc(sizeof(NSTACKX_LocalDeviceInfoV2));
    DISC_CHECK_AND_RETURN_RET_LOGE(dup != NULL, NULL, DISC_COAP, "malloc local device info fail");
    if (info->name != NULL) {
        dup->name = strdup(info->name);
        if (dup->name == NULL) {
            DISC_LOGE(DISC_COAP, "strdup name fail");
            FreeLocalDeviceInfo(dup);
            return NULL;
        }
    }
    if (info->deviceId != NULL) {
        dup->deviceId = strdup(info->deviceId);
        if (dup->deviceId == NULL) {
            DISC_LOGE(DISC_COAP, "strdup deviceId fail");
            FreeLocalDeviceInfo(dup);
            return NULL;
        }
    }
    if (info->ifNums == 1) {
        dup->localIfInfo = (NSTACKX_InterfaceInfo *)SoftBusCalloc(sizeof(NSTACKX_InterfaceInfo));
        if (dup->localIfInfo == NULL || memcpy_s(dup->localIfInfo, sizeof(NSTACKX_InterfaceInfo),
            info->localIfInfo, sizeof(NSTACKX_InterfaceInfo)) != EOK) {
            DISC_LOGE(DISC_COAP, "mem local device info If info fail");
            FreeLocalDeviceInfo(dup);
            return NULL;
        }
        dup->ifNums = info->ifNums;
    }
    dup->deviceType = info->deviceType;
    dup->deviceHash = info->deviceHash;
    dup->hasDeviceHash = info->hasDeviceHash;
    dup->businessType = info->businessType;
    return dup;
}

static void UpdateLocalIpByLocalNumInfo(int64_t accountId, int32_t port)
{
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, DISC_COAP, "lock fail");
    char *deviceIdStr = GetDeviceId();
    if (deviceIdStr == NULL) {
        DISC_LOGE(DISC_COAP, "get device id fail");
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return;
    }

    if (g_localDeviceInfo->deviceId != NULL) {
        DISC_LOGE(DISC_COAP, "g_localDeviceInfo->deviceId is not null");
        cJSON_free(deviceIdStr);
        g_localDeviceInfo->deviceId = NULL;
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return;
    }
    g_localDeviceInfo->deviceId = deviceIdStr;
    g_localDeviceInfo->deviceHash = (uint64_t)accountId;
    if (sprintf_s(g_localDeviceInfo->localIfInfo->serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,%s",
        port, g_serviceData) < 0) {
        DISC_LOGE(DISC_COAP, "write service data fail.");
        cJSON_free(deviceIdStr);
        g_localDeviceInfo->deviceId = NULL;
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return;
    }
    NSTACKX_LocalDeviceInfoV2 *dupInfo = DupLocalDeviceInfo(g_localDeviceInfo);
    if (dupInfo == NULL) {
        DISC_LOGE(DISC_COAP, "dup local device info fail");
        cJSON_free(deviceIdStr);
        g_localDeviceInfo->deviceId = NULL;
        (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
        return;
    }
    cJSON_free(deviceIdStr);
    g_localDeviceInfo->deviceId = NULL;
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
    int32_t ret = NSTACKX_RegisterDeviceV2(dupInfo);
    FreeLocalDeviceInfo(dupInfo);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP,
        "register local device info to dfinder fail, ret=%{public}d", ret);
    DiscCoapUpdateDevName();
}

void DiscCoapUpdateLocalIp(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_LOGE(status == LINK_STATUS_UP || status == LINK_STATUS_DOWN, DISC_COAP,
        "invlaid link status, status=%{public}d.", status);
    DISC_CHECK_AND_RETURN_LOGE(ifnameIdx >= 0 && ifnameIdx <= MAX_IF, DISC_COAP,
        "invlaid ifnameIdx, ifnameIdx=%{public}d.", ifnameIdx);

    DISC_CHECK_AND_RETURN_LOGE(SetLocalDeviceInfo(status, ifnameIdx) == SOFTBUS_OK, DISC_COAP,
        "link status change: set local device info fail");

    int64_t accountId = 0;
    int32_t port = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "get local account fail, err=%{public}d", ret);
    ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &port, ifnameIdx);
    DISC_CHECK_AND_RETURN_LOGE(ret != SOFTBUS_INVALID_PARAM, DISC_COAP, "get local port fail, err=%{public}d", ret);
    DISC_LOGI(DISC_COAP, "register ifname=%{public}s. status=%{public}s, port=%{public}d, accountInfo=%{public}s",
        g_localDeviceInfo->localIfInfo->networkName, status == LINK_STATUS_UP ? "up" : "down", port,
        accountId == 0 ? "without" : "with");
    UpdateLocalIpByLocalNumInfo(accountId, port);
}

void DiscCoapUpdateDevName(void)
{
    char localDevName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "get local device name fail, ret=%{public}d.", ret);

    uint32_t truncateLen = 0;
    if (CalculateMbsTruncateSize((const char *)localDevName, NSTACKX_MAX_DEVICE_NAME_LEN - 1, &truncateLen)
        != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "truncate device name fail");
        return;
    }
    localDevName[truncateLen] = '\0';
    char *anonymizedName = NULL;
    AnonymizeDeviceName(localDevName, &anonymizedName);
    DISC_LOGI(DISC_COAP, "register new local device name. localDevName=%{public}s", AnonymizeWrapper(anonymizedName));
    AnonymizeFree(anonymizedName);
    ret = NSTACKX_RegisterDeviceName(localDevName);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "register local device name fail, ret=%{public}d.", ret);
}

void DiscCoapUpdateAccount(void)
{
    DISC_LOGI(DISC_COAP, "accountId change, register new local accountId.");
    int64_t accountId = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &accountId);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_COAP, "get local account fail");
    NSTACKX_RegisterDeviceHash((uint64_t)accountId);
}

static void DeinitLocalInfo(void)
{
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, DISC_COAP, "lock fail");
    if (g_localDeviceInfo != NULL && g_localDeviceInfo->localIfInfo != NULL) {
        SoftBusFree(g_localDeviceInfo->localIfInfo);
        g_localDeviceInfo->localIfInfo = NULL;
    }
    if (g_localDeviceInfo != NULL) {
        SoftBusFree(g_localDeviceInfo);
        g_localDeviceInfo = NULL;
    }
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);

    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_discCoapInnerCbLock) == SOFTBUS_OK, DISC_COAP, "lock fail");
    if (g_discCoapInnerCb != NULL) {
        SoftBusFree(g_discCoapInnerCb);
        g_discCoapInnerCb = NULL;
    }
    (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);

    (void)SoftBusMutexDestroy(&g_localDeviceInfoLock);
    (void)SoftBusMutexDestroy(&g_discCoapInnerCbLock);
}

static int32_t InitLocalInfo(void)
{
    if (SoftBusMutexInit(&g_localDeviceInfoLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "g_localDeviceInfoLock init fail");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_discCoapInnerCbLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "g_discCoapInnerCbLock init fail");
        (void)SoftBusMutexDestroy(&g_localDeviceInfoLock);
        return SOFTBUS_NO_INIT;
    }

    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    if (g_localDeviceInfo == NULL) {
        g_localDeviceInfo = (NSTACKX_LocalDeviceInfoV2 *)SoftBusCalloc(sizeof(NSTACKX_LocalDeviceInfoV2));
        if (g_localDeviceInfo == NULL) {
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            DeinitLocalInfo();
            return SOFTBUS_MEM_ERR;
        }
        g_localDeviceInfo->localIfInfo = (NSTACKX_InterfaceInfo *)SoftBusCalloc(sizeof(NSTACKX_InterfaceInfo));
        if (g_localDeviceInfo->localIfInfo == NULL) {
            (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);
            DISC_LOGE(DISC_COAP, "mem local If info fail");
            DeinitLocalInfo();
            return SOFTBUS_MEM_ERR;
        }
    }
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);

    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_discCoapInnerCbLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    if (g_discCoapInnerCb == NULL) {
        g_discCoapInnerCb = (DiscInnerCallback *)SoftBusCalloc(sizeof(DiscInnerCallback));
        if (g_discCoapInnerCb == NULL) {
            (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
            DeinitLocalInfo();
            return SOFTBUS_MEM_ERR;
        }
    }
    (void)SoftBusMutexUnlock(&g_discCoapInnerCbLock);
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
        DISC_LOGI(DISC_COAP, "get disc max device num config fail, use default %{public}u", DEFAULT_MAX_DEVICE_NUM);
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
    char *anonymizedInfo = NULL;
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_localDeviceInfoLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_COAP, "lock fail");
    SOFTBUS_DPRINTF(fd, "\n-----------------NstackxLocalDevInfo-------------------\n");
    SOFTBUS_DPRINTF(fd, "name                                : %s\n", g_localDeviceInfo->name);
    Anonymize(g_localDeviceInfo->deviceId, &anonymizedInfo);
    SOFTBUS_DPRINTF(fd, "deviceId                            : %s\n", AnonymizeWrapper(anonymizedInfo));
    AnonymizeFree(anonymizedInfo);
    Anonymize(g_localDeviceInfo->localIfInfo->networkName, &anonymizedInfo);
    SOFTBUS_DPRINTF(fd, "localIfInfo networkName             : %s\n", AnonymizeWrapper(anonymizedInfo));
    AnonymizeFree(anonymizedInfo);
    SOFTBUS_DPRINTF(fd, "ifNums                              : %d\n", g_localDeviceInfo->ifNums);
    SOFTBUS_DPRINTF(fd, "deviceType                          : %d\n", g_localDeviceInfo->deviceType);
    SOFTBUS_DPRINTF(fd, "businessType                        : %d\n", g_localDeviceInfo->businessType);
    (void)SoftBusMutexUnlock(&g_localDeviceInfoLock);

    return SOFTBUS_OK;
}