/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "securec.h"

#include "disc_log.h"
#include "disc_manager.h"
#include "disc_raise_ble.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#define JSON_KEY_NOW_TIMES          "nowTimes"
#define JSON_KEY_HEARTBEAT_VALUE    "heartbeatValue"
#define JSON_KEY_HEARTBEAT_VERSION  "heartbeatVersion"
#define JSON_KEY_HEARTBEAT_TYPE     "heartbeatType"

static DiscInnerCallback *g_raiseInnerCb = NULL;

static int32_t RaiseBleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t RaiseBleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t RaiseBleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t RaiseBleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t RaiseBleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    DISC_LOGI(DISC_BLE, "raise is not support active discovery");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t RaiseBleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    DISC_LOGI(DISC_BLE, "raise start active discovery");
    return SOFTBUS_OK;
}

static int32_t RaiseBleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    DISC_LOGI(DISC_BLE, "raise stop active discovery");
    return SOFTBUS_OK;
}

static int32_t RaiseBleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    DISC_LOGI(DISC_BLE, "raise is not support active discovery");
    return SOFTBUS_NOT_IMPLEMENT;
}

static void RaiseBleLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    (void)status;
    (void)ifnameIdx;
}

static void RaiseBleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool RaiseBleIsConcern(uint32_t capability)
{
    static uint32_t mask = 1U << RAISE_HAND_CAPABILITY_BITMAP;
    return (capability & mask) != 0;
}

static DiscoveryFuncInterface g_discRaiseFuncInterface = {
    .Publish = RaiseBleStartActivePublish,
    .StartScan = RaiseBleStartPassivePublish,
    .Unpublish = RaiseBleStopActivePublish,
    .StopScan = RaiseBleStopPassivePublish,
    .StartAdvertise = RaiseBleStartActiveDiscovery,
    .Subscribe = RaiseBleStartPassiveDiscovery,
    .Unsubscribe = RaiseBleStopPassiveDiscovery,
    .StopAdvertise = RaiseBleStopActiveDiscovery,
    .LinkStatusChanged = RaiseBleLinkStatusChanged,
    .UpdateLocalDeviceInfo = RaiseBleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_raiseBleInterface = {
    .IsConcern = RaiseBleIsConcern,
    .mediumInterface = &g_discRaiseFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscRaiseBleInit(DiscInnerCallback *discInnerCb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(discInnerCb != NULL, NULL, DISC_BLE, "invalid param");
    g_raiseInnerCb = discInnerCb;
    return &g_raiseBleInterface;
}

void DiscRaiseBleDeinit(void)
{
    g_raiseInnerCb = NULL;
}

static int32_t CreateCustDataJson(DeviceInfo *device, RaiseHandDeviceInfo *deviceInfo)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(
        deviceInfo != NULL && device != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param");
    cJSON *jsonObj = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOGE(jsonObj != NULL, SOFTBUS_CREATE_JSON_ERR, DISC_BLE, "create json object fail");
    if (!AddNumberToJsonObject(jsonObj, JSON_KEY_NOW_TIMES, deviceInfo->nowTimes)) {
        DISC_LOGE(DISC_BLE, "add nowTimes to json fail");
        cJSON_Delete(jsonObj);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }

    int32_t heartbeatValueInt[HB_HEARTBEAT_VALUE_LEN];
    for (int i = 0; i < HB_HEARTBEAT_VALUE_LEN; ++i) {
        heartbeatValueInt[i] = (int32_t)deviceInfo->heartbeatValue[i];
    }
    if (!AddIntArrayToJsonObject(jsonObj, JSON_KEY_HEARTBEAT_VALUE, heartbeatValueInt, HB_HEARTBEAT_VALUE_LEN)) {
        DISC_LOGE(DISC_BLE, "add heartbeatValue to json fail");
        cJSON_Delete(jsonObj);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }

    if (!AddNumberToJsonObject(jsonObj, JSON_KEY_HEARTBEAT_VERSION, deviceInfo->heartbeatVersion)) {
        DISC_LOGE(DISC_BLE, "add heartbeatVersion to json fail");
        cJSON_Delete(jsonObj);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }

    if (!AddNumberToJsonObject(jsonObj, JSON_KEY_HEARTBEAT_TYPE, deviceInfo->heartbeatType)) {
        DISC_LOGE(DISC_BLE, "add heartbeatType to json fail");
        cJSON_Delete(jsonObj);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }

    char *custData = cJSON_PrintUnformatted(jsonObj);
    cJSON_Delete(jsonObj);
    DISC_CHECK_AND_RETURN_RET_LOGE(custData != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_BLE, "json print fail");
    if (strlen(custData) >= sizeof(device->custData)) {
        DISC_LOGE(DISC_BLE, "custData invaild length");
        cJSON_free(custData);
        return SOFTBUS_INVALID_PARAM;
    }
    errno_t errRet = strcpy_s(device->custData, sizeof(device->custData), custData);
    cJSON_free(custData);
    DISC_CHECK_AND_RETURN_RET_LOGE(errRet == EOK, SOFTBUS_PARSE_JSON_ERR, DISC_BLE, "copy cust data fail");
    return SOFTBUS_OK;
}

int32_t OnRaiseHandDeviceFound(RaiseHandDeviceInfo *deviceInfo)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceInfo != NULL && g_raiseInnerCb != NULL,
        SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param");
    DeviceInfo device = { 0 };
    device.capabilityBitmap[0] = 1U << RAISE_HAND_CAPABILITY_BITMAP;
    device.capabilityBitmapNum = 1;
    device.addrNum = 1;
    device.addr[0].type = CONNECTION_ADDR_BLE;
    device.devType = deviceInfo->deviceTypeId;
    
    DISC_CHECK_AND_RETURN_RET_LOGE(
        memcpy_s(device.devId, sizeof(device.devId), deviceInfo->deviceIdHash, DISC_MAX_DEVICE_ID_LEN) == EOK,
        SOFTBUS_MEM_ERR, DISC_BLE, "memcpy devId error");
    DISC_CHECK_AND_RETURN_RET_LOGE(
        memcpy_s(device.accountHash, sizeof(device.accountHash), deviceInfo->accountHash, MAX_ACCOUNT_HASH_LEN) == EOK,
        SOFTBUS_MEM_ERR, DISC_BLE, "memcpy accountHash error");
    errno_t errRet = strcpy_s(device.addr[0].info.ble.bleMac, BT_MAC_LEN, deviceInfo->bleMac);
    if (errRet != EOK) {
        DISC_LOGE(DISC_BLE, "copy bleMac fail");
        return SOFTBUS_STRCPY_ERR;
    }

    int32_t ret = CreateCustDataJson(&device, deviceInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_PARSE_JSON_ERR, DISC_BLE, "create cust data error");
    InnerDeviceInfoAddtions additions = { 0 };
    additions.medium = BLE;
    g_raiseInnerCb->OnDeviceFound(&device, &additions);
    return SOFTBUS_OK;
}
