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

#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "cJSON.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "nstackx.h"
#include "ohos_init.h"
#include "softbus_error_code.h"

#define DEVICE_NAME "HI3861"
#define DEVICE_ID "ABCDEFGFHIJKLMNOPQRSTVUWXYZ"
#define DEVICE_UDID "UDID"
#define NET_WORK_NAME "wlan0"
#define DEVICE_TYPE 0
#define VERSION "3.1.0"
#define AUTH_PORT 45576

#define MAXT_WAIT_COUNT 6
#define WIFI_CONFIG_INTERVAL 10
#define TEST_COUNT_INTREVAL 10
#define MAX_TEST_COUNT 20
#define TEST_DISCOVERY_INTERVAL 10
#define TEST_DISCOVERY_COUNT 10

static char *g_capData = NULL;
static int32_t g_onDeviceFoundCnt = 0;

static void OnDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if (deviceCount == 0) {
        return;
    }

    for (uint32_t i = 0; i < deviceCount; i++) {
        const NSTACKX_DeviceInfo *nstackxDeviceInfo = deviceList + i;
        if (nstackxDeviceInfo == NULL) {
            return;
        }
        if (((nstackxDeviceInfo->update) & 0x1) == 0) {
            printf("duplicate  device is not reported.[%u]\n", i);
            continue;
        }
        printf("deviceId = %s.\n", nstackxDeviceInfo->deviceId);
        printf("deviceName = %s.\n", nstackxDeviceInfo->deviceName);
        printf("capabilityBitmapNum = %d.\n", nstackxDeviceInfo->capabilityBitmapNum);
        for (uint32_t j = 0; j < nstackxDeviceInfo->capabilityBitmapNum; j++) {
            printf("capabilityBitmap = %d.\n", nstackxDeviceInfo->capabilityBitmap[j]);
        }
        printf("deviceType = %d.\n", nstackxDeviceInfo->deviceType);
        printf("reservedInfo = %s.\n", nstackxDeviceInfo->reservedInfo);
        g_onDeviceFoundCnt++;
    }
}

NSTACKX_Parameter g_nstackxParam = {
    .onDeviceListChanged = OnDeviceFound,
    .onDeviceFound = NULL,
    .onMsgReceived = NULL,
    .onDFinderMsgReceived = NULL
};

static void GetLocalWifiIp(char *ip, int32_t len)
{
    struct netif *wifiNetIf = NULL;
    ip4_addr_t ipaddr;
    int32_t ret;
    int32_t cnt = 0;
    while (cnt < MAXT_WAIT_COUNT) {
        cnt++;
        sleep(WIFI_CONFIG_INTERVAL);
        wifiNetIf = netifapi_netif_find(NET_WORK_NAME);
        if (wifiNetIf == NULL) {
            printf("netif find device failed.\n");
            continue;
        }
        ret = netifapi_netif_get_addr(wifiNetIf, &ipaddr, NULL, NULL);
        if (ret != 0) {
            printf("netif get ip addr failed, ret = %d.\n", ret);
            continue;
        }
        if (ipaddr.addr == 0) {
            printf("wifi is not connected.\n");
            continue;
        }
        break;
    }
    inet_ntop(AF_INET, &ipaddr, ip, len);
    printf("wifi connected, device ip = %s.\n", ip);
}

static char *GetDeviceId(void)
{
    char *formatString = NULL;
    cJSON *deviceIdObj = NULL;
    cJSON *deviceIdItem = NULL;

    do {
        deviceIdObj = cJSON_CreateObject();
        if (deviceIdObj == NULL) {
            break;
        }
        deviceIdItem = cJSON_CreateString(DEVICE_ID);
        if (deviceIdItem == NULL) {
            break;
        }
        if (!cJSON_AddItemToObject(deviceIdObj, DEVICE_UDID, deviceIdItem)) {
            break;
        }
        formatString = cJSON_PrintUnformatted(deviceIdObj);
    } while (0);

    if (deviceIdObj != NULL) {
        cJSON_Delete(deviceIdObj);
    }
    if (deviceIdItem != NULL) {
        cJSON_Delete(deviceIdItem);
    }
    return formatString;
}

static int32_t TestRegisterDeviceInfo(const char *ip)
{
    NSTACKX_LocalDeviceInfo *localDevInfo = (NSTACKX_LocalDeviceInfo *)malloc(sizeof(NSTACKX_LocalDeviceInfo));
    if (localDevInfo == NULL) {
        printf("nstackx local device info malloc failed.\n");
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    (void)memset_s(localDevInfo, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    char *udidStr = GetDeviceId();
    if (udidStr == NULL) {
        printf("get device id string failed.\n");
        free(localDevInfo);
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    if (strcpy_s(localDevInfo->deviceId, sizeof(localDevInfo->deviceId), udidStr) != EOK) {
        cJSON_free(udidStr);
        printf("strcpy_s device id failed.\n");
        free(localDevInfo);
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    cJSON_free(udidStr);
    if (strcpy_s(localDevInfo->name, sizeof(localDevInfo->name), DEVICE_NAME) != EOK ||
        strcpy_s(localDevInfo->networkIpAddr, sizeof(localDevInfo->networkIpAddr), ip) != EOK ||
        strcpy_s(localDevInfo->networkName, sizeof(localDevInfo->networkName), NET_WORK_NAME) != EOK ||
        strcpy_s(localDevInfo->version, sizeof(localDevInfo->version), VERSION) != EOK) {
        printf("strcpy_s failed.\n");
        free(localDevInfo);
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    localDevInfo->deviceType = DEVICE_TYPE;

    if (NSTACKX_RegisterDevice(localDevInfo) != 0) {
        printf("nstackx register device failed.\n");
        NSTACKX_Deinit();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    free(localDevInfo);
    return SOFTBUS_OK;
}

static int32_t TestRegisterCap(uint32_t capBitMapNum, uint32_t capBitMap[])
{
    if (capBitMapNum == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (NSTACKX_RegisterCapability(capBitMapNum, capBitMap) != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t TestSetFilterCap(uint32_t capBitMapNum, uint32_t capBitMap[])
{
    if (capBitMapNum == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (NSTACKX_SetFilterCapability(capBitMapNum, capBitMap) != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t TestRegisterServiceData(const unsigned char *serviceData, uint32_t dataLen)
{
    (void)serviceData;
    (void)dataLen;
    if (g_capData == NULL) {
        return SOFTBUS_DISCOVER_COAP_NOT_INIT;
    }

    int32_t authPort = AUTH_PORT;
    (void)memset_s(g_capData, NSTACKX_MAX_SERVICE_DATA_LEN, 0, NSTACKX_MAX_SERVICE_DATA_LEN);
    int32_t ret = sprintf_s(g_capData, NSTACKX_MAX_SERVICE_DATA_LEN, "port:%d,", authPort);
    if (ret == -1) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (NSTACKX_RegisterServiceData(g_capData) != SOFTBUS_OK) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

static int32_t TestInit(void)
{
    g_capData = (char *)malloc(NSTACKX_MAX_SERVICE_DATA_LEN);
    if (g_capData == NULL) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    (void)memset_s(g_capData, NSTACKX_MAX_SERVICE_DATA_LEN, 0, NSTACKX_MAX_SERVICE_DATA_LEN);
    if (NSTACKX_Init(&g_nstackxParam) != 0) {
        printf("nstackx init failed\n");
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

static void TestDeinit(void)
{
    if (g_capData != NULL) {
        free(g_capData);
        g_capData = NULL;
    }

    NSTACKX_Deinit();
}

static void NstackxTestEntry(void)
{
    char ip[NSTACKX_MAX_IP_STRING_LEN] = {0};
    int32_t testCnt = 0;
    while (testCnt < MAX_TEST_COUNT) {
        if (TestInit() != SOFTBUS_OK) {
            printf("init failed\n");
            return;
        }

        GetLocalWifiIp(ip, NSTACKX_MAX_IP_STRING_LEN);
        if (TestRegisterDeviceInfo(ip) != SOFTBUS_OK) {
            printf("register device info failed.\n");
            TestDeinit();
            return;
        }

        uint32_t cap[1] = {64};
        if (TestRegisterCap(1, cap) != SOFTBUS_OK) {
            printf("register cap info failed\n");
            TestDeinit();
            return;
        }

        if (TestSetFilterCap(1, cap) != SOFTBUS_OK) {
            printf("set filter cap failed\n");
            TestDeinit();
            return;
        }

        if (TestRegisterServiceData(NULL, 0) != SOFTBUS_OK) {
            printf("register service data failed\n");
            TestDeinit();
            return;
        }

        for (int32_t discTestCnt = 0; discTestCnt < TEST_DISCOVERY_COUNT;) {
            if (NSTACKX_StartDeviceFind() != 0) {
                printf("start device find failed\n");
                return;
            }
            sleep(TEST_DISCOVERY_INTERVAL);
            if (NSTACKX_StopDeviceFind() != 0) {
                printf("stop device find failed\n");
                return;
            }
            printf("disc test cnt = %d / %d\n", ++discTestCnt, TEST_DISCOVERY_COUNT);
        }

        testCnt++;
        sleep(TEST_COUNT_INTREVAL);
        TestDeinit();
        printf("test cnt = %d / %d\n", testCnt, MAX_TEST_COUNT);
    }
    printf("ondevice found cnt = %d / %d\n", g_onDeviceFoundCnt, MAX_TEST_COUNT * TEST_DISCOVERY_COUNT);
}

SYS_SERVICE_INIT_PRI(NstackxTestEntry, 4);
