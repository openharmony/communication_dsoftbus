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

#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "discovery_service.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "ohos_init.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_server_frame.h"

#define NET_WORK_NAME "wlan0"
#define TEST_CASE_NUM 10
#define MAXT_WAIT_COUNT 6
#define WIFI_CONFIG_INTERVAL 10
#define TEST_COUNT_INTREVAL 5
#define WAIT_SERVER_READY 5
#define MAX_TEST_COUNT 20
#define NSTACKX_MAX_IP_STRING_LEN 20
#define DISC_TEST_PKG_NAME "DISC_TEST"

static int32_t g_testSuccessCnt = 0;

static int GetSubscribeId(void)
{
    static int32_t subscribeId = 0;
    subscribeId++;
    return subscribeId;
}

static int GetPublishId(void)
{
    static int32_t publishId = 0;
    publishId++;
    return publishId;
}

static SubscribeInfo g_sInfo1 = {
    .subscribeId = 1,
    .medium = COAP,
    .mode = DISCOVER_MODE_PASSIVE,
    .freq = MID,
    .capability = "ddmpCapability",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3"),
    .isSameAccount = true,
    .isWakeRemote = false
};

static SubscribeInfo g_sInfo2 = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0,
    .isSameAccount = true,
    .isWakeRemote = false
};

static SubscribeInfo g_sInfo3 = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "ddmpCapability",
    .capabilityData = NULL,
    .dataLen = 0,
    .isSameAccount = true,
    .isWakeRemote = false
};

static PublishInfo g_pInfo1 = {
    .publishId = 1,
    .medium = COAP,
    .mode = DISCOVER_MODE_PASSIVE,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static PublishInfo g_pInfo2 = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};

static void OnDeviceFound(const DeviceInfo *device)
{
    if (device == NULL) {
        printf("ondevice found device is null\n");
        return;
    }
    printf("***********OnDeviceFound!!!!!******************************************\n");
    printf("id : %s.\n", device->devId);
    printf("name : %s.\n", device->devName);
    printf("device type : %u.\n", device->devType);
    printf("capNum : %u.\n", device->capabilityBitmapNum);
    for (uint32_t i = 0; i < device->capabilityBitmapNum; i++) {
        printf("capBitmap[%u] : %u.\n", i, device->capabilityBitmap[i]);
    }
    printf("addr num : %u.\n", device->addrNum);
    printf("ip : %s.\n", device->addr[0].info.ip.ip);
    printf("port : %d.\n", device->addr[0].info.ip.port);
    printf("connect type : %d.\n", device->addr[0].type);
    printf("peerUid : %s.\n", device->addr[0].peerUid);
    printf("hw account hash : %s.\n", device->hwAccountHash);
    printf("**********************************************************************\n");
    return;
}

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
    OnDeviceFound(device);
}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    printf("[client]TestDiscoverFailed, subscribeId = %d, failReason = %d\n", subscribeId, failReason);
}

static void TestDiscoverySuccess(int subscribeId)
{
    printf("[client]TestDiscoverySuccess, subscribeId = %d\n", subscribeId);
}

static void TestPublishSuccess(int publishId)
{
    printf("[client]TestPublishSuccess, publishId = %d\n", publishId);
}

static void TestPublishFail(int publishId, PublishFailReason reason)
{
    printf("[client]TestPublishFail, publishId = %d, PublishFailReason = %d\n", publishId, reason);
}

static IDiscoveryCallback g_subscribeCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverFailed = TestDiscoverFailed,
    .OnDiscoverySuccess = TestDiscoverySuccess
};

static IPublishCallback g_publishCb = {
    .OnPublishSuccess = TestPublishSuccess,
    .OnPublishFail = TestPublishFail
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

static void TestPassivePubSrv1(void)
{
    g_pInfo1.publishId = GetPublishId();
    if (PublishService(DISC_TEST_PKG_NAME, &g_pInfo1, &g_publishCb) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestActivePubSrv2(void)
{
    g_pInfo2.publishId = GetPublishId();
    if (PublishService(DISC_TEST_PKG_NAME, &g_pInfo2, &g_publishCb) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestUnPubSrv1(void)
{
    if (UnPublishService(DISC_TEST_PKG_NAME, g_pInfo1.publishId) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestUnPubSrv2(void)
{
    if (UnPublishService(DISC_TEST_PKG_NAME, g_pInfo2.publishId) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestPassiveStartDisc1(void)
{
    g_sInfo1.subscribeId = GetSubscribeId();
    if (StartDiscovery(DISC_TEST_PKG_NAME, &g_sInfo1, &g_subscribeCb) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestPassiveStartDisc2(void)
{
    g_sInfo2.subscribeId = GetSubscribeId();
    if (StartDiscovery(DISC_TEST_PKG_NAME, &g_sInfo2, &g_subscribeCb) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestActiveStartDisc3(void)
{
    g_sInfo3.subscribeId = GetSubscribeId();
    if (StartDiscovery(DISC_TEST_PKG_NAME, &g_sInfo3, &g_subscribeCb) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestStopDisc1(void)
{
    if (StopDiscovery(DISC_TEST_PKG_NAME, g_sInfo1.subscribeId) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestStopDisc2(void)
{
    if (StopDiscovery(DISC_TEST_PKG_NAME, g_sInfo2.subscribeId) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void TestStopDisc3(void)
{
    if (StopDiscovery(DISC_TEST_PKG_NAME, g_sInfo3.subscribeId) != SOFTBUS_OK) {
        printf("test failed, [%s].\n", __FUNCTION__);
        return;
    }
    g_testSuccessCnt++;
}

static void DiscoveryTestEntry(void)
{
    InitSoftBusServer();
    sleep(WAIT_SERVER_READY);

    char ip[NSTACKX_MAX_IP_STRING_LEN] = {0};
    int32_t testCnt = 0;
    GetLocalWifiIp(ip, NSTACKX_MAX_IP_STRING_LEN);
    while (testCnt < MAX_TEST_COUNT) {
        TestPassivePubSrv1();
        TestActivePubSrv2();
        TestPassiveStartDisc1();
        TestPassiveStartDisc2();
        TestActiveStartDisc3();
        sleep(TEST_COUNT_INTREVAL);
        TestUnPubSrv1();
        TestUnPubSrv2();
        TestStopDisc1();
        TestStopDisc2();
        TestStopDisc3();
        testCnt++;
        printf("*****test index: %d / %d *******\n", testCnt, MAX_TEST_COUNT);
        printf("*****success: %d / %d *****\n", g_testSuccessCnt, TEST_CASE_NUM * MAX_TEST_COUNT);
    }
}

SYS_SERVICE_INIT_PRI(DiscoveryTestEntry, 4); // 4 : priority
