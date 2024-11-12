/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "legacy/softbus_hisysevt_bus_center.h"

#include "comm_log.h"
#include "securec.h"
#include "legacy/softbus_adapter_hisysevent.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_common.h"

#define BUS_CENTER_PARAM_TOTAL_TIME "TOTAL_TIME"
#define BUS_CENTER_PARAM_TOTAL_COUNT "TOTAL_COUNT"
#define BUS_CENTER_PARAM_COUNT1 "COUNT1"
#define BUS_CENTER_PARAM_COUNT2 "COUNT2"
#define BUS_CENTER_PARAM_COUNT3 "COUNT3"
#define BUS_CENTER_PARAM_COUNT4 "COUNT4"
#define BUS_CENTER_PARAM_COUNT5 "COUNT5"
#define BUS_CENTER_PARAM_SOFT_BUS_VERSION "SOFT_BUS_VERSION"
#define BUS_CENTER_PARAM_LINK_TYPE "LINK_TYPE"
#define BUS_CENTER_PARAM_PACKAGE_VERSION "PACKAGE_VERSION"

#define BUS_CENTER_PARAM_FAIL_TOTAL_COUNT "FAIL_TOTAL_COUNT"
#define BUS_CENTER_PARAM_FAIL_TOTAL_TIME "FAIL_TOTAL_TIME"
#define BUS_CENTER_PARAM_CONNECT_FAIL_TOTAL_COUNT "CONNECT_FAIL_TOTAL_COUNT"
#define BUS_CENTER_PARAM_AUTH_FAIL_TOTAL_COUNT "AUTH_FAIL_TOTAL_COUNT"
#define BUS_CENTER_PARAM_EXCHANGE_FAIL_TOTAL_COUNT "EXCHANGE_FAIL_TOTAL_COUNT"

#define BUS_CENTER_ONLINE_DEVICE_NUM "ONLINE_DEVICE_NUM"
#define BUS_CENTER_BT_ONLINE_DEVICE_NUM "BT_ONLINE_DEVICE_NUM"
#define BUS_CENTER_WIFI_ONLINE_DEVICE_NUM "WIFI_ONLINE_DEVICE_NUM"
#define BUS_CENTER_PEER_DEVICE_TYPE "PEER_DEVICE_TYPE"
#define BUS_CENTER_PEER_SOFT_BUS_VERSION "PEER_SOFT_BUS_VERSION"
#define BUS_CENTER_PEER_DEVICE_NAME "PEER_DEVICE_NAME"
#define BUS_CENTER_INSERT_PROFILE_RESULT "INSERT_PROFILE_RESULT"
#define BUS_CENTER_PEER_PACKAGE_VERSION "PEER_PACKAGE_VERSION"

#define FAULT_EVT_PARAM_MODULE_TYPE "MODULE_TYPE"
#define FAULT_EVT_PARAM_BUSUNINESS_NAME "BUSUNINESS_NAME"
#define FAULT_EVT_PARAM_ERROR_CODE "ERROR_CODE"
#define FAULT_EVT_PARAM_CALLER_PACKAGE_NAME "CALLER_PACKAGE_NAME"
#define FAULT_EVT_PARAM_REMOTE_BIZ_TRUNCATED_UUID "REMOTE_BIZ_TRUNCATED_UUID"
#define FAULT_EVT_PARAM_CHANNEL_QUALITY "CHANNEL_QUALITY"
#define FAULT_EVT_PARAM_CONNECTION_NUM "CONNECTION_NUM"
#define FAULT_EVT_PARAM_NIGHT_MODE "NIGHT_MODE"
#define FAULT_EVT_PARAM_WIFI_STATUS "WIFI_STATUS"
#define FAULT_EVT_PARAM_BLUETOOTH_STATUS "BLUETOOTH_STATUS"
#define FAULT_EVT_PARAM_CALLER_APP_MODE "CALLER_APP_MODE"
#define FAULT_EVT_PARAM_SUB_ERROR_CODE "SUB_ERROR_CODE"
#define FAULT_EVT_PARAM_CONN_BR_NUM "CONN_BR_NUM"
#define FAULT_EVT_PARAM_CONN_BLE_NUM "CONN_BLE_NUM"
#define FAULT_EVT_PARAM_BLE_BROADCAST_STATUS "BLUETOOTH_BROADCAST_STATUS"
#define FAULT_EVT_PARAM_BLE_SCAN_STATUS "BLUETOOTH_SCAN_STATUS"

#define BUS_CENTER_START_DISCOVERY_COUNT "START_DISCOVERY_COUNT"
#define BUS_CENTER_SEND_BROADCAST_COUNT "SEND_BROADCAST_COUNT"
#define BUS_CENTER_RECEIVER_BROADCAST_COUNT "RECEIVE_BROADCAST_COUNT"
#define BUS_CENTER_DEVICE_FOUND_COUNT "DEVICE_FOUND_COUNT"
#define BUS_CENTER_BUSINESS_DISCOVERY_COUNT "BUSINESS_DISCOVERY_COUNT"
#define BUS_CENTER_BUSINESS_DISCOVERY_DETAIL "BUSINESS_DISCOVERY_DETAIL"

#define BUS_CENTER_APP_NAME "APP_NAME"
#define BUS_CENTER_APP_DISCOVERY_COUNT "APP_DISCOVERY_COUNT"

#define BUS_CENTER_DURATION_PARAM_NUM 10
#define ONLINE_DURATION_STATISTIC_PARAM_NUM 9
#define AUTH_RESULT_STATISTIC_PARAM_NUM 15
#define ONLINE_INFO_STATISTIC_PARAM_NUM 10
#define SOFTBUS_FAULT_EVT_PARAM_NUM 21
#define DEV_DISCOVERY_STATISTIC_PARAM_NUM 8
#define APP_DISCOVERY_STATISTIC_PARAM_NUM 2

#define SECOND_TO_MSENC 1000
#define MILLISECOND_TO_MICRO 1000

typedef enum {
    LNN_TIME_STANDARD_S = 800, // ms
    LNN_TIME_STANDARD_A = 1000,
    LNN_TIME_STANDARD_B = 1200,
    LNN_TIME_STANDARD_C = 1500,
    LNN_TIME_STANDARD_D = 1800,
} BusCenterThreshold;

typedef enum {
    ONLINE_TIME_STANDARD_S = 10, // s
    ONLINE_TIME_STANDARD_A = 30,
    ONLINE_TIME_STANDARD_B = 300,
    ONLINE_TIME_STANDARD_C = 600,
    ONLINE_TIME_STANDARD_D = 900,
} OnlineThreshold;

typedef enum {
    AUTH_TIME_STANDARD_S = 2000, // ms
    AUTH_TIME_STANDARD_A = 2500,
    AUTH_TIME_STANDARD_B = 3000,
    AUTH_TIME_STANDARD_C = 3500,
    AUTH_TIME_STANDARD_D = 4000,
} AuthThreshold;

typedef struct {
    SoftBusMutex lock;
    uint64_t totalTime;
    char softBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char packName[SOFTBUS_HISYSEVT_NAME_LEN];
    uint8_t linkType;
    uint32_t totalCount;
    uint32_t count1;
    uint32_t count2;
    uint32_t count3;
    uint32_t count4;
    uint32_t count5;
} BusCenterDuraRecord;

typedef struct {
    SoftBusMutex lock;
    uint64_t totalTime;
    uint32_t totalCount;
    uint32_t count1;
    uint32_t count2;
    uint32_t count3;
    uint32_t count4;
    uint32_t count5;
    char softBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char packName[SOFTBUS_HISYSEVT_NAME_LEN];
} DevOnlineDurRecord;

typedef struct {
    uint8_t linkType;
    char softBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char packName[SOFTBUS_HISYSEVT_NAME_LEN];
    uint32_t authTotalCount;
    uint32_t authCount1;
    uint32_t authCount2;
    uint32_t authCount3;
    uint32_t authCount4;
    uint32_t authCount5;
    uint32_t failTotalCount;
    uint32_t connFailTotalCount;
    uint32_t authFailTotalCount;
    uint32_t exchangeFailTotalCount;
    uint64_t failTotalTime;
    uint64_t authTotalTime;
    SoftBusMutex lock;
} AuthResultRecord;

typedef struct {
    SoftBusEvtParamType paramType;
    char paramName[SOFTBUS_HISYSEVT_NAME_LEN];
} SoftBusEvtParamSize;

typedef struct {
    char udid[UDID_BUF_LEN];
    uint32_t onlineDevNum;
    uint32_t btOnlineDevNum;
    uint32_t wifiOnlineDevNum;
    ListNode node;
} DevUdidNode;

typedef struct {
    char businessDiscoveryDetail[SOFTBUS_HISYSEVT_NAME_LEN];
    char softBusVer[SOFTBUS_HISYSEVT_NAME_LEN];
    char packName[SOFTBUS_HISYSEVT_NAME_LEN];
    uint64_t startDiscoveryCnt;
    uint64_t sendBroadCastCnt;
    uint64_t recvBroadCastCnt;
    uint64_t devFoundCnt;
    uint64_t businessDiscoveryCnt;
    SoftBusMutex lock;
} DevDiscoveryRecord;

static SoftBusEvtParamSize g_busCenterDurStaticParam[BUS_CENTER_DURATION_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_LINK_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_PARAM_TOTAL_TIME},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT1},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT2},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT3},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT4},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT5},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_PACKAGE_VERSION},
};

static SoftBusEvtParamSize g_authResultParam[AUTH_RESULT_STATISTIC_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_LINK_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_PARAM_TOTAL_TIME},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT1},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT2},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT3},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT4},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_COUNT5},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_FAIL_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_PARAM_FAIL_TOTAL_TIME},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_CONNECT_FAIL_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_AUTH_FAIL_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_EXCHANGE_FAIL_TOTAL_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_PACKAGE_VERSION},
};

static SoftBusEvtParamSize g_onlineInfoStaticParam[ONLINE_INFO_STATISTIC_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_ONLINE_DEVICE_NUM},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_BT_ONLINE_DEVICE_NUM},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_WIFI_ONLINE_DEVICE_NUM},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PEER_DEVICE_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_INSERT_PROFILE_RESULT},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PEER_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PEER_DEVICE_NAME},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PEER_PACKAGE_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_PACKAGE_VERSION},
};

static SoftBusEvtParamSize g_softBusFailEvtParam[SOFTBUS_FAULT_EVT_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_UINT32, FAULT_EVT_PARAM_MODULE_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_PARAM_LINK_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_FLOAT, FAULT_EVT_PARAM_CHANNEL_QUALITY},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_ERROR_CODE},
    {SOFTBUS_EVT_PARAMTYPE_INT32, BUS_CENTER_PEER_DEVICE_TYPE},
    {SOFTBUS_EVT_PARAMTYPE_INT32, BUS_CENTER_ONLINE_DEVICE_NUM},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_CONNECTION_NUM},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_NIGHT_MODE},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_WIFI_STATUS},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_BLUETOOTH_STATUS},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_CALLER_APP_MODE},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_SUB_ERROR_CODE},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_CONN_BR_NUM},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_CONN_BLE_NUM},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_BLE_BROADCAST_STATUS},
    {SOFTBUS_EVT_PARAMTYPE_INT32, FAULT_EVT_PARAM_BLE_SCAN_STATUS},
    {SOFTBUS_EVT_PARAMTYPE_STRING, FAULT_EVT_PARAM_BUSUNINESS_NAME},
    {SOFTBUS_EVT_PARAMTYPE_STRING, FAULT_EVT_PARAM_CALLER_PACKAGE_NAME},
    {SOFTBUS_EVT_PARAMTYPE_STRING, FAULT_EVT_PARAM_REMOTE_BIZ_TRUNCATED_UUID},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_PACKAGE_VERSION},
};

static SoftBusEvtParamSize g_devDiscoveryStaticParam[DEV_DISCOVERY_STATISTIC_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_START_DISCOVERY_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_SEND_BROADCAST_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_RECEIVER_BROADCAST_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_DEVICE_FOUND_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, BUS_CENTER_BUSINESS_DISCOVERY_COUNT},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_BUSINESS_DISCOVERY_DETAIL},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_SOFT_BUS_VERSION},
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_PARAM_PACKAGE_VERSION},
};

static SoftBusEvtParamSize g_appDiscoveryStaticParam[APP_DISCOVERY_STATISTIC_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_STRING, BUS_CENTER_APP_NAME},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, BUS_CENTER_APP_DISCOVERY_COUNT},
};

static bool g_isBusCenterDfxInit = false;
static char *g_packageVersion = "PackageVersion";
static char *g_softbusVersion = "hm.1.0.0";
static char *g_discoveryDetail = "DiscoveryDetail";
static char *g_busuninessName = "DefaultBusName";
static char *g_callerPkgName = "DefaultPkgName";
static char *g_remoteBizUuid = "DefaultBizUuid";
static char *g_deviceName = "DefaultDevName";

static SoftBusMutex g_devUdidLock;
static SoftBusMutex g_appDiscLock;
static LIST_HEAD(g_devUdidList);
static LIST_HEAD(g_appDiscList);
BusCenterDuraRecord g_busCenterRecord[SOFTBUS_HISYSEVT_LINK_TYPE_BUTT];
AuthResultRecord g_authResultRecord[SOFTBUS_HISYSEVT_LINK_TYPE_BUTT];
DevOnlineDurRecord g_devOnlineDurRecord;
DevDiscoveryRecord g_devDiscoveryRecord;

int64_t LnnUpTimeMs(void)
{
    SoftBusSysTime t;
    t.sec = 0;
    t.usec = 0;
    SoftBusGetTime(&t);
    int64_t when = t.sec * SECOND_TO_MSENC + t.usec / MILLISECOND_TO_MICRO;
    return when;
}

static int32_t AddUdidInfoNodeToList(OnlineDeviceInfo *info, const char *udid)
{
    if (udid == NULL || info == NULL) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    DevUdidNode *udidNode = SoftBusCalloc(sizeof(DevUdidNode));
    if (udidNode == NULL) {
        COMM_LOGE(COMM_EVENT, "malloc udid info node fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(udidNode->udid, UDID_BUF_LEN, udid) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy_s udid fail");
        SoftBusFree(udidNode);
        return SOFTBUS_STRCPY_ERR;
    }
    udidNode->onlineDevNum = info->onlineDevNum;
    udidNode->btOnlineDevNum = info->btOnlineDevNum;
    udidNode->wifiOnlineDevNum = info->wifiOnlineDevNum;
    if (SoftBusMutexLock(&g_devUdidLock) != SOFTBUS_OK) {
        SoftBusFree(udidNode);
        COMM_LOGE(COMM_EVENT, "device udid list lock fail");
        return false;
    }
    ListTailInsert(&g_devUdidList, &udidNode->node);
    (void)SoftBusMutexUnlock(&g_devUdidLock);
    return SOFTBUS_OK;
}

static void ReleaseDevUdidInfoNode(void)
{
    if (SoftBusMutexLock(&g_devUdidLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "device udid list lock fail");
        return;
    }
    DevUdidNode *item = NULL;
    DevUdidNode *nextItem = NULL;
    if (g_devUdidList.prev == NULL && g_devUdidList.next == NULL) {
        COMM_LOGE(COMM_EVENT, "g_devUdidList is NULL");
        ListInit(&g_devUdidList);
        (void)SoftBusMutexUnlock(&g_devUdidLock);
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_devUdidList, DevUdidNode, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    ListInit(&g_devUdidList);
    (void)SoftBusMutexUnlock(&g_devUdidLock);
}

static bool IsUdidAlreadyReported(OnlineDeviceInfo *info, const char *udid)
{
    if (SoftBusMutexLock(&g_devUdidLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "device udid list lock fail");
        return false;
    }
    DevUdidNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_devUdidList, DevUdidNode, node) {
        if (strcmp(item->udid, udid) == 0 && item->onlineDevNum == info->onlineDevNum &&
            item->btOnlineDevNum == info->btOnlineDevNum && item->wifiOnlineDevNum == info->wifiOnlineDevNum) {
            (void)SoftBusMutexUnlock(&g_devUdidLock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_devUdidLock);
    return false;
}

static int32_t InitDevDiscoveryEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    if (SoftBusMutexInit(&(g_devDiscoveryRecord.lock), &mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static void CleanDevDiscoveryRecord(void)
{
    if (SoftBusMutexLock(&(g_devDiscoveryRecord.lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return;
    }
    g_devDiscoveryRecord.startDiscoveryCnt = 0;
    g_devDiscoveryRecord.sendBroadCastCnt = 0;
    g_devDiscoveryRecord.recvBroadCastCnt = 0;
    g_devDiscoveryRecord.devFoundCnt = 0;
    g_devDiscoveryRecord.businessDiscoveryCnt = 0;
    (void)SoftBusMutexUnlock(&(g_devDiscoveryRecord.lock));
}

static int32_t SetDevDiscStaticMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < DEV_DISCOVERY_STATISTIC_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_devDiscoveryStaticParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_devDiscoveryStaticParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "copy param fail. paramName=%{public}s", g_devDiscoveryStaticParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetDevDiscStaticMsgParamValve(SoftBusEvtReportMsg *msg, DevDiscoveryRecord *record)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u64v = record->startDiscoveryCnt;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u64v = record->sendBroadCastCnt;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u64v = record->recvBroadCastCnt;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u64v = record->devFoundCnt;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.u64v = record->businessDiscoveryCnt;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_discoveryDetail) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy discoveryDetail fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_softbusVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy softbus version fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_packageVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy package ver fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateDevDiscStaticMsg(SoftBusEvtReportMsg *msg)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DEVICE_DISCOVERY) != EOK) {
        COMM_LOGE(COMM_EVENT,
            "strcpy evtname fail. STATISTIC_EVT_DEVICE_DISCOVERY=%{public}s", STATISTIC_EVT_DEVICE_DISCOVERY);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = DEV_DISCOVERY_STATISTIC_PARAM_NUM;
    int32_t ret = SetDevDiscStaticMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "device discovery statistic msg set param name fail");
        return ret;
    }
    if (SoftBusMutexLock(&(g_devDiscoveryRecord.lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "create device disc static msg lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ret = SetDevDiscStaticMsgParamValve(msg, &g_devDiscoveryRecord);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "device discovery statistic msg set param valve fail");
        (void)SoftBusMutexUnlock(&(g_devDiscoveryRecord.lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_devDiscoveryRecord.lock));
    return SOFTBUS_OK;
}

static bool IsNeedReportDevDiscoveryRecordEvt(void)
{
    DevDiscoveryRecord *record = &g_devDiscoveryRecord;
    if (SoftBusMutexLock(&(record->lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return false;
    }
    if ((record->businessDiscoveryCnt == 0) && (record->devFoundCnt == 0) && (record->recvBroadCastCnt == 0)
        && (record->sendBroadCastCnt == 0) && (record->startDiscoveryCnt == 0)) {
        (void)SoftBusMutexUnlock(&(record->lock));
        return false;
    }
    (void)SoftBusMutexUnlock(&(record->lock));
    return true;
}

static int32_t ReportDevDiscoveryRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report device discovery record evt enter");
    if (!IsNeedReportDevDiscoveryRecordEvt()) {
        COMM_LOGD(COMM_EVENT, "this time do not need report device discovery record evt");
        return SOFTBUS_OK;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(DEV_DISCOVERY_STATISTIC_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create discovery statistic report msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    do {
        ret = SoftBusCreateDevDiscStaticMsg(msg);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "create device discovery statistic report msg fail");
            break;
        }
        ret = SoftbusWriteHisEvt(msg);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "write device discovery statistic hisevt fail");
            break;
        }
    } while (false);
    SoftbusFreeEvtReportMsg(msg);
    CleanDevDiscoveryRecord();
    return ret;
}

static void ReleaseAppDiscInfoNode(void)
{
    if (SoftBusMutexLock(&g_appDiscLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "release app disc info node lock fail");
        return;
    }
    AppDiscNode *item = NULL;
    AppDiscNode *nextItem = NULL;
    if (g_appDiscList.prev == NULL && g_appDiscList.next == NULL) {
        COMM_LOGE(COMM_EVENT, "g_appDiscList is NULL");
        ListInit(&g_appDiscList);
        (void)SoftBusMutexUnlock(&g_appDiscLock);
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_appDiscList, AppDiscNode, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    ListInit(&g_appDiscList);
    (void)SoftBusMutexUnlock(&g_appDiscLock);
}

static int32_t AddAppDiscInfoNodeToList(AppDiscNode *discNode)
{
    if (discNode == NULL) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AppDiscNode *newDiscNode = SoftBusCalloc(sizeof(AppDiscNode));
    if (newDiscNode == NULL) {
        COMM_LOGE(COMM_EVENT, "malloc AppDiscNode fail");
        return SOFTBUS_MALLOC_ERR;
    }
    newDiscNode->appDiscCnt = discNode->appDiscCnt;
    if (strcpy_s(newDiscNode->appName, SOFTBUS_HISYSEVT_NAME_LEN, discNode->appName) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy app name fail");
        SoftBusFree(newDiscNode);
        return SOFTBUS_STRCPY_ERR;
    }
    if (SoftBusMutexLock(&g_appDiscLock) != SOFTBUS_OK) {
        SoftBusFree(newDiscNode);
        COMM_LOGE(COMM_EVENT, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_appDiscList, &newDiscNode->node);
    (void)SoftBusMutexUnlock(&g_appDiscLock);
    return SOFTBUS_OK;
}

static int32_t SetAppDiscStaticMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < APP_DISCOVERY_STATISTIC_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_appDiscoveryStaticParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_appDiscoveryStaticParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT,
                "strcpy_s param name fail. paramName=%{public}s", g_appDiscoveryStaticParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetAppDiscStaticMsgParamValve(SoftBusEvtReportMsg *msg, AppDiscNode *discNode)
{
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        discNode->appName) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy app name fail");
        return SOFTBUS_STRCPY_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.i32v = discNode->appDiscCnt;
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateAppDiscStaticMsg(SoftBusEvtReportMsg *msg, AppDiscNode *discNode)
{
    if (msg == NULL || discNode == NULL) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_APP_DISCOVERY) != EOK) {
        COMM_LOGE(COMM_EVENT,
            "strcpy evt name fail. STATISTIC_EVT_APP_DISCOVERY=%{public}s", STATISTIC_EVT_APP_DISCOVERY);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = APP_DISCOVERY_STATISTIC_PARAM_NUM;
    int32_t ret = SetAppDiscStaticMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "app discovery statistic msg set param name fail");
        return ret;
    }
    ret = SetAppDiscStaticMsgParamValve(msg, discNode);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "app discovery statistic msg set param valve fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ReportAppDiscoveryRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report app discovery record evt enter");
    if (SoftBusMutexLock(&g_appDiscLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "app disc list lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (IsListEmpty(&g_appDiscList)) {
        COMM_LOGE(COMM_EVENT, "app disc list count=0");
        (void)SoftBusMutexUnlock(&g_appDiscLock);
        return SOFTBUS_OK;
    }
    AppDiscNode *item = NULL;
    int32_t ret = SOFTBUS_OK;
    LIST_FOR_EACH_ENTRY(item, &g_appDiscList, AppDiscNode, node) {
        SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(APP_DISCOVERY_STATISTIC_PARAM_NUM);
        if (msg == NULL) {
            COMM_LOGE(COMM_EVENT, "create app discovery statistic report msg fail");
            (void)SoftBusMutexUnlock(&g_appDiscLock);
            return SOFTBUS_MEM_ERR;
        }
        do {
            ret = SoftBusCreateAppDiscStaticMsg(msg, item);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "create app discovery statistic report msg fail");
                break;
            }
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "write app discovery statistic hisevt fail");
                break;
            }
        } while (false);
        SoftbusFreeEvtReportMsg(msg);
        if (ret != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&g_appDiscLock);
            return ret;
        }
    }
    (void)SoftBusMutexUnlock(&g_appDiscLock);
    ReleaseAppDiscInfoNode();
    return ret;
}

int32_t SoftBusRecordDiscoveryResult(DiscoveryStage stage, AppDiscNode *discNode)
{
    if (stage < START_DISCOVERY || stage > BUSINESS_DISCOVERY) {
        COMM_LOGE(COMM_EVENT, "record discovery result param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_devDiscoveryRecord.lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "device discovery result record lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    bool isNeedToDiscList = false;
    switch (stage) {
        case START_DISCOVERY:
            g_devDiscoveryRecord.startDiscoveryCnt++;
            break;
        case SEND_BROADCAST:
            g_devDiscoveryRecord.sendBroadCastCnt++;
            break;
        case RECV_BROADCAST:
            g_devDiscoveryRecord.recvBroadCastCnt++;
            break;
        case DEVICE_FOUND:
            g_devDiscoveryRecord.devFoundCnt++;
            break;
        case BUSINESS_DISCOVERY:
            isNeedToDiscList = true;
            g_devDiscoveryRecord.businessDiscoveryCnt++;
            break;
        default:
            break;
    }
    (void)SoftBusMutexUnlock(&(g_devDiscoveryRecord.lock));
    if (isNeedToDiscList && (discNode == NULL || AddAppDiscInfoNodeToList(discNode) != SOFTBUS_OK)) {
        ret = SOFTBUS_STRCPY_ERR;
    }
    return ret;
}

static int32_t SetBusCenterFaultMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < SOFTBUS_FAULT_EVT_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_softBusFailEvtParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_softBusFailEvtParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s param name fail. paramName=%{public}s", g_softBusFailEvtParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetBusCenterFaultMsgParamValve(SoftBusEvtReportMsg *msg, SoftBusFaultEvtInfo *info)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u32v = info->moduleType;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = info->linkType;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.f = info->channelQuality;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.i32v = info->errorCode;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.i32v = info->peerDevType;
    msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.i32v = info->onLineDevNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.i32v = info->connNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.i32v = info->nightMode;
    msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT].paramValue.i32v = info->wifiStatue;
    msg->paramArray[SOFTBUS_EVT_PARAM_NINE].paramValue.i32v = info->bleStatue;
    msg->paramArray[SOFTBUS_EVT_PARAM_TEN].paramValue.i32v = info->callerAppMode;
    msg->paramArray[SOFTBUS_EVT_PARAM_ELEVEN].paramValue.i32v = info->subErrCode;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWELVE].paramValue.i32v = info->connBrNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_THIRTEEN].paramValue.i32v = info->connBleNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOURTEEN].paramValue.i32v = info->bleBradStatus;
    msg->paramArray[SOFTBUS_EVT_PARAM_FIFTEEN].paramValue.i32v = info->bleScanStatus;
    do {
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SIXTEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_busuninessName) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy business name fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SEVENTEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_callerPkgName) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy caller pack name fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_EIGHTEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_remoteBizUuid) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy remote biz uuid fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_NINETEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_softbusVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy softbus version fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWENTY].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_packageVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy package version fail");
            break;
        }
        return SOFTBUS_OK;
    } while (false);
    return SOFTBUS_STRCPY_ERR;
}

static int32_t SoftBusCreateBusCenterFaultMsg(SoftBusEvtReportMsg *msg, SoftBusFaultEvtInfo *info)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, FAULT_EVT_BUS_CENTER) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy_s evt name fail. FAULT_EVT_BUS_CENTER=%{public}s", FAULT_EVT_BUS_CENTER);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_FAULT;
    msg->paramNum = SOFTBUS_FAULT_EVT_PARAM_NUM;
    int32_t ret = SetBusCenterFaultMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param name fail");
        return ret;
    }
    ret = SetBusCenterFaultMsgParamValve(msg, info);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param valve fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusReportBusCenterFaultEvt(SoftBusFaultEvtInfo *info)
{
    if (info == NULL) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_FAULT_EVT_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "alloc bus center fault evt report msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    info->errorCode = GetErrorCodeEx(info->errorCode);
    SoftBusCreateBusCenterFaultMsg(msg, info);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "sys evt write buscenter fault msg fail");
    }
    return ret;
}

static int32_t InitAuthItemMutexLock(SoftBusLinkType linkType, SoftBusMutexAttr *mutexAttr)
{
    if (SoftBusMutexInit(&(g_authResultRecord[linkType].lock), mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitAuthEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    int32_t ret = SOFTBUS_OK;
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        ret = InitAuthItemMutexLock(linkType, &mutexAttr);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "lock fail");
            break;
        }
    }
    return ret;
}

static void DeinitAuthEvtMutexLock(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        (void)SoftBusMutexDestroy(&(g_authResultRecord[linkType].lock));
    }
}

static int32_t InitBusCenterItemMutexLock(SoftBusLinkType linkType, SoftBusMutexAttr *mutexAttr)
{
    if (SoftBusMutexInit(&(g_busCenterRecord[linkType].lock), mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitBusCenterEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    int32_t ret = SOFTBUS_OK;
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        ret = InitBusCenterItemMutexLock(linkType, &mutexAttr);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "lock fail");
            break;
        }
    }
    return ret;
}

static void DeinitBusCenterEvtMutexLock(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        (void)SoftBusMutexDestroy(&(g_busCenterRecord[linkType].lock));
    }
}

static int32_t InitDevOnlineDurEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    if (SoftBusMutexInit(&(g_devOnlineDurRecord.lock), &mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetOnlineInfoMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < ONLINE_INFO_STATISTIC_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_onlineInfoStaticParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_onlineInfoStaticParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT,
                "strcpy_s param name fail. paramName=%{public}s", g_onlineInfoStaticParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetOnlineInfoMsgParamValve(SoftBusEvtReportMsg *msg, OnlineDeviceInfo *info)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.i32v = (int32_t)info->onlineDevNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.i32v = (int32_t)info->btOnlineDevNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.i32v = (int32_t)info->wifiOnlineDevNum;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.i32v = (int32_t)info->peerDevType;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.i32v = info->insertFileResult;
    do {
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_softbusVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s peer softbus version fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_deviceName) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s peer device name fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_softbusVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s local softbus verion fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_packageVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s peer package version fail");
            break;
        }
        if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_NINE].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
            g_packageVersion) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s local package version fail");
            break;
        }
        return SOFTBUS_OK;
    } while (false);
    return SOFTBUS_STRCPY_ERR;
}

static int32_t SoftBusCreateEvtMsgByInfo(SoftBusEvtReportMsg *msg, OnlineDeviceInfo *info)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DEVICE_ONLINE) != EOK) {
        COMM_LOGE(COMM_EVENT,
            "strcpy_s evtname fail. STATISTIC_EVT_DEVICE_ONLINE=%{public}s", STATISTIC_EVT_DEVICE_ONLINE);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = ONLINE_INFO_STATISTIC_PARAM_NUM;
    int32_t ret = SetOnlineInfoMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set online info msg param name fail");
        return ret;
    }
    ret = SetOnlineInfoMsgParamValve(msg, info);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set online info msg param valve fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusReportDevOnlineEvt(OnlineDeviceInfo *info, const char *udid)
{
    if (info == NULL || udid == NULL) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsUdidAlreadyReported(info, udid)) {
        COMM_LOGE(COMM_EVENT, "device has already been reported");
        return SOFTBUS_OK;
    }
    int32_t ret = AddUdidInfoNodeToList(info, udid);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "add online device info to list fail");
        return ret;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(ONLINE_INFO_STATISTIC_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "alloc device online evt report msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    SoftBusCreateEvtMsgByInfo(msg, info);
    ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "sysevt write online device info msg fail");
    }
    return ret;
}

static void CleanAuthResultRecord(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        if (SoftBusMutexLock(&(g_authResultRecord[linkType].lock)) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "lock fail");
            return;
        }
        g_authResultRecord[linkType].linkType = linkType;
        g_authResultRecord[linkType].authTotalTime = 0;
        g_authResultRecord[linkType].authTotalCount = 0;
        g_authResultRecord[linkType].authCount1 = 0;
        g_authResultRecord[linkType].authCount2 = 0;
        g_authResultRecord[linkType].authCount3 = 0;
        g_authResultRecord[linkType].authCount4 = 0;
        g_authResultRecord[linkType].authCount5 = 0;
        g_authResultRecord[linkType].failTotalTime = 0;
        g_authResultRecord[linkType].failTotalCount = 0;
        g_authResultRecord[linkType].connFailTotalCount = 0;
        g_authResultRecord[linkType].authFailTotalCount = 0;
        g_authResultRecord[linkType].exchangeFailTotalCount = 0;
        (void)SoftBusMutexUnlock(&(g_authResultRecord[linkType].lock));
    }
}

static int32_t SetAuthResultMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < AUTH_RESULT_STATISTIC_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_authResultParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_authResultParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy_s param name fail. paramName=%{public}s", g_authResultParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetAuthResultMsgParamValve(SoftBusEvtReportMsg *msg, AuthResultRecord *record)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u32v = record->linkType;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u64v = record->authTotalTime;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = record->authTotalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = record->authCount1;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.u32v = record->authCount2;
    msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = record->authCount3;
    msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.u32v = record->authCount4;
    msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.u32v = record->authCount5;
    msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT].paramValue.u64v = record->failTotalTime;
    msg->paramArray[SOFTBUS_EVT_PARAM_NINE].paramValue.u32v = record->failTotalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_TEN].paramValue.u32v = record->connFailTotalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_ELEVEN].paramValue.u32v = record->authFailTotalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWELVE].paramValue.u32v = record->exchangeFailTotalCount;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_THIRTEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_softbusVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy softbus version fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_FOURTEEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_packageVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy package name fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateAuthResultMsg(SoftBusEvtReportMsg *msg, SoftBusLinkType linkType)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_AUTH_KPI) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy evtname fail. STATISTIC_EVT_AUTH_KPI=%{public}s", STATISTIC_EVT_AUTH_KPI);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = AUTH_RESULT_STATISTIC_PARAM_NUM;
    int32_t ret = SetAuthResultMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param name fail");
        return ret;
    }
    if (SoftBusMutexLock(&(g_authResultRecord[linkType].lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ret = SetAuthResultMsgParamValve(msg, &g_authResultRecord[linkType]);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param valve fail");
        (void)SoftBusMutexUnlock(&(g_authResultRecord[linkType].lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_authResultRecord[linkType].lock));
    return SOFTBUS_OK;
}

static void CleanDevOnlineDurRecord(void)
{
    if (SoftBusMutexLock(&(g_devOnlineDurRecord.lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return;
    }
    g_devOnlineDurRecord.totalTime = 0;
    g_devOnlineDurRecord.totalCount = 0;
    g_devOnlineDurRecord.count1 = 0;
    g_devOnlineDurRecord.count2 = 0;
    g_devOnlineDurRecord.count3 = 0;
    g_devOnlineDurRecord.count4 = 0;
    g_devOnlineDurRecord.count5 = 0;
    (void)SoftBusMutexUnlock(&(g_devOnlineDurRecord.lock));
}

static int32_t SetOnlineDurMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < ONLINE_DURATION_STATISTIC_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_busCenterDurStaticParam[i + 1].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_busCenterDurStaticParam[i + 1].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT,
                "copy param name fail. paramName=%{public}s", g_busCenterDurStaticParam[i + 1].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetOnlineDurMsgParamValve(SoftBusEvtReportMsg *msg, DevOnlineDurRecord *record)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u64v = record->totalTime;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = record->totalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = record->count1;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = record->count2;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.u32v = record->count3;
    msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = record->count4;
    msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.u32v = record->count5;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_softbusVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy softbus version fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_packageVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy package name fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateOnlineDurMsg(SoftBusEvtReportMsg *msg)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_ONLINE_DURATION) != EOK) {
        COMM_LOGE(COMM_EVENT,
            "strcpy evtname fail. STATISTIC_EVT_ONLINE_DURATION=%{public}s", STATISTIC_EVT_ONLINE_DURATION);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = ONLINE_DURATION_STATISTIC_PARAM_NUM;
    int32_t ret = SetOnlineDurMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "online duration stastic msg set param name fail");
        return ret;
    }
    if (SoftBusMutexLock(&(g_devOnlineDurRecord.lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "add online duration record lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ret = SetOnlineDurMsgParamValve(msg, &g_devOnlineDurRecord);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "online duration stastic msg set param valve fail");
        (void)SoftBusMutexUnlock(&(g_devOnlineDurRecord.lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_devOnlineDurRecord.lock));
    return SOFTBUS_OK;
}

static void CleanBusCenterRecord(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        if (SoftBusMutexLock(&(g_busCenterRecord[linkType].lock)) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "lock fail");
            return;
        }
        g_busCenterRecord[linkType].linkType = linkType;
        g_busCenterRecord[linkType].totalTime = 0;
        g_busCenterRecord[linkType].totalCount = 0;
        g_busCenterRecord[linkType].count1 = 0;
        g_busCenterRecord[linkType].count2 = 0;
        g_busCenterRecord[linkType].count3 = 0;
        g_busCenterRecord[linkType].count4 = 0;
        g_busCenterRecord[linkType].count5 = 0;
        (void)SoftBusMutexUnlock(&(g_busCenterRecord[linkType].lock));
    }
}

static int32_t SetBusCenterDurMsgParamName(SoftBusEvtReportMsg *msg)
{
    SoftBusEvtParam *param = NULL;
    for (int i = SOFTBUS_EVT_PARAM_ZERO; i < BUS_CENTER_DURATION_PARAM_NUM; i++) {
        param = &msg->paramArray[i];
        param->paramType = g_busCenterDurStaticParam[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, g_busCenterDurStaticParam[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "copy param name fail. paramName=%{public}s", g_busCenterDurStaticParam[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetBusCenterDurMsgParamValve(SoftBusEvtReportMsg *msg, BusCenterDuraRecord *record)
{
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u32v = record->linkType;
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u64v = record->totalTime;
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = record->totalCount;
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = record->count1;
    msg->paramArray[SOFTBUS_EVT_PARAM_FOUR].paramValue.u32v = record->count2;
    msg->paramArray[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = record->count3;
    msg->paramArray[SOFTBUS_EVT_PARAM_SIX].paramValue.u32v = record->count4;
    msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN].paramValue.u32v = record->count5;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_softbusVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy softbus version fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_NINE].paramValue.str, SOFTBUS_HISYSEVT_NAME_LEN,
        g_packageVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy package name fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CreateBusCenterDurStasticMsg(SoftBusEvtReportMsg *msg, SoftBusLinkType linkType)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_LNN_DURATION) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy evtname fail. STATISTIC_EVT_LNN_DURATION=%{public}s", STATISTIC_EVT_LNN_DURATION);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = BUS_CENTER_DURATION_PARAM_NUM;
    int32_t ret = SetBusCenterDurMsgParamName(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param name fail");
        return ret;
    }
    if (SoftBusMutexLock(&(g_busCenterRecord[linkType].lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ret = SetBusCenterDurMsgParamValve(msg, &g_busCenterRecord[linkType]);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param valve fail");
        (void)SoftBusMutexUnlock(&(g_busCenterRecord[linkType].lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_busCenterRecord[linkType].lock));
    return SOFTBUS_OK;
}

static bool IsNeedReportOnlineDurRecordEvt(void)
{
    DevOnlineDurRecord *record = &g_devOnlineDurRecord;
    if (SoftBusMutexLock(&(record->lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return false;
    }
    if ((record->count1 == 0) && (record->count2 == 0) && (record->count3 == 0) && (record->count4 == 0)
        && (record->count5 == 0) && (record->totalCount == 0) && (record->totalTime == 0)) {
        (void)SoftBusMutexUnlock(&(record->lock));
        return false;
    }
    (void)SoftBusMutexUnlock(&(record->lock));
    return true;
}

static int32_t ReportOnlineDurRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report online duration record evt enter");
    if (!IsNeedReportOnlineDurRecordEvt()) {
        COMM_LOGD(COMM_EVENT, "this time do not need report online duration record evt");
        return SOFTBUS_OK;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(ONLINE_DURATION_STATISTIC_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create online duration report msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    do {
        ret = SoftBusCreateOnlineDurMsg(msg);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "create device online duration report msg fail");
            break;
        }
        ret = SoftbusWriteHisEvt(msg);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "write device online duration hisevt fail");
            break;
        }
    } while (false);
    SoftbusFreeEvtReportMsg(msg);
    CleanDevOnlineDurRecord();
    return ret;
}

static bool IsNeedReportLnnDurRecordItem(SoftBusLinkType linkType)
{
    BusCenterDuraRecord *record = &g_busCenterRecord[linkType];
    if (SoftBusMutexLock(&(record->lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return false;
    }
    if ((record->totalTime == 0) && (record->totalCount == 0) && (record->count1 == 0) && (record->count2 == 0)
        && (record->count3 == 0) && (record->count4 == 0) && (record->count5 == 0)) {
        (void)SoftBusMutexUnlock(&(record->lock));
        return false;
    }
    (void)SoftBusMutexUnlock(&(record->lock));
    return true;
}

static bool IsNeedReportLnnDurRecordEvt(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        if (IsNeedReportLnnDurRecordItem(linkType)) {
            return true;
        }
    }
    return false;
}

static int32_t ReportBusCenterRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report buscenter record evt enter");
    ReleaseDevUdidInfoNode();
    if (!IsNeedReportLnnDurRecordEvt()) {
        COMM_LOGD(COMM_EVENT, "this time do not need report buscenter record evt");
        return SOFTBUS_OK;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(BUS_CENTER_DURATION_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create buscenter record msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        do {
            if (!IsNeedReportLnnDurRecordItem(linkType)) {
                break;
            }
            ret = CreateBusCenterDurStasticMsg(msg, linkType);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "create lnn time report msg fail");
                break;
            }
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "write lnn time hisevt fail");
                break;
            }
        } while (false);
        if (ret != SOFTBUS_OK) {
            break;
        }
    }
    SoftbusFreeEvtReportMsg(msg);
    CleanBusCenterRecord();
    return ret;
}

static bool IsNeedReportAuthResultRecordItem(SoftBusLinkType linkType)
{
    AuthResultRecord *record = &g_authResultRecord[linkType];
    if (SoftBusMutexLock(&(record->lock)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return false;
    }
    if ((record->exchangeFailTotalCount == 0) && (record->authTotalTime == 0) && (record->authTotalCount == 0)
        && (record->authCount2 == 0) && (record->authCount3 == 0) && (record->authCount4 == 0)
        && (record->authCount5 == 0) && (record->failTotalTime == 0) && (record->connFailTotalCount == 0)
        && (record->failTotalCount == 0) && (record->authFailTotalCount == 0) && (record->authCount1 == 0)) {
        (void)SoftBusMutexUnlock(&(record->lock));
        return false;
    }
    (void)SoftBusMutexUnlock(&(record->lock));
    return true;
}

static bool IsNeedReportAuthResultRecordEvt(void)
{
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        if (IsNeedReportAuthResultRecordItem(linkType)) {
            return true;
        }
    }
    return false;
}

static int32_t ReportAuthResultRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report auth result record evt enter");
    if (!IsNeedReportAuthResultRecordEvt()) {
        COMM_LOGD(COMM_EVENT, "this time do not need report auth result record evt");
        return SOFTBUS_OK;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(AUTH_RESULT_STATISTIC_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create auth result report msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    for (SoftBusLinkType linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BR; linkType < SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        linkType++) {
        do {
            if (!IsNeedReportAuthResultRecordItem(linkType)) {
                break;
            }
            ret = SoftBusCreateAuthResultMsg(msg, linkType);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "create auth result report msg fail");
                break;
            }
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                COMM_LOGE(COMM_EVENT, "write auth result hisevt fail");
                break;
            }
        } while (false);
        if (ret != SOFTBUS_OK) {
            break;
        }
    }
    SoftbusFreeEvtReportMsg(msg);
    CleanAuthResultRecord();
    return ret;
}

int32_t SoftBusRecordDevOnlineDurResult(uint64_t constTime)
{
    if (constTime < 0) {
        COMM_LOGE(COMM_EVENT, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    DevOnlineDurRecord *reCord = &g_devOnlineDurRecord;
    if (SoftBusMutexLock(&reCord->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    reCord->totalTime += constTime;
    reCord->totalCount++;
    if (constTime > ONLINE_TIME_STANDARD_S) {
        reCord->count1++;
    }
    if (constTime > ONLINE_TIME_STANDARD_A) {
        reCord->count2++;
    }
    if (constTime > ONLINE_TIME_STANDARD_B) {
        reCord->count3++;
    }
    if (constTime > ONLINE_TIME_STANDARD_C) {
        reCord->count4++;
    }
    if (constTime > ONLINE_TIME_STANDARD_D) {
        reCord->count5++;
    }
    (void)SoftBusMutexUnlock(&reCord->lock);
    return SOFTBUS_OK;
}

int32_t SoftBusRecordBusCenterResult(SoftBusLinkType linkType, uint64_t constTime)
{
    if (linkType >= SOFTBUS_HISYSEVT_LINK_TYPE_BUTT || constTime < 0) {
        COMM_LOGE(COMM_EVENT, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    BusCenterDuraRecord *reCord = &g_busCenterRecord[linkType];
    if (SoftBusMutexLock(&reCord->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "lnn result record lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    reCord->totalTime += constTime;
    reCord->totalCount++;
    if (constTime > LNN_TIME_STANDARD_S) {
        reCord->count1++;
    }
    if (constTime > LNN_TIME_STANDARD_A) {
        reCord->count2++;
    }
    if (constTime > LNN_TIME_STANDARD_B) {
        reCord->count3++;
    }
    if (constTime > LNN_TIME_STANDARD_C) {
        reCord->count4++;
    }
    if (constTime > LNN_TIME_STANDARD_D) {
        reCord->count5++;
    }
    (void)SoftBusMutexUnlock(&reCord->lock);
    return SOFTBUS_OK;
}

int32_t SoftBusRecordAuthResult(SoftBusLinkType linkType, int32_t ret, uint64_t constTime, AuthFailStage stage)
{
    if (linkType >= SOFTBUS_HISYSEVT_LINK_TYPE_BUTT || constTime < 0) {
        COMM_LOGE(COMM_EVENT, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthResultRecord *reCord = &g_authResultRecord[linkType];
    if (SoftBusMutexLock(&reCord->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "auth result record lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    reCord->authTotalTime += constTime;
    reCord->authTotalCount++;
    if (constTime > AUTH_TIME_STANDARD_S) {
        reCord->authCount1++;
    }
    if (constTime > AUTH_TIME_STANDARD_A) {
        reCord->authCount2++;
    }
    if (constTime > AUTH_TIME_STANDARD_B) {
        reCord->authCount3++;
    }
    if (constTime > AUTH_TIME_STANDARD_C) {
        reCord->authCount4++;
    }
    if (constTime > AUTH_TIME_STANDARD_D) {
        reCord->authCount5++;
    }
    if (ret != SOFTBUS_OK) {
        reCord->failTotalTime += constTime;
        reCord->failTotalCount++;
        switch (stage) {
            case AUTH_CONNECT_STAGE:
                reCord->connFailTotalCount++;
                break;
            case AUTH_VERIFY_STAGE:
                reCord->authFailTotalCount++;
                break;
            case AUTH_EXCHANGE_STAGE:
                reCord->exchangeFailTotalCount++;
                break;
            default:
                break;
        }
    }
    (void)SoftBusMutexUnlock(&reCord->lock);
    return SOFTBUS_OK;
}

int32_t InitBusCenterDfx(void)
{
    if (g_isBusCenterDfxInit) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_devUdidLock, NULL) != SOFTBUS_OK || SoftBusMutexInit(&g_appDiscLock, NULL) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init buscenter dfx lock init fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (InitBusCenterEvtMutexLock() != SOFTBUS_OK || InitDevOnlineDurEvtMutexLock() != SOFTBUS_OK ||
        InitAuthEvtMutexLock() != SOFTBUS_OK || InitDevDiscoveryEvtMutexLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&g_devUdidList);
    ListInit(&g_appDiscList);
    CleanBusCenterRecord();
    CleanDevOnlineDurRecord();
    CleanAuthResultRecord();
    CleanDevDiscoveryRecord();
    do {
        if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_DURATION, ReportBusCenterRecordEvt) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "set report buscenter record evt function fail");
            break;
        }
        if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_ONLINE_DURATION,
            ReportOnlineDurRecordEvt) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "set report online duration record evt function fail");
            break;
        }
        if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_AUTH_KPI, ReportAuthResultRecordEvt) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "set report auth result record evt function fail");
            break;
        }
        if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DEV_DISCOVERY, ReportDevDiscoveryRecordEvt) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "set report device discovery record evt function fail");
            break;
        }
        if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_APP_DISCOVERY, ReportAppDiscoveryRecordEvt) != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "set report app discovery record evt function fail");
            break;
        }
        g_isBusCenterDfxInit = true;
        return SOFTBUS_OK;
    } while (false);
    return SOFTBUS_INVALID_PARAM;
}

static void DestroyBusCenterDfxMutex(void)
{
    SoftBusMutexDestroy(&g_devUdidLock);
    SoftBusMutexDestroy(&g_appDiscLock);
    SoftBusMutexDestroy(&(g_devOnlineDurRecord.lock));
    SoftBusMutexDestroy(&(g_devDiscoveryRecord.lock));
    DeinitBusCenterEvtMutexLock();
    DeinitAuthEvtMutexLock();
}

void DeinitBusCenterDfx(void)
{
    ReleaseDevUdidInfoNode();
    ReleaseAppDiscInfoNode();
    DestroyBusCenterDfxMutex();
    g_isBusCenterDfxInit = false;
}
