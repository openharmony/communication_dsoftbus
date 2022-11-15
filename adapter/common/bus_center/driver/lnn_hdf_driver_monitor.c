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

#include "lnn_event_monitor_impl.h"

#include <hdf_io_service.h>
#include <hdf_sbuf.h>
#include <securec.h>

#include "lnn_async_callback_utils.h"
#include "lnn_driver_request.h"
#include "lnn_ip_utils.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"

#define DRIVER_SERVICE_NAME "hdf_dsoftbus"

#define NETIF_NAME_LENGTH 16

#define BIND_HDF_DELAY 1000
#define MAX_BIND_HDF_RETRY_COUNT 10

typedef struct {
    struct HdfIoService *softbusService;
    struct HdfDevEventlistener eventListener;
    LnnMonitorEventHandler handler;
} HdfDriverEventCtrl;

typedef struct {
    uint32_t event;
    char ifName[NETIF_NAME_LENGTH];
    union ExtInfo {
        int32_t status;
    } extInfo;
} LwipMonitorReportInfo;

static HdfDriverEventCtrl g_driverCtrl;

static void ProcessLwipEvent(const LnnMoniterData *monitorData)
{
    const LwipMonitorReportInfo *info = (const LwipMonitorReportInfo *)monitorData->value;
    ConnectionAddrType type = CONNECTION_ADDR_MAX;

    if (monitorData->len != sizeof(LwipMonitorReportInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "receive lwip monitor not correct size: %d<->%d",
            monitorData->len, sizeof(LwipMonitorReportInfo));
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "receive lwip monitor event(%d) for %s",
        info->event, info->ifName);
    if (LnnGetAddrTypeByIfName(info->ifName, strlen(info->ifName), &type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ProcessLwipEvent LnnGetAddrTypeByIfName error");
        return;
    }
    if (type == CONNECTION_ADDR_ETH || type == CONNECTION_ADDR_WLAN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "network addr changed, type:%d", type);
        g_driverCtrl.handler(LNN_MONITOR_EVENT_IP_ADDR_CHANGED, NULL);
    }
}

static void DispatchModuleEvent(int32_t moduleId, const LnnMoniterData *monitorData)
{
    switch (moduleId) {
        case LNN_DRIVER_MODULE_WLAN_PARAM:
            g_driverCtrl.handler(LNN_MONITOR_EVENT_WLAN_PARAM, monitorData);
            break;
        case LNN_DRIVER_MODULE_LWIP_MONITOR:
            ProcessLwipEvent(monitorData);
            break;
        default:
            break;
    }
}

static int32_t OnReceiveDriverEvent(struct HdfDevEventlistener *listener,
    struct HdfIoService *service, uint32_t moduleId, struct HdfSBuf *data)
{
    uint8_t *eventData = NULL;
    uint32_t eventDataSize;
    LnnMoniterData *monitorData = NULL;

    (void)listener;
    (void)service;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "receive hdf moudle(%d) event", moduleId);
    if (moduleId >= LNN_DRIVER_MODULE_MAX_INDEX) {
        return SOFTBUS_OK;
    }
    if (!HdfSbufReadBuffer(data, (const void **)&eventData, &eventDataSize)) {
        eventData = NULL;
        eventDataSize = 0;
    }
    monitorData = (LnnMoniterData *)SoftBusMalloc(sizeof(LnnMoniterData) + eventDataSize);
    if (monitorData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc monitor data fail");
        return SOFTBUS_ERR;
    }
    monitorData->len = eventDataSize;
    if (eventData != NULL) {
        if (memcpy_s(monitorData->value, eventDataSize, eventData, eventDataSize) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcopy monitor data fail");
            SoftBusFree(monitorData);
            return SOFTBUS_ERR;
        }
    }
    DispatchModuleEvent(moduleId, monitorData);
    SoftBusFree(monitorData);
    return SOFTBUS_OK;
}

static void DelayInitFunction(void *para)
{
    int32_t rc;
    static int32_t retry = 0;

    (void)para;
    if (retry >= MAX_BIND_HDF_RETRY_COUNT) {
        return;
    }
    g_driverCtrl.softbusService = HdfIoServiceBind(DRIVER_SERVICE_NAME);
    if (g_driverCtrl.softbusService == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get hdf dsoftbus service fail(%d)", retry);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
        ++retry;
        return;
    }
    rc = HdfDeviceRegisterEventListener(g_driverCtrl.softbusService, &g_driverCtrl.eventListener);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init hdf driver monitor(%d) result: %d", retry, rc);
    if (rc != SOFTBUS_OK) {
        HdfIoServiceRecycle(g_driverCtrl.softbusService);
        g_driverCtrl.softbusService = NULL;
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
    }
    ++retry;
}

int32_t LnnInitDriverMonitorImpl(LnnMonitorEventHandler handler)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "hdf driver monitor init enter");
    g_driverCtrl.eventListener.onReceive = OnReceiveDriverEvent;
    g_driverCtrl.handler = handler;
    return LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
}
