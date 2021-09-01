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

#include "softbus_adapter_log.h"
#include "softbus_errcode.h"
#include "hdf_io_service_if.h"

static LnnMonitorEventHandler g_eventHandler;

#define HISYSLINK_SERVICE_NAME "hisyslink_sevice"
#define IP_READY 124

static struct HdfIoService *g_serv = NULL;

static int OnDevEventReceived(void* priv, unsigned int id, struct HdfSBuf* data)
{
    if (id == IP_READY) {
        g_eventHandler(LNN_MONITOR_EVENT_IP_ADDR_CHANGED, NULL);
        HILOG_INFO(SOFTBUS_HILOG_ID, "envent %{public}s: dev event received: %{public}u", (char*)priv, id);
    }
    return HDF_SUCCESS;
}

static struct HdfDevEventlistener g_listener = {
    .callBack = OnDevEventReceived,
    .priv = "Service0",
};

int32_t LnnInitProductMonitorImpl(LnnMonitorEventHandler handler)
{
    if (handler == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "hisyslink event handler is null");
        return SOFTBUS_ERR;
    }
    g_serv = HdfIoServiceBind(HISYSLINK_SERVICE_NAME);
    if (g_serv == NULL) {
        HILOG_WARN(SOFTBUS_HILOG_ID, "fail to get service %{public}s", HISYSLINK_SERVICE_NAME);
        return SOFTBUS_OK;
    }

    if (HdfDeviceRegisterEventListener(g_serv, &g_listener) != HDF_SUCCESS) {
        HILOG_WARN(SOFTBUS_HILOG_ID, "fail to register event listener");
        return SOFTBUS_OK;
    }
    g_eventHandler = handler;
    HILOG_ERROR(SOFTBUS_HILOG_ID, "start success...");
    return SOFTBUS_OK;
}
