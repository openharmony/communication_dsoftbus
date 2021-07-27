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

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "hdf_io_service_if.h"

static LnnMonitorEventHandler g_eventHandler;

#define HISYSLINK_SERVICE_NAME "hisyslink_sevice"
#define IP_READY 124

struct HdfIoService *serv = NULL;

static int OnDevEventReceived(void* priv, unsigned int id, struct HdfSBuf* data)
{
    if (id == IP_READY) {
        g_eventHandler(LNN_MONITOR_EVENT_IP_ADDR_CHANGED, NULL);
        LOG_INFO("[%s] enter,%s: dev event received: %u, send LNN_MONITOR_EVENT_IP_ADDR_CHANGED to Softbus\n",
            __FUNCTION__, (char*)priv, id);
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
        LOG_ERR("hisyslink event handler is null");
        return SOFTBUS_ERR;
    }
    serv = HdfIoServiceBind(HISYSLINK_SERVICE_NAME);
    if (serv == NULL) {
        LOG_WARN("[%s] fail to get service %s\n", __FUNCTION__, HISYSLINK_SERVICE_NAME);
        return SOFTBUS_OK;
    }

    if (HdfDeviceRegisterEventListener(serv, &g_listener) != HDF_SUCCESS) {
        LOG_WARN("[%s] fail to register event listener\n", __FUNCTION__);
        return SOFTBUS_OK;
    }
    g_eventHandler = handler;
    LOG_INFO("[%s] start success...\n", __FUNCTION__);
    return SOFTBUS_OK;
}