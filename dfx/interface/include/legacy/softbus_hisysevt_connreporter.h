/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef SOFTBUS_HISYSEVT_CONNREPORTER_H
#define SOFTBUS_HISYSEVT_CONNREPORTER_H

#include "legacy/softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define DEFAULT_PID 0

typedef enum {
    SOFTBUS_EVT_CONN_SUCC,
    SOFTBUS_EVT_CONN_FAIL,
} SoftBusConnStatus;

typedef enum {
    SOFTBUS_HISYSEVT_CONN_TYPE_BR = 0,
    SOFTBUS_HISYSEVT_CONN_TYPE_BLE = 1,
    SOFTBUS_HISYSEVT_CONN_TYPE_TCP = 2,
    SOFTBUS_HISYSEVT_CONN_TYPE_P2P = 3,
    SOFTBUS_HISYSEVT_CONN_TYPE_HML = 4,
    SOFTBUS_HISYSEVT_CONN_TYPE_COC = 5,
    SOFTBUS_HISYSEVT_CONN_TYPE_BUTT = 6,
} SoftBusConnType;

typedef enum {
    NEGOTIATION_STEP = 0,
    GROUP_CREATE_STEP = 1,
    CONN_GROUP_STEP = 2,
    STEP_BUTT = 3,
} ProcessStep;

typedef enum {
    SOFTBUS_HISYSEVT_CONN_OK,
    SOFTBUS_HISYSEVT_CONN_MANAGER_OP_NOT_SUPPORT,
    SOFTBUS_HISYSEVT_BLE_NOT_INIT,
    SOFTBUS_HISYSEVT_BLE_GATTSERVER_INIT_FAIL,
    SOFTBUS_HISYSEVT_BLE_GATTCLIENT_INIT_FAIL,
    SOFTBUS_HISYSEVT_BLE_TRANS_INIT_FAIL,
    SOFTBUS_HISYSEVT_BLE_QUEUE_INIT_FAIL,
    SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL,
    SOFTBUS_HISYSEVT_BLE_DISCONNECT_FAIL,
    SOFTBUS_HISYSEVT_BLE_SEND_FAIL,
    SOFTBUS_HISYSEVT_BLE_RECV_INVALID_DATA,
    SOFTBUS_HISYSEVT_BLE_RECV_INVALID_DEVICE,
    SOFTBUS_HISYSEVT_BLE_GATTSERVER_START_FAIL,
    SOFTBUS_HISYSEVT_BLE_GATTSERVER_STOP_FAIL,
    SOFTBUS_HISYSEVT_BLE_GATTCLIENT_UPDATA_STATE_ERR,
    SOFTBUS_HISYSEVT_BLE_GATTCLIENT_SEARCH_SERVICES_ERR,
    SOFTBUS_HISYSEVT_TCP_CONNECTION_SOCKET_ERR,
    SOFTBUS_HISYSEVT_CONN_ERRCODE_BUTT,
} SoftBusConnErrCode;

typedef struct {
    uint64_t totalTime;
    uint64_t negotiationTime;
    uint64_t groupCreateTime;
    uint64_t connGroupTime;
} ProcessStepTime;

typedef struct {
    bool reuse;
    uint32_t reqId;
    uint32_t connectTraceId;
    uint64_t startTime;
} ConnectStatistics;

int32_t SoftBusRecordPIdAndPkgName(uint32_t pId, const char *pkgName);

int32_t SoftbusRecordConnResult(uint32_t pId, SoftBusConnType connType, SoftBusConnStatus status,
                                uint64_t costTime, int32_t errCode);

int32_t SoftbusRecordProccessDuration(uint32_t pId, SoftBusConnType connType, SoftBusConnStatus status,
                                      ProcessStepTime *stepTime, int32_t errCode);

uint32_t SoftbusGetConnectTraceId();

int32_t InitConnStatisticSysEvt(void);

void DeinitConnStatisticSysEvt(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_HISYSEVT_DISCREPORTER_H */