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

#include "softbus_conn_ble_snapshot.h"

#include "cJSON.h"
#include <stdio.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_def.h"

static void FillConnectionsJson(cJSON *root, ListNode *connectionSnapshots)
{
    cJSON *array = cJSON_AddArrayToObject(root, "BleConnectionsHiDumperArray");
    CONN_CHECK_AND_RETURN_LOGE(array != NULL, CONN_BLE, "ble hidumper add array to object fail");
    ConnBleConnectionSnapshot *it = NULL;
    LIST_FOR_EACH_ENTRY(it, connectionSnapshots, ConnBleConnectionSnapshot, node) {
        cJSON *json = cJSON_CreateObject();
        if (json == NULL) {
            CONN_LOGE(CONN_BLE, "ble hidumper create object fail");
            continue;
        }
        cJSON_AddNumberToObject(json, "currentTime", SoftBusGetSysTimeMs());
        cJSON_AddNumberToObject(json, "connectionId", it->connectionId);
        cJSON_AddNumberToObject(json, "side", it->side);
        cJSON_AddStringToObject(json, "mac", it->addr);
        cJSON_AddNumberToObject(json, "state", it->state);
        cJSON_AddNumberToObject(json, "mtu", it->mtu);
        cJSON_AddNumberToObject(json, "connectionRc", it->connectionRc);
        cJSON_AddItemToArray(array, json);
    }
}

static char *ToJson(ListNode *connectionSnapshots)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        CONN_LOGE(CONN_BLE, "create json object failed");
        return NULL;
    }

    FillConnectionsJson(root, connectionSnapshots);

    char *result = cJSON_Print(root);
    if (result == NULL) {
        CONN_LOGE(CONN_BLE, "ble print hidumper json failed");
        cJSON_Delete(root);
        return NULL;
    }
    cJSON_Delete(root);
    return result;
}

ConnBleConnectionSnapshot *ConnBleCreateConnectionSnapshot(const ConnBleConnection *connection)
{
    ConnBleConnectionSnapshot *snapshot = (ConnBleConnectionSnapshot *)SoftBusCalloc(sizeof(ConnBleConnectionSnapshot));
    CONN_CHECK_AND_RETURN_RET_LOGE(snapshot != NULL, NULL, CONN_BLE, "ble hidumper malloc failed");

    ListInit(&snapshot->node);
    snapshot->connectionId = connection->connectionId;
    snapshot->side = connection->side;
    char anonymizedAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anonymizedAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    if (strcpy_s(snapshot->addr, BT_MAC_LEN, anonymizedAddress) != EOK) {
        CONN_LOGE(CONN_BLE, "ble hidumper construct failed");
    }
    snapshot->state = connection->state;
    snapshot->mtu = connection->mtu;
    snapshot->connectionRc = connection->connectionRc;
    return snapshot;
}

void ConnBleDestroyConnectionSnapshot(ConnBleConnectionSnapshot *snapshot)
{
    SoftBusFree(snapshot);
}

static void FreeConnections(ListNode *connectionSnapshots)
{
    ConnBleConnectionSnapshot *it = NULL;
    ConnBleConnectionSnapshot *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, connectionSnapshots, ConnBleConnectionSnapshot, node) {
        ListDelete(&it->node);
        ConnBleDestroyConnectionSnapshot(it);
    }
}

int32_t BleHiDumper(int fd)
{
    ListNode connectionSnapshots;
    ListInit(&connectionSnapshots);
    int32_t ret = ConnBleDumper(&connectionSnapshots);

    do {
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "get ble snapshot failed");
            break;
        }

        char *json = ToJson(&connectionSnapshots);
        if (json == NULL) {
            CONN_LOGE(CONN_BLE, "ble snapshot to json error %{public}d", SOFTBUS_CREATE_JSON_ERR);
            break;
        }

        SOFTBUS_DPRINTF(fd, "%s\n", json);
        cJSON_free(json);
    } while (false);

    FreeConnections(&connectionSnapshots);
    return ret;
}