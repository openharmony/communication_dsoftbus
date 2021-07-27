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

#include "softbus_config_type.h"

#define MAX_BYTES_LENGTH 4194304
#define MAX_MESSAGE_LENGTH 4096
#define CONN_BR_MAX_DATA_LENGTH 4096
#define CONN_RFCOM_SEND_MAX_LEN  990
#define CONN_BR_RECEIVE_MAX_LEN 10
#define CONN_TCP_MAX_LENGTH 3072
#define CONN_TCP_MAX_CONN_NUM 30
#define CONN_TCP_TIME_OUT 100
#define MAX_NODE_STATE_CB_CNT 10
#define MAX_LNN_CONNECTION_CNT 10
#define LNN_SUPPORT_CAPBILITY 22
#define AUTH_ABILITY_COLLECTION 0

void SoftbusConfigAdaptInit(const ConfigSetProc *sets)
{
    int32_t val;
    val = MAX_BYTES_LENGTH;
    sets->SetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH, (unsigned char*)&val, sizeof(val));
    val = MAX_MESSAGE_LENGTH;
    sets->SetConfig(SOFTBUS_INT_MAX_MESSAGE_LENGTH, (unsigned char*)&val, sizeof(val));
    val = CONN_BR_MAX_DATA_LENGTH;
    sets->SetConfig(SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH, (unsigned char*)&val, sizeof(val));
    val = CONN_RFCOM_SEND_MAX_LEN;
    sets->SetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN, (unsigned char*)&val, sizeof(val));
    val = CONN_BR_RECEIVE_MAX_LEN;
    sets->SetConfig(SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN, (unsigned char*)&val, sizeof(val));
    val = CONN_TCP_MAX_LENGTH;
    sets->SetConfig(SOFTBUS_INT_CONN_TCP_MAX_LENGTH, (unsigned char*)&val, sizeof(val));
    val = CONN_TCP_MAX_CONN_NUM;
    sets->SetConfig(SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM, (unsigned char*)&val, sizeof(val));
    val = CONN_TCP_TIME_OUT;
    sets->SetConfig(SOFTBUS_INT_CONN_TCP_TIME_OUT, (unsigned char*)&val, sizeof(val));
    val = MAX_NODE_STATE_CB_CNT;
    sets->SetConfig(SOFTBUS_INT_MAX_NODE_STATE_CB_CNT, (unsigned char*)&val, sizeof(val));
    val = MAX_LNN_CONNECTION_CNT;
    sets->SetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, (unsigned char*)&val, sizeof(val));
    val = LNN_SUPPORT_CAPBILITY;
    sets->SetConfig(SOFTBUS_INT_LNN_SUPPORT_CAPBILITY, (unsigned char*)&val, sizeof(val));
    val = AUTH_ABILITY_COLLECTION;
    sets->SetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, (unsigned char*)&val, sizeof(val));
}