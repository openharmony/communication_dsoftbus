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

#include "softbus_errcode.h"
#include "softbus_config_adapter.h"
#include "softbus_log.h"

typedef struct {
    int maxByteLen;
    int maxMsgLen;
    int authAbilityConn;
    int connBrMaxDataLen;
    int connRfcomSendMaxLen;
    int connBrRecvMaxLen;
    int connTcpMaxLen;
    int connTcpMaxConnNum;
    int connTcpTimeOut;
    int maxNodeStateCbCnt;
    int maxLnnConnCnt;
    int maxLnnSupportCap;
} ConfigItem;

typedef struct {
    ConfigType type;
    unsigned char *val;
    int len;
} ConfigVal;

ConfigItem g_config = {0};

ConfigVal g_configItems[SOFTBUS_CONFIG_TYPE_MAX] = {
    {
        SOFTBUS_INT_MAX_BYTES_LENGTH, 
        (unsigned char*)&(g_config.maxByteLen), 
        sizeof(g_config.maxByteLen)
    },
    {
        SOFTBUS_INT_MAX_MESSAGE_LENGTH, 
        (unsigned char*)&(g_config.maxMsgLen), 
        sizeof(g_config.maxMsgLen)
    },
    {
        SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH, 
        (unsigned char*)&(g_config.connBrMaxDataLen), 
        sizeof(g_config.connBrMaxDataLen)
    },
    {
        SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN, 
        (unsigned char*)&(g_config.connRfcomSendMaxLen), 
        sizeof(g_config.connRfcomSendMaxLen)
    },
    {
        SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN, 
        (unsigned char*)&(g_config.connBrRecvMaxLen), 
        sizeof(g_config.connBrRecvMaxLen)
    },
    {
        SOFTBUS_INT_CONN_TCP_MAX_LENGTH, 
        (unsigned char*)&(g_config.connTcpMaxLen), 
        sizeof(g_config.connTcpMaxLen)
    },
    {
        SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM, 
        (unsigned char*)&(g_config.connTcpMaxConnNum), 
        sizeof(g_config.connTcpMaxConnNum)
    },
    {
        SOFTBUS_INT_CONN_TCP_TIME_OUT, 
        (unsigned char*)&(g_config.connTcpTimeOut), 
        sizeof(g_config.connTcpTimeOut)
    },
    {
        SOFTBUS_INT_MAX_NODE_STATE_CB_CNT, 
        (unsigned char*)&(g_config.maxNodeStateCbCnt), 
        sizeof(g_config.maxNodeStateCbCnt)
    },
    {
        SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, 
        (unsigned char*)&(g_config.maxLnnConnCnt), 
        sizeof(g_config.maxLnnConnCnt)
    },
    {
        SOFTBUS_INT_LNN_SUPPORT_CAPBILITY,
        (unsigned char*)&(g_config.maxLnnSupportCap), 
        sizeof(g_config.maxLnnSupportCap)
    },
    {
        SOFTBUS_INT_AUTH_ABILITY_COLLECTION, 
        (unsigned char*)&(g_config.authAbilityConn), 
        sizeof(g_config.authAbilityConn)
    },
};

int SoftbusSetConfig(ConfigType type, const unsigned char *val, int len)
{
    if (len > g_configItems[type].len) {
        return SOFTBUS_ERR;
    }
    if ((type >= SOFTBUS_CONFIG_TYPE_MAX) || (type != g_configItems[type].type)) {
        return SOFTBUS_ERR;
    }
    if (memcpy_s(g_configItems[type].val, g_configItems[type].len, val, len) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftbusGetConfig(ConfigType type, unsigned char *val, int len)
{
    if (len != g_configItems[type].len) {
        return SOFTBUS_ERR;
    }
    if ((type >= SOFTBUS_CONFIG_TYPE_MAX) || (type != g_configItems[type].type)) {
        return SOFTBUS_ERR;
    }
    if (memcpy_s((void*)val, len, g_configItems[type].val, g_configItems[type].len) != EOK) {
	return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SoftbusConfigInit(void)
{
    ConfigSetProc sets;

    sets.SetConfig = &SoftbusSetConfig;
    SoftbusConfigAdapterInit(&sets);
    LOG_INFO("SoftbusConfigInit success");
}