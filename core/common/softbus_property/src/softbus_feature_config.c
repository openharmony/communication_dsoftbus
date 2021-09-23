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

#include "softbus_errcode.h"
#include "softbus_config_adapter.h"
#include "softbus_feature_config.h"

#define MAX_STORAGE_PATH_LEN 256

#define MAX_BYTES_LENGTH 4194304
#define MAX_MESSAGE_LENGTH 4096
#define CONN_BR_MAX_DATA_LENGTH 4096
#define CONN_RFCOM_SEND_MAX_LEN 990
#define CONN_BR_RECEIVE_MAX_LEN 10
#define CONN_TCP_MAX_LENGTH 3072
#define CONN_TCP_MAX_CONN_NUM 30
#define CONN_TCP_TIME_OUT 100
#define MAX_NODE_STATE_CB_CNT 10
#define MAX_LNN_CONNECTION_CNT 10
#define LNN_SUPPORT_CAPBILITY 22
#define AUTH_ABILITY_COLLECTION 0
#define ADAPTER_LOG_LEVEL 0
#ifndef DEFAULT_STORAGE_PATH
#define DEFAULT_STORAGE_PATH "/data/data"
#endif

#ifdef __LITEOS_M__
#define DEFAULT_SElECT_INTERVAL 100000
#else
#define DEFAULT_SElECT_INTERVAL 10000
#endif

#ifdef SOFTBUS_STANDARD_SYSTEM
#define DEFAULT_MAX_BYTES_LEN (4 * 1024 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 1
#elif defined SOFTBUS_SMALL_SYSTEM
#define DEFAULT_MAX_BYTES_LEN (1 * 1024 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 1
#else
#define DEFAULT_MAX_BYTES_LEN (2 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 0
#endif

typedef struct {
    int32_t authAbilityConn;
    int32_t connBrMaxDataLen;
    int32_t connRfcomSendMaxLen;
    int32_t connBrRecvMaxLen;
    int32_t connTcpMaxLen;
    int32_t connTcpMaxConnNum;
    int32_t connTcpTimeOut;
    int32_t maxNodeStateCbCnt;
    int32_t maxLnnConnCnt;
    int32_t maxLnnSupportCap;
    int32_t adapterLogLevel;
    char storageDir[MAX_STORAGE_PATH_LEN];
} ConfigItem;

typedef struct {
    ConfigType type;
    unsigned char *val;
    int32_t len;
} ConfigVal;

ConfigItem g_config = {
    AUTH_ABILITY_COLLECTION,
    CONN_BR_MAX_DATA_LENGTH,
    CONN_RFCOM_SEND_MAX_LEN,
    CONN_BR_RECEIVE_MAX_LEN,
    CONN_TCP_MAX_LENGTH,
    CONN_TCP_MAX_CONN_NUM,
    CONN_TCP_TIME_OUT,
    MAX_NODE_STATE_CB_CNT,
    MAX_LNN_CONNECTION_CNT,
    LNN_SUPPORT_CAPBILITY,
    ADAPTER_LOG_LEVEL,
    DEFAULT_STORAGE_PATH,
};

typedef struct {
    int32_t isSupportTcpProxy;
    int32_t selectInterval;
    int32_t maxBytesLen;
    int32_t maxMessageLen;
} TransConfigItem;

static TransConfigItem g_tranConfig = {0};

ConfigVal g_configItems[SOFTBUS_CONFIG_TYPE_MAX] = {
    {
        SOFTBUS_INT_MAX_BYTES_LENGTH, 
        (unsigned char*)&(g_tranConfig.maxBytesLen),
        sizeof(g_tranConfig.maxBytesLen)
    },
    {
        SOFTBUS_INT_MAX_MESSAGE_LENGTH, 
        (unsigned char*)&(g_tranConfig.maxMessageLen),
        sizeof(g_tranConfig.maxMessageLen)
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
    {
        SOFTBUS_INT_ADAPTER_LOG_LEVEL, 
        (unsigned char*)&(g_config.adapterLogLevel), 
        sizeof(g_config.adapterLogLevel)
    },
    {
        SOFTBUS_STR_STORAGE_DIRECTORY, 
        (unsigned char*)(g_config.storageDir), 
        sizeof(g_config.storageDir)
    },
};

int SoftbusSetConfig(ConfigType type, const unsigned char *val, int32_t len)
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

int SoftbusGetConfig(ConfigType type, unsigned char *val, int32_t len)
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

static void SoftbusConfigSetTransDefaultVal(void)
{
    g_tranConfig.isSupportTcpProxy = DEFAULT_IS_SUPPORT_TCP_PROXY;
    g_tranConfig.selectInterval = DEFAULT_SElECT_INTERVAL;
    g_tranConfig.maxBytesLen = DEFAULT_MAX_BYTES_LEN;
    g_tranConfig.maxMessageLen = DEFAULT_MAX_MESSAGE_LEN;
}

static void SoftbusConfigSetDefaultVal(void)
{
    SoftbusConfigSetTransDefaultVal();
}

void SoftbusConfigInit(void)
{
    ConfigSetProc sets;
    SoftbusConfigSetDefaultVal();
    sets.SetConfig = &SoftbusSetConfig;
    SoftbusConfigAdapterInit(&sets);
}