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
#include <stdbool.h>

#include "comm_log.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_config_adapter.h"
#include "softbus_feature_config.h"

#define MAX_STORAGE_PATH_LEN 256
#define MAX_NET_IF_NAME_LEN 256

#define MAX_BYTES_LENGTH 4194304
#define MAX_MESSAGE_LENGTH 4096

#ifdef SOFTBUS_LINUX
#define CONN_BR_MAX_DATA_LENGTH (40 * 1000)
#define CONN_COC_MAX_DATA_LENGTH (40 * 1000)
#define CONN_BLE_CLOSE_DELAY (10 * 1000)
#else
#define CONN_BR_MAX_DATA_LENGTH 4096
#define CONN_COC_MAX_DATA_LENGTH 4096
#define CONN_BLE_CLOSE_DELAY (30 * 1000)
#endif

#define CONN_RFCOM_SEND_MAX_LEN 990
#define CONN_COC_SEND_MTU_LEN 990
/* 4KB + INDEX + IV_HEAD + PACKET_HEAD + SLICE_HEAD + CHANNEL_HEAD */
#define CONN_TCP_MAX_LENGTH (4096 + 12 + 28 + 16 + 16)
#define CONN_BR_RECEIVE_MAX_LEN 500
#define CONN_TCP_MAX_CONN_NUM 30
#define CONN_TCP_TIME_OUT 100
#define MAX_NODE_STATE_CB_CNT 10
#define MAX_LNN_CONNECTION_CNT 30
#define LNN_SUPPORT_CAPBILITY 62
#define LNN_SUPPORT_FEATURE     0x177C2
#define AUTH_ABILITY_COLLECTION 0
#define DEFAULT_SUPPORT_AUTHCAPACITY 0xF
#define ADAPTER_LOG_LEVEL 0
#ifndef DEFAULT_STORAGE_PATH
#define DEFAULT_STORAGE_PATH "/data/service/el1/public"
#endif
#define LNN_UDID_INIT_DELAY_LEN 1500
#define LNN_NET_IF_NAME "0:eth0,1:wlan0,2:br0,3:ble0"
#define LNN_MAX_CONCURENT_NUM 2
#define DEFAULT_DISC_FREQ_LOW ((5 << 16) | 12)
#define DEFAULT_DISC_FREQ_MID ((5 << 16) | 24)
#define DEFAULT_DISC_FREQ_HIGH ((5 << 16) | 36)
#define DEFAULT_DISC_FREQ_SUPER_HIGH ((10 << 16) | 48)
#define DEFAULT_DISC_FREQ_EXTREME_HIGH ((10 << 16) | 48)
#define DEFAULT_DISC_COAP_MAX_DEVICE_NUM 20

#ifdef SOFTBUS_LINUX
#define DEFAULT_NEW_BYTES_LEN (4 * 1024 * 1024)
#define DEFAULT_NEW_MESSAGE_LEN (4 * 1024)
#define DEFAULT_MAX_BYTES_LEN (4 * 1024 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_AUTH_MAX_BYTES_LEN (40000 - 32)
#define DEFAULT_AUTH_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_PROXY_MAX_BYTES_LEN (4 * 1024 * 1024)
#define DEFAULT_PROXY_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 1
#define DEFAULT_BLE_MAC_AUTO_REFRESH 1
#elif defined SOFTBUS_LITEOS_A
#define DEFAULT_NEW_BYTES_LEN (1 * 1024 * 1024)
#define DEFAULT_NEW_MESSAGE_LEN (4 * 1024)
#define DEFAULT_MAX_BYTES_LEN (1 * 1024 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (4 * 1024)
#define DEFAULT_AUTH_MAX_BYTES_LEN (4 * 1024)
#define DEFAULT_AUTH_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_PROXY_MAX_BYTES_LEN (4 * 1024)
#define DEFAULT_PROXY_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 1
#define DEFAULT_BLE_MAC_AUTO_REFRESH 1
#else
#define DEFAULT_NEW_BYTES_LEN (4 * 1024)
#define DEFAULT_NEW_MESSAGE_LEN (4 * 1024)
#define DEFAULT_MAX_BYTES_LEN (2 * 1024)
#define DEFAULT_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_AUTH_MAX_BYTES_LEN (2 * 1024)
#define DEFAULT_AUTH_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_PROXY_MAX_BYTES_LEN (2 * 1024)
#define DEFAULT_PROXY_MAX_MESSAGE_LEN (1 * 1024)
#define DEFAULT_IS_SUPPORT_TCP_PROXY 1
#define DEFAULT_BLE_MAC_AUTO_REFRESH 0
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
    int32_t lnnUdidInitDelayLen;
    char lnnNetIfName[MAX_NET_IF_NAME_LEN];
    int32_t lnnMaxConcurentNum;
    bool lnnAutoNetworkingSwitch;
    bool isSupportTopo;
    uint64_t supportFeature;
    int32_t connCocMaxDataLen;
    int32_t connCocSendMtu;
    uint32_t authCapacity;
    int32_t connBleCloseDelayTime;
    int32_t bleMacAutoRefreshSwitch;
} ConfigItem;

typedef struct {
    ConfigType type;
    unsigned char *val;
    uint32_t len;
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
    LNN_UDID_INIT_DELAY_LEN,
    LNN_NET_IF_NAME,
    LNN_MAX_CONCURENT_NUM,
    true,
    true,
    LNN_SUPPORT_FEATURE,
    CONN_COC_MAX_DATA_LENGTH,
    CONN_COC_SEND_MTU_LEN,
    DEFAULT_SUPPORT_AUTHCAPACITY,
    CONN_BLE_CLOSE_DELAY,
    DEFAULT_BLE_MAC_AUTO_REFRESH,
};

typedef struct {
    int32_t isSupportTcpProxy;
    int32_t maxBytesNewLen;
    int32_t maxMessageNewLen;
    int32_t maxBytesLen;
    int32_t maxMessageLen;
    int32_t maxAuthBytesLen;
    int32_t maxAuthMessageLen;
    uint32_t maxProxyBytesLen;
    uint32_t maxProxyMessageLen;
} TransConfigItem;

static TransConfigItem g_tranConfig = {0};

typedef struct {
    uint32_t discFreq[FREQ_BUTT];
    uint32_t discCoapMaxDeviceNum;
} DiscConfigItem;

static DiscConfigItem g_discConfig = {
    .discFreq = {
        DEFAULT_DISC_FREQ_LOW,
        DEFAULT_DISC_FREQ_MID,
        DEFAULT_DISC_FREQ_HIGH,
        DEFAULT_DISC_FREQ_SUPER_HIGH,
        DEFAULT_DISC_FREQ_EXTREME_HIGH,
    },
    .discCoapMaxDeviceNum = DEFAULT_DISC_COAP_MAX_DEVICE_NUM
};

ConfigVal g_configItems[SOFTBUS_CONFIG_TYPE_MAX] = {
    {
        SOFTBUS_INT_MAX_BYTES_NEW_LENGTH,
        (unsigned char *)&(g_tranConfig.maxBytesNewLen),
        sizeof(g_tranConfig.maxBytesNewLen)
    },
    {
        SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH,
        (unsigned char *)&(g_tranConfig.maxMessageNewLen),
        sizeof(g_tranConfig.maxMessageNewLen)
    },
    {
        SOFTBUS_INT_MAX_BYTES_LENGTH,
        (unsigned char *)&(g_tranConfig.maxBytesLen),
        sizeof(g_tranConfig.maxBytesLen)
    },
    {
        SOFTBUS_INT_MAX_MESSAGE_LENGTH,
        (unsigned char *)&(g_tranConfig.maxMessageLen),
        sizeof(g_tranConfig.maxMessageLen)
    },
    {
        SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH,
        (unsigned char *)&(g_config.connBrMaxDataLen),
        sizeof(g_config.connBrMaxDataLen)
    },
    {
        SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN,
        (unsigned char *)&(g_config.connRfcomSendMaxLen),
        sizeof(g_config.connRfcomSendMaxLen)
    },
    {
        SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN,
        (unsigned char *)&(g_config.connBrRecvMaxLen),
        sizeof(g_config.connBrRecvMaxLen)
    },
    {
        SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
        (unsigned char *)&(g_config.connTcpMaxLen),
        sizeof(g_config.connTcpMaxLen)
    },
    {
        SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
        (unsigned char *)&(g_config.connTcpMaxConnNum),
        sizeof(g_config.connTcpMaxConnNum)
    },
    {
        SOFTBUS_INT_CONN_TCP_TIME_OUT,
        (unsigned char *)&(g_config.connTcpTimeOut),
        sizeof(g_config.connTcpTimeOut)
    },
    {
        SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
        (unsigned char *)&(g_config.maxNodeStateCbCnt),
        sizeof(g_config.maxNodeStateCbCnt)
    },
    {
        SOFTBUS_INT_MAX_LNN_CONNECTION_CNT,
        (unsigned char *)&(g_config.maxLnnConnCnt),
        sizeof(g_config.maxLnnConnCnt)
    },
    {
        SOFTBUS_INT_LNN_SUPPORT_CAPABILITY,
        (unsigned char *)&(g_config.maxLnnSupportCap),
        sizeof(g_config.maxLnnSupportCap)
    },
    {
        SOFTBUS_INT_AUTH_ABILITY_COLLECTION,
        (unsigned char *)&(g_config.authAbilityConn),
        sizeof(g_config.authAbilityConn)
    },
    {
        SOFTBUS_INT_ADAPTER_LOG_LEVEL,
        (unsigned char *)&(g_config.adapterLogLevel),
        sizeof(g_config.adapterLogLevel)
    },
    {
        SOFTBUS_STR_STORAGE_DIRECTORY,
        (unsigned char *)(g_config.storageDir),
        sizeof(g_config.storageDir)
    },
    {
        SOFTBUS_INT_SUPPORT_TCP_PROXY,
        (unsigned char *)&(g_tranConfig.isSupportTcpProxy),
        sizeof(g_tranConfig.isSupportTcpProxy)
    },
    {
        SOFTBUS_INT_LNN_UDID_INIT_DELAY_LEN,
        (unsigned char *)&(g_config.lnnUdidInitDelayLen),
        sizeof(g_config.lnnUdidInitDelayLen)
    },
    {
        SOFTBUS_STR_LNN_NET_IF_NAME,
        (unsigned char *)&(g_config.lnnNetIfName),
        sizeof(g_config.lnnNetIfName)
    },
    {
        SOFTBUS_INT_LNN_MAX_CONCURRENT_NUM,
        (unsigned char *)&(g_config.lnnMaxConcurentNum),
        sizeof(g_config.lnnMaxConcurentNum)
    },
    {
        SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH,
        (unsigned char *)&(g_tranConfig.maxAuthBytesLen),
        sizeof(g_tranConfig.maxAuthBytesLen)
    },
    {
        SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH,
        (unsigned char *)&(g_tranConfig.maxAuthMessageLen),
        sizeof(g_tranConfig.maxAuthMessageLen)
    },
    {
        SOFTBUS_INT_AUTO_NETWORKING_SWITCH,
        (unsigned char *)&(g_config.lnnAutoNetworkingSwitch),
        sizeof(g_config.lnnAutoNetworkingSwitch)
    },
    {
        SOFTBUS_BOOL_SUPPORT_TOPO,
        (unsigned char *)&(g_config.isSupportTopo),
        sizeof(g_config.isSupportTopo)
    },
    {
        SOFTBUS_INT_DISC_FREQ,
        (unsigned char *)(g_discConfig.discFreq),
        sizeof(g_discConfig.discFreq)
    },
    {
        SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH,
        (unsigned char *)&(g_tranConfig.maxProxyBytesLen),
        sizeof(g_tranConfig.maxProxyBytesLen)
    },
    {
        SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH,
        (unsigned char *)&(g_tranConfig.maxProxyMessageLen),
        sizeof(g_tranConfig.maxProxyMessageLen)
    },
    {
        SOFTBUS_INT_LNN_SUPPORT_FEATURE,
        (unsigned char *)&(g_config.supportFeature),
        sizeof(g_config.supportFeature)
    },
    {
        SOFTBUS_INT_CONN_COC_MAX_DATA_LENGTH,
        (unsigned char *)&(g_config.connCocMaxDataLen),
        sizeof(g_config.connCocMaxDataLen)
    },
    {
        SOFTBUS_INT_CONN_COC_SEND_MTU,
        (unsigned char *)&(g_config.connCocSendMtu),
        sizeof(g_config.connCocSendMtu)
    },
    {
        SOFTBUS_INT_CONN_BLE_CLOSE_DELAY_TIME,
        (unsigned char *)&(g_config.connBleCloseDelayTime),
        sizeof(g_config.connBleCloseDelayTime)
    },
    {
        SOFTBUS_INT_BLE_MAC_AUTO_REFRESH_SWITCH,
        (unsigned char *)&(g_config.bleMacAutoRefreshSwitch),
        sizeof(g_config.bleMacAutoRefreshSwitch)
    },
    {
        SOFTBUS_INT_DISC_COAP_MAX_DEVICE_NUM,
        (unsigned char *)&(g_discConfig.discCoapMaxDeviceNum),
        sizeof(g_discConfig.discCoapMaxDeviceNum)
    },
    {
        SOFTBUS_INT_AUTH_CAPACITY,
        (unsigned char *)&(g_config.authCapacity),
        sizeof(g_config.authCapacity)
    },
};

int SoftbusSetConfig(ConfigType type, const unsigned char *val, uint32_t len)
{
    if ((type >= SOFTBUS_CONFIG_TYPE_MAX) || (val == NULL) ||
        (len > g_configItems[type].len) || (type != g_configItems[type].type)) {
        COMM_LOGW(COMM_DFX, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(g_configItems[type].val, g_configItems[type].len, val, len) != EOK) {
        COMM_LOGW(COMM_DFX, "memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    if ((type >= SOFTBUS_CONFIG_TYPE_MAX) || (val == NULL) ||
        (len != g_configItems[type].len) || (type != g_configItems[type].type)) {
        COMM_LOGW(COMM_DFX, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s((void*)val, len, g_configItems[type].val, g_configItems[type].len) != EOK) {
        COMM_LOGW(COMM_DFX, "memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void SoftbusConfigSetTransDefaultVal(void)
{
    g_tranConfig.isSupportTcpProxy = DEFAULT_IS_SUPPORT_TCP_PROXY;
    g_tranConfig.maxBytesNewLen = DEFAULT_NEW_BYTES_LEN;
    g_tranConfig.maxMessageNewLen = DEFAULT_NEW_MESSAGE_LEN;
    g_tranConfig.maxBytesLen = DEFAULT_MAX_BYTES_LEN;
    g_tranConfig.maxMessageLen = DEFAULT_MAX_MESSAGE_LEN;
    g_tranConfig.maxAuthBytesLen = DEFAULT_AUTH_MAX_BYTES_LEN;
    g_tranConfig.maxAuthMessageLen = DEFAULT_AUTH_MAX_MESSAGE_LEN;
    g_tranConfig.maxProxyBytesLen = DEFAULT_PROXY_MAX_BYTES_LEN;
    g_tranConfig.maxProxyMessageLen = DEFAULT_PROXY_MAX_MESSAGE_LEN;
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