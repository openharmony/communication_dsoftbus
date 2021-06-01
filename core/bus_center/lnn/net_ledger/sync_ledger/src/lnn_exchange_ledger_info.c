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

#include "lnn_exchange_ledger_info.h"

#include <stdint.h>
#include <stdlib.h>

#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "softbus_errcode.h"
#include "softbus_mem_interface.h"

static int32_t PackCommon(cJSON *json, const NodeInfo *info, SoftBusVersion version)
{
    if (json == NULL || info == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (version >= SOFT_BUS_NEW_V1) {
        if (!AddStringToJsonObject(json, SW_VERSION, info->softBusVersion)) {
            LOG_ERR("AddStringToJsonObject Fail.");
            return SOFTBUS_ERR;
        }
    }

    if (!AddStringToJsonObject(json, DEVICE_NAME, LnnGetDeviceName(&info->deviceInfo)) ||
        !AddStringToJsonObject(json, DEVICE_TYPE, LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId)) ||
        !AddStringToJsonObject(json, DEVICE_UDID, LnnGetDeviceUdid(info)) ||
        !AddStringToJsonObject(json, NETWORK_ID, info->networkId) ||
        !AddStringToJsonObject(json, VERSION_TYPE, info->versionType) ||
        !AddNumberToJsonObject(json, CONN_CAP, info->netCapacity)) {
        LOG_ERR("AddStringToJsonObject Fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UnPackCommon(const cJSON* json, NodeInfo *info, SoftBusVersion version)
{
    char deviceType[DEVICE_TYPE_BUF_LEN] = {0};
    uint8_t typeId;
    if (json == NULL || info == NULL) {
        LOG_ERR("para error!");
        return;
    }

    if (version >= SOFT_BUS_NEW_V1) {
        (void)GetJsonObjectStringItem(json, SW_VERSION, info->softBusVersion, VERSION_MAX_LEN);
    }

    (void)GetJsonObjectStringItem(json, DEVICE_NAME, info->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN);
    if (GetJsonObjectStringItem(json, DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN)) {
        if (LnnConvertDeviceTypeToId(deviceType, &typeId) == SOFTBUS_OK) {
            info->deviceInfo.deviceTypeId = typeId;
        }
    }
    (void)GetJsonObjectStringItem(json, DEVICE_UDID, info->deviceInfo.deviceUdid, UDID_BUF_LEN);
    (void)GetJsonObjectStringItem(json, NETWORK_ID, info->networkId, NETWORK_ID_BUF_LEN);
    (void)GetJsonObjectStringItem(json, VERSION_TYPE, info->versionType, VERSION_MAX_LEN);
    (void)GetJsonObjectNumberItem(json, CONN_CAP, (int *)&info->netCapacity);
    return;
}

static char *PackBt(const NodeInfo *info, SoftBusVersion version)
{
    if (info == NULL) {
        LOG_ERR("info para error!");
        return NULL;
    }
    LOG_INFO("PackBt enter!");
    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        LOG_ERR("create cjson object error!");
        return NULL;
    }

    if (!AddNumberToJsonObject(json, CODE, CODE_VERIFY_BT) ||
        !AddStringToJsonObject(json, BT_MAC, LnnGetBtMac(info))) {
        LOG_ERR("AddToJsonObject error!");
        cJSON_Delete(json);
        return NULL;
    }

    if (PackCommon(json, info, version) != SOFTBUS_OK) {
        LOG_ERR("PackCommon error!");
        cJSON_Delete(json);
        return NULL;
    }

    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

static int32_t UnPackBt(const cJSON *json, NodeInfo *info, SoftBusVersion version)
{
    if (info == NULL || json == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)GetJsonObjectStringItem(json, BT_MAC, info->connectInfo.macAddr, MAC_LEN);
    UnPackCommon(json, info, version);
    return SOFTBUS_OK;
}

static int32_t UnPackWifi(const cJSON* json, NodeInfo *info, SoftBusVersion version)
{
    if (info == NULL || json == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)GetJsonObjectNumberItem(json, AUTH_PORT, &info->connectInfo.authPort);
    (void)GetJsonObjectNumberItem(json, SESSION_PORT, &info->connectInfo.sessionPort);
    (void)GetJsonObjectNumberItem(json, PROXY_PORT, &info->connectInfo.proxyPort);
    UnPackCommon(json, info, version);
    return SOFTBUS_OK;
}

static char *PackWifi(const NodeInfo *info, SoftBusVersion version)
{
    if (info == NULL) {
        LOG_ERR("info para error!");
        return NULL;
    }
    LOG_INFO("PackWifi enter!");
    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        LOG_ERR("create cjson object error!");
        return NULL;
    }

    if (!AddNumberToJsonObject(json, CODE, CODE_VERIFY_IP) ||
        !AddNumberToJsonObject(json, BUS_MAX_VERSION, BUS_V2) ||
        !AddNumberToJsonObject(json, BUS_MIN_VERSION, BUS_V1) ||
        !AddNumberToJsonObject(json, AUTH_PORT, LnnGetAuthPort(info)) ||
        !AddNumberToJsonObject(json, SESSION_PORT, LnnGetSessionPort(info)) ||
        !AddNumberToJsonObject(json, PROXY_PORT, LnnGetProxyPort(info))) {
        LOG_ERR("AddStringToJsonObject Fail.");
        cJSON_Delete(json);
        return NULL;
    }

    if (PackCommon(json, info, version) != SOFTBUS_OK) {
        LOG_ERR("PackCommon error!");
        cJSON_Delete(json);
        return NULL;
    }

    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted Failed!");
    }
    cJSON_Delete(json);
    return data;
}

static ProcessLedgerInfo g_processFuncs[] = {
    {AUTH_BT, PackBt, UnPackBt},
    {AUTH_WIFI, PackWifi, UnPackWifi},
};

char *PackLedgerInfo(SoftBusVersion version, AuthType type)
{
    uint32_t i;
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        LOG_ERR("info = null.");
        return NULL;
    }
    for (i = 0; i < sizeof(g_processFuncs) / sizeof(ProcessLedgerInfo); i++) {
        if (g_processFuncs[i].type == type) {
            return g_processFuncs[i].pack(info, version);
        }
    }
    return NULL;
}

static int32_t UnPackLedgerInfo(const cJSON *json, NodeInfo *info,
    SoftBusVersion version, AuthType type)
{
    uint32_t i;
    if (info == NULL || json == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    for (i = 0; i < sizeof(g_processFuncs) / sizeof(ProcessLedgerInfo); i++) {
        if (g_processFuncs[i].type == type) {
            return g_processFuncs[i].unpack(json, info, version);
        }
    }
    return SOFTBUS_ERR;
}
static ConvertType g_convertTable[] = {
    {CONNECT_BR, AUTH_BT},
    {CONNECT_BLE, AUTH_BT},
    {CONNECT_TCP, AUTH_WIFI},
};

static AuthType ConvertCnnTypeToAuthType(ConnectType type)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_convertTable) / sizeof(ConvertType); i++) {
        if (g_convertTable[i].cnnType == type) {
            return g_convertTable[i].authType;
        }
    }
    return AUTH_MAX;
}

uint8_t *LnnGetExchangeNodeInfo(ConnectOption *option, SoftBusVersion version,
    uint32_t *outSize, AuthSideFlag *side)
{
    char *data = NULL;
    uint8_t *encryptData = NULL;
    OutBuf buf = {0};
    AuthType authType;
    uint32_t len;

    if (option == NULL || outSize == NULL || side == NULL) {
        return NULL;
    }
    authType = ConvertCnnTypeToAuthType(option->type);
    data = PackLedgerInfo(version, authType);
    if (data == NULL) {
        LOG_ERR("pack ledger info error!");
        return NULL;
    }
    len = strlen(data) + 1 + AuthGetEncryptHeadLen();
    encryptData = (uint8_t *)SoftBusCalloc(len);
    if (encryptData == NULL) {
        LOG_ERR("malloc error!");
        cJSON_free(data);
        return NULL;
    }
    buf.buf = encryptData;
    buf.bufLen = len;
    if (AuthEncrypt(option, side, (uint8_t *)data, strlen(data) + 1, &buf) != SOFTBUS_OK) {
        LOG_ERR("AuthEncrypt error.");
        cJSON_free(data);
        SoftBusFree(encryptData);
        return NULL;
    }
    if (buf.outLen != len) {
        LOG_ERR("outLen not right.");
    }
    *outSize = buf.outLen;
    cJSON_free(data);
    return encryptData;
}

int32_t LnnParsePeerNodeInfo(ConnectOption *option, NodeInfo *info,
    const ParseBuf *bufInfo, AuthSideFlag side, SoftBusVersion version)
{
    cJSON *json = NULL;
    int ret = SOFTBUS_OK;
    uint8_t *decryptData = NULL;
    OutBuf buf = {0};
    AuthType authType;
    if ((option == NULL) || (info == NULL) || (bufInfo == NULL) || (bufInfo->buf == NULL)) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    authType = ConvertCnnTypeToAuthType(option->type);
    decryptData = (uint8_t *)SoftBusCalloc(bufInfo->len - AuthGetEncryptHeadLen() + 1);
    if (decryptData == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    buf.buf = decryptData;
    buf.bufLen = bufInfo->len - AuthGetEncryptHeadLen();

    // Decrypt
    if (AuthDecrypt(option, side, bufInfo->buf, bufInfo->len, &buf) != SOFTBUS_OK) {
        SoftBusFree(decryptData);
        return SOFTBUS_ERR;
    }
    json = cJSON_Parse((char *)decryptData);
    SoftBusFree(decryptData);
    decryptData = NULL;
    if (json == NULL) {
        LOG_ERR("CJSON PARSE error!");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (UnPackLedgerInfo(json, info, version, authType) != SOFTBUS_OK) {
        LOG_ERR("UnPackLedgerInfo error!");
        ret = SOFTBUS_ERR;
    }
    cJSON_Delete(json);
    return ret;
}