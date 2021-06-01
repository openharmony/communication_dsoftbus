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

#include "auth_connection.h"

#include <securec.h>
#include "auth_common.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t __attribute__ ((weak)) AuthSocketSendData(AuthManager *auth,
    const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    (void)auth;
    (void)head;
    (void)data;
    (void)len;
    return SOFTBUS_ERR;
}

typedef struct {
    AuthSideFlag side;
    int64_t seq;
    uint32_t connectionId;
    int32_t connModule;
} PostDataInfo;

static int32_t PostDataByConn(const PostDataInfo *info, char *buf, uint32_t postDataLen)
{
    int64_t seq = 0;
    if (info->connModule == MODULE_DEVICE_AUTH ||
        info->connModule == MODULE_TRUST_ENGINE || info->connModule == MODULE_AUTH_SDK) {
        seq = info->seq;
    } else if (info->connModule == MODULE_AUTH_CONNECTION) {
        seq = GetSeq(info->side);
    } else {
        LOG_ERR("invalid conn module.");
        SoftBusFree(buf);
        return SOFTBUS_INVALID_PARAM;
    }

    ConnPostData postParam;
    postParam.module = info->connModule;
    postParam.seq = seq;
    postParam.flag = info->side;
    postParam.pid = 0;
    postParam.buf = buf;
    postParam.len = postDataLen + ConnGetHeadSize();

    return ConnPostBytes(info->connectionId, &postParam);
}

static int32_t SetBufData(char *buf, const AuthManager *auth, const AuthDataHead *head,
    const uint8_t *data, uint32_t len)
{
    buf += ConnGetHeadSize();
    if (auth->option.type != CONNECT_TCP) {
        *(int32_t *)buf = head->dataType;
        buf += sizeof(int32_t);
        *(int32_t *)buf = head->module;
        buf += sizeof(int32_t);
        *(int64_t *)buf = head->authId;
        buf += sizeof(int64_t);
        *(int32_t *)buf = head->flag;
        buf += sizeof(int32_t);
        *(int32_t *)buf = len;
        buf += sizeof(int32_t);
    }
    if (memcpy_s(buf, len, data, len) != EOK) {
        LOG_ERR("memcpy_s failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void HandlePeerSyncDeviceInfo(AuthManager *auth, const AuthDataHead *head)
{
    if (head->dataType == DATA_TYPE_SYNC) {
        auth->status = SYNC_FINISH;
    }
    if (head->dataType == DATA_TYPE_SYNC && auth->encryptDevData != NULL) {
        AuthHandlePeerSyncDeviceInfo(auth, auth->encryptDevData, auth->encryptLen);
        SoftBusFree(auth->encryptDevData);
        auth->encryptDevData = NULL;
    }
}

int32_t AuthPostData(const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    if (head == NULL || data == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(head->authId, false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(head->authId, true);
        if (auth == NULL) {
            LOG_ERR("no match auth found, AuthPostData failed");
            return SOFTBUS_ERR;
        }
    }

    if (auth->option.type == CONNECT_TCP) {
        if (AuthSocketSendData(auth, head, data, len) != SOFTBUS_OK) {
            LOG_ERR("AuthSocketSendData failed");
            return SOFTBUS_ERR;
        }
    } else {
        PostDataInfo info;
        uint32_t postDataLen;
        info.side = auth->side;
        info.connectionId = auth->connectionId;
        postDataLen = sizeof(AuthDataInfo) + len;
        info.connModule = MODULE_DEVICE_AUTH;
        info.seq = GetSeq(auth->side);
        char *connPostData = NULL;
        char *buf = (char *)SoftBusMalloc(ConnGetHeadSize() + postDataLen);
        if (buf == NULL) {
            LOG_ERR("SoftBusMalloc failed");
            return SOFTBUS_ERR;
        }
        connPostData = buf;
        if (SetBufData(buf, auth, head, data, len) != SOFTBUS_OK) {
            LOG_ERR("SetBufData failed");
            SoftBusFree(connPostData);
            return SOFTBUS_ERR;
        }
        LOG_INFO("auth start post data, authId is %lld, connectionId is %u, moduleId is %d, seq is %lld",
            auth->authId, info.connectionId, info.connModule, info.seq);
        if (PostDataByConn(&info, connPostData, postDataLen) != SOFTBUS_OK) {
            LOG_ERR("PostDataByConn failed");
            return SOFTBUS_ERR;
        }
    }
    HandlePeerSyncDeviceInfo(auth, head);
    return SOFTBUS_OK;
}

static cJSON *AuthPackDeviceInfo(const AuthManager *auth)
{
    if (auth == NULL) {
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("auth get uuid failed!");
        cJSON_Delete(msg);
        return NULL;
    }
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("auth get device udid failed!");
        cJSON_Delete(msg);
        return NULL;
    }
    if (auth->option.type == CONNECT_TCP && auth->side == CLIENT_SIDE_FLAG) {
        if (AddStringToJsonObject(msg, CMD_TAG, CMD_GET_AUTH_INFO) == false) {
            LOG_ERR("AddStringToJsonObject failed!");
            cJSON_Delete(msg);
            return NULL;
        }
    } else {
        if (AddStringToJsonObject(msg, CMD_TAG, CMD_RET_AUTH_INFO) == false) {
            LOG_ERR("AddStringToJsonObject failed!");
            cJSON_Delete(msg);
            return NULL;
        }
    }
    if (!AddStringToJsonObject(msg, DATA_TAG, uuid) ||
        !AddStringToJsonObject(msg, TE_DEVICE_ID_TAG, udid) ||
        !AddNumberToJsonObject(msg, DATA_BUF_SIZE_TAG, PACKET_SIZE) ||
        !AddNumberToJsonObject(msg, SOFTBUS_VERSION_INFO, auth->softbusVersion)) {
        LOG_ERR("AddStringToJsonObject Fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    return msg;
}

int32_t AuthSyncDeviceUuid(AuthManager *auth)
{
    if (auth == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthDataHead head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    cJSON *obj = AuthPackDeviceInfo(auth);
    if (obj == NULL) {
        LOG_ERR("AuthPackDeviceInfo failed");
        return SOFTBUS_ERR;
    }
    char *msgStr = cJSON_PrintUnformatted(obj);
    if (msgStr == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
        cJSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    auth->status = IN_AUTH_PROGRESS;
    if (auth->option.type == CONNECT_TCP) {
        head.module = MODULE_TRUST_ENGINE;
    } else {
        head.dataType = DATA_TYPE_DEVICE_ID;
        head.module = NONE;
    }
    head.authId = auth->authId;
    head.flag = auth->side;
    if (AuthPostData(&head, (uint8_t *)msgStr, strlen(msgStr) + 1) != SOFTBUS_OK) {
        LOG_ERR("AuthPostData failed");
        cJSON_free(msgStr);
        cJSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    cJSON_free(msgStr);
    cJSON_Delete(obj);
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceId(cJSON *msg, AuthManager *auth)
{
    if (!GetJsonObjectStringItem(msg, DATA_TAG, auth->peerUuid, UUID_BUF_LEN)) {
        LOG_ERR("auth get peer uuid failed");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(msg, TE_DEVICE_ID_TAG, auth->peerUdid, UDID_BUF_LEN)) {
        LOG_ERR("auth get peer udid failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthUnpackDeviceInfo(AuthManager *auth, uint8_t *data)
{
    if (auth == NULL || data == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *msg = cJSON_Parse((char*)data);
    if (msg == NULL) {
        LOG_ERR("json parse failed.");
        return SOFTBUS_ERR;
    }
    char cmd[CMD_TAG_LEN] = {0};
    if (!GetJsonObjectStringItem(msg, CMD_TAG, cmd, CMD_TAG_LEN)) {
        LOG_ERR("auth get cmd tag failed");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    if (auth->option.type == CONNECT_TCP && auth->side == SERVER_SIDE_FLAG) {
        if (strncmp(cmd, CMD_GET_AUTH_INFO, strlen(CMD_GET_AUTH_INFO)) != 0) {
            LOG_ERR("auth cmd tag error");
            cJSON_Delete(msg);
            return SOFTBUS_ERR;
        }
    } else {
        if (strncmp(cmd, CMD_RET_AUTH_INFO, strlen(CMD_RET_AUTH_INFO)) != 0) {
            LOG_ERR("auth cmd tag error");
            cJSON_Delete(msg);
            return SOFTBUS_ERR;
        }
    }
    if (UnpackDeviceId(msg, auth) != SOFTBUS_OK) {
        LOG_ERR("UnpackDeviceId failed");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    int32_t packetSize;
    if (!GetJsonObjectNumberItem(msg, DATA_BUF_SIZE_TAG, &packetSize)) {
        LOG_ERR("auth get packet size failed");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }

    int32_t peerVersion;
    if (!GetJsonObjectNumberItem(msg, SOFTBUS_VERSION_INFO, &peerVersion)) {
        auth->peerVersion = SOFT_BUS_OLD_V2;
    } else {
        auth->peerVersion = (SoftBusVersion)peerVersion;
    }
    cJSON_Delete(msg);
    return SOFTBUS_OK;
}

char *AuthGenDeviceLevelParam(const AuthManager *auth, bool isClient)
{
    if (auth == NULL) {
        LOG_ERR("invalid parameter");
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, auth->peerUdid) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        cJSON_AddBoolToObject(msg, FIELD_IS_CLIENT, isClient) == NULL ||
        !AddNumberToJsonObject(msg, FIELD_KEY_LENGTH, SESSION_KEY_LENGTH)) {
        LOG_ERR("AddStringToJsonObject Fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(msg);
    return data;
}

void AuthSendCloseAck(uint32_t connectionId)
{
    LOG_INFO("auth finished, send close ack");
    const char *closeData = "close ack";
    uint32_t closeDataLen = strlen(closeData) + 1;

    PostDataInfo info;
    uint32_t postDataLen = sizeof(AuthDataInfo) + closeDataLen;
    char *connPostData = NULL;
    char *buf = (char *)SoftBusMalloc(ConnGetHeadSize() + postDataLen);
    if (buf == NULL) {
        LOG_ERR("SoftBusMalloc failed");
        return;
    }
    connPostData = buf;
    buf += ConnGetHeadSize();
    *(int32_t *)buf = DATA_TYPE_CLOSE_ACK;
    buf += sizeof(int32_t);
    *(int32_t *)buf = NONE;
    buf += sizeof(int32_t);
    *(int64_t *)buf = 0;
    buf += sizeof(int64_t);
    *(int32_t *)buf = 0;
    buf += sizeof(int32_t);
    *(int32_t *)buf = closeDataLen;
    buf += sizeof(int32_t);
    if (memcpy_s(buf, closeDataLen, closeData, closeDataLen) != EOK) {
        LOG_ERR("memcpy_s failed");
        SoftBusFree(connPostData);
        return;
    }
    info.side = (AuthSideFlag)0;
    info.seq = 0;
    info.connectionId = connectionId;
    info.connModule = MODULE_DEVICE_AUTH;
    if (PostDataByConn(&info, connPostData, postDataLen) != SOFTBUS_OK) {
        LOG_ERR("PostDataByConn failed");
        return;
    }
}

void AuthTryCloseConnection(uint32_t connectionId)
{
    (void)ConnDisconnectDevice(connectionId);
}

bool AuthOnTransmit(int64_t authId, const uint8_t *data, uint32_t len)
{
    AuthManager *auth = NULL;
    AuthDataHead head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    auth = AuthGetManagerByAuthId(authId, false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, true);
        if (auth == NULL) {
            LOG_ERR("no match auth found");
            return false;
        }
    }
    head.dataType = DATA_TYPE_AUTH;
    head.module = AUTH_SDK;
    head.authId = auth->authId;
    head.flag = auth->side;
    return AuthPostData(&head, data, len) == SOFTBUS_OK;
}

#ifdef __cplusplus
}
#endif
