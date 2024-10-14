/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_log.h"
#include "auth_meta_manager.h"
#include "auth_common.h"

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    (void)connectionId;
    (void)authKeyInfo;
    (void)requestId;
    (void)callingPid;
    (void)callBack;
    AUTH_LOGI(AUTH_INIT, "auth meta not support verify");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthMetaReleaseVerify(int64_t authId)
{
    (void)authId;
    AUTH_LOGI(AUTH_INIT, "auth meta not support verify");
}

int32_t AuthMetaEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    AUTH_LOGI(AUTH_CONN, "auth meta encrypt data");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    AUTH_LOGI(AUTH_CONN, "auth meta decrypt data");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    (void)uuid;
    (void)connInfo;
    AUTH_LOGI(AUTH_CONN, "auth meta get prefer conninfo");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    (void)info;
    (void)requestId;
    (void)callback;
    AUTH_LOGI(AUTH_CONN, "auth meta open connection");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthMetaNotifyDataReceived(uint32_t connectionId, const SocketPktHead *pktHead, const uint8_t *data)
{
    (void)connectionId;
    (void)pktHead;
    (void)data;
    AUTH_LOGI(AUTH_CONN, "auth meta notify data received");
}

void AuthMetaCloseConn(int64_t authId)
{
    (void)authId;
    AUTH_LOGI(AUTH_CONN, "auth meta close connection");
}

int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    (void)authId;
    (void)dataInfo;
    AUTH_LOGI(AUTH_CONN, "auth meta start post transdata");
    return SOFTBUS_NOT_IMPLEMENT;
}

int64_t AuthMetaGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    (void)connInfo;
    (void)isServer;
    AUTH_LOGI(AUTH_CONN, "auth meta get auth id by connection info");
    return SOFTBUS_NOT_IMPLEMENT;
}

int64_t AuthMetaGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer)
{
    (void)uuid;
    (void)type;
    (void)isServer;
    AUTH_LOGI(AUTH_CONN, "auth meta get auth id by uuid");
    return SOFTBUS_NOT_IMPLEMENT;
}
 
int32_t AuthMetaSetP2pMac(int64_t authId, const char *p2pMac)
{
    (void)authId;
    (void)p2pMac;
    AUTH_LOGI(AUTH_CONN, "auth meta set p2p mac info by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    (void)authId;
    (void)connInfo;
    AUTH_LOGI(AUTH_CONN, "auth meta get connection info by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer)
{
    (void)authId;
    (void)isServer;
    AUTH_LOGI(AUTH_CONN, "auth meta get server side");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    (void)authId;
    (void)uuid;
    (void)size;
    AUTH_LOGI(AUTH_CONN, "auth meta get device uuid by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetVersion(int64_t authId, SoftBusVersion *version)
{
    (void)authId;
    (void)version;
    AUTH_LOGI(AUTH_CONN, "auth meta get version by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaInit(const AuthTransCallback *callback)
{
    (void)callback;
    AUTH_LOGI(AUTH_INIT, "auth meta init");
    return SOFTBUS_OK;
}

void AuthMetaDeinit(void)
{
    AUTH_LOGI(AUTH_INIT, "auth meta deinit");
}

void DelAuthMetaManagerByPid(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
}

int32_t AuthMetaGetConnIdByInfo(const AuthConnInfo *connInfo, uint32_t *connectionId)
{
    (void)connInfo;
    (void)connectionId;
    return SOFTBUS_OK;
}

void AuthMetaCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist)
{
    (void)connInfo;
    (void)isExist;
}

void DelAuthMetaManagerByConnectionId(uint32_t connectionId)
{
    (void)connectionId;
}
