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

#include "auth_meta_manager.h"
#include "auth_common.h"

int32_t AuthMetaStartVerify(uint32_t connectionId, const uint8_t *key, uint32_t keyLen,
    uint32_t requestId, const AuthVerifyCallback *callBack)
{
    (void)connectionId;
    (void)key;
    (void)keyLen;
    (void)requestId;
    (void)callBack;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta start verify");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthMetaReleaseVerify(int64_t authId)
{
    (void)authId;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta release verify");
}

int32_t AuthMetaEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta encrypt data");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta decrypt data");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    (void)uuid;
    (void)connInfo;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get prefer conninfo");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    (void)info;
    (void)requestId;
    (void)callback;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta open connection");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthMetaCloseConn(int64_t authId)
{
    (void)authId;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta close connection");
}

int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    (void)authId;
    (void)dataInfo;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta start post transdata");
    return SOFTBUS_NOT_IMPLEMENT;
}

int64_t AuthMetaGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    (void)connInfo;
    (void)isServer;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get auth id by connection info");
    return SOFTBUS_NOT_IMPLEMENT;
}

int64_t AuthMetaGetIdByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer)
{
    (void)p2pMac;
    (void)type;
    (void)isServer;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get auth id by p2p mac info");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaSetP2pMac(int64_t authId, const char *p2pMac)
{
    (void)authId;
    (void)p2pMac;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta set p2p mac info by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    (void)authId;
    (void)connInfo;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get connection info by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer)
{
    (void)authId;
    (void)isServer;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get server side");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    (void)authId;
    (void)uuid;
    (void)size;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get device uuid by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaGetVersion(int64_t authId, SoftBusVersion *version)
{
    (void)authId;
    (void)version;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta get version by auth id");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthMetaInit(const AuthTransCallback *callback)
{
    (void)callback;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta init");
    return SOFTBUS_OK;
}

void AuthMetaDeinit(void)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth meta deinit");
    return;
}
