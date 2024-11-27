/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "authmanager_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include "auth_manager.h"
#include "fuzz_data_generator.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

#include "auth_manager.c"

using namespace std;

#define UDID_HASH_LEN 32

static const std::vector<AuthLinkType> AUTH_LINK_TYPE_LIST = { AUTH_LINK_TYPE_WIFI, AUTH_LINK_TYPE_BR,
    AUTH_LINK_TYPE_BLE, AUTH_LINK_TYPE_P2P, AUTH_LINK_TYPE_ENHANCED_P2P, AUTH_LINK_TYPE_RAW_ENHANCED_P2P,
    AUTH_LINK_TYPE_NORMALIZED };

static const std::vector<string> AUTH_LINK_TYPE_WIFI_IP_LIST = { "192.168.1.1", "192.168.1.2", "192.168.2.1",
    "192.168.3.1", "192.168.1.12", "192.168.11.12", "192.168.111.11", "192.168.110.1", "192.168.75.3", "192.168.64.24",
    "192.168.5.1" };

static const std::vector<ModeCycle> MODE_CYCLE_LIST = { HIGH_FREQ_CYCLE, MID_FREQ_CYCLE, LOW_FREQ_CYCLE,
    DEFAULT_FREQ_CYCLE };

static int32_t FuzzEnvInit(const uint8_t *data, size_t size)
{
    int32_t ret = AuthCommonInit();
    DataGenerator::Write(data, size);
    return ret;
}

static void FuzzEnvDeinit()
{
    AuthCommonDeinit();
    DataGenerator::Clear();
}

namespace OHOS {
    bool NewAuthManagerFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        GenerateBool(info.isServer);
        string udid, uuid;
        GenerateString(udid);
        GenerateString(uuid);
        if (memcpy_s(info.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        GenerateFromList(info.connInfo.type, AUTH_LINK_TYPE_LIST);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        return true;
    }

    bool GetAuthManagerByAuthIdFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        GenerateBool(info.isServer);
        string udid, uuid;
        GenerateString(udid);
        GenerateString(uuid);
        if (memcpy_s(info.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        GenerateFromList(info.connInfo.type, AUTH_LINK_TYPE_LIST);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManager *getAuth = GetAuthManagerByAuthId(authSeq);
            if (getAuth != nullptr) {
                DelDupAuthManager(getAuth);
            }
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManager *newAuth = GetAuthManagerByAuthId(authSeq);
        if (newAuth != nullptr) {
            DelDupAuthManager(newAuth);
        }
        return true;
    }

    bool RemoveAuthManagerByAuthIdFuzzTest(const uint8_t *data, size_t size)
    {
        AuthHandle authHandle = {0};
        GenerateInt64(authHandle.authId);
        GenerateUint32(authHandle.type);
        RemoveAuthManagerByAuthId(authHandle);
        return true;
    }

    bool GetAuthManagerByConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        GenerateBool(info.isServer);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManager *getAuth = GetAuthManagerByConnInfo(&info.connInfo, info.isServer);
            if (getAuth != nullptr) {
                DelDupAuthManager(getAuth);
            }
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManager *newAuth = GetAuthManagerByConnInfo(&info.connInfo, info.isServer);
        if (newAuth != nullptr) {
            DelDupAuthManager(newAuth);
        }
        return true;
    }

    bool GetAuthIdByConnIdFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        GenerateBool(info.isServer);
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetAuthIdByConnId(info.connId, info.isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        GetAuthIdByConnId(info.connId, info.isServer);
        return true;
    }

    bool RemoveNotPassedAuthManagerByUdidFuzzTest(const uint8_t *data, size_t size)
    {
        string udid;
        GenerateString(udid);
        RemoveNotPassedAuthManagerByUdid(udid.c_str());
        return true;
    }

    bool GetAuthConnInfoByUuidFuzzTest(const uint8_t *data, size_t size)
    {
        string uuid;
        GenerateString(uuid);
        string udid;
        GenerateString(udid);
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthLinkType type = AUTH_LINK_TYPE_WIFI;
        AuthSessionInfo sessionInfo = {0};
        sessionInfo.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        GenerateBool(sessionInfo.isServer);
        if (memcpy_s(sessionInfo.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(sessionInfo.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        sessionInfo.connInfo.type = type;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(sessionInfo.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthConnInfo info;
        (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
        AuthManager *auth = NewAuthManager(authSeq, &sessionInfo);
        if (auth != nullptr) {
            GetAuthConnInfoByUuid(uuid.c_str(), type, &info);
            DelAuthManager(auth, auth->connInfo[sessionInfo.connInfo.type].type);
        }
        GetAuthConnInfoByUuid(uuid.c_str(), type, &info);
        return true;
    }

    bool GetLatestIdByConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthLinkType type = AUTH_LINK_TYPE_WIFI;
        AuthSessionInfo info = {0};
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        GenerateBool(info.isServer);
        string uuid, udid;
        GenerateString(uuid);
        GenerateString(udid);
        if (memcpy_s(info.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = type;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetLatestIdByConnInfo(&info.connInfo);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        GetLatestIdByConnInfo(&info.connInfo);
        return true;
    }

    bool GetActiveAuthIdByConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthLinkType type = AUTH_LINK_TYPE_WIFI;
        AuthSessionInfo info = {0};
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        GenerateBool(info.isServer);
        string uuid, udid;
        GenerateString(uuid);
        GenerateString(udid);
        if (memcpy_s(info.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = type;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetActiveAuthIdByConnInfo(&info.connInfo, info.isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        GetActiveAuthIdByConnInfo(&info.connInfo, info.isServer);
        return true;
    }

    bool GetDeviceAuthManagerFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        GenerateBool(info.isServer);
        string uuid, udid;
        GenerateString(uuid);
        GenerateString(udid);
        if (memcpy_s(info.udid, UDID_BUF_LEN, udid.c_str(), UDID_BUF_LEN) != EOK) {
            return false;
        }
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str(), UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        int64_t lastAuthSeq = authSeq;
        bool isNewCreated;
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetDeviceAuthManager(authSeq, &info, &isNewCreated, lastAuthSeq);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        GetDeviceAuthManager(authSeq, &info, &isNewCreated, lastAuthSeq);
        return true;
    }

    bool AuthManagerSetSessionKeyFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        SessionKey key;
        (void)memset_s(&key, sizeof(SessionKey), 0, sizeof(SessionKey));
        string value;
        GenerateString(value);
        if (memcpy_s(key.value, SESSION_KEY_LENGTH, value.c_str(), SESSION_KEY_LENGTH) != EOK) {
            return false;
        }
        GenerateUint32(key.len);
        bool isConnect = false;
        bool isOldKey = false;
        GenerateBool(isConnect);
        GenerateBool(isOldKey);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManagerSetSessionKey(authSeq, &info, &key, isConnect, isOldKey);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManagerSetSessionKey(authSeq, &info, &key, isConnect, isOldKey);
        return true;
    }

    bool AuthManagerGetSessionKeyFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        SessionKey key;
        (void)memset_s(&key, sizeof(SessionKey), 0, sizeof(SessionKey));
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManagerGetSessionKey(authSeq, &info, &key);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManagerGetSessionKey(authSeq, &info, &key);
        return true;
    }

    bool AuthNotifyAuthPassedFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthNotifyAuthPassed(authSeq, &info);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthNotifyAuthPassed(authSeq, &info);
        return true;
    }

    bool AuthManagerSetAuthPassedFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.module = AUTH_MODULE_TRANS;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManagerSetAuthPassed(authSeq, &info);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManagerSetAuthPassed(authSeq, &info);
        return true;
    }

    bool AuthManagerSetAuthFailedFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        int32_t reason = 0;
        GenerateInt32(reason);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManagerSetAuthFailed(authSeq, &info, reason);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManagerSetAuthFailed(authSeq, &info, reason);
        return true;
    }

    bool AuthManagerSetAuthFinishedFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_BLE;
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthManagerSetAuthFinished(authSeq, &info);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthManagerSetAuthFinished(authSeq, &info);
        return true;
    }

    bool AuthGenRequestIdFuzzTest(const uint8_t *data, size_t size)
    {
        AuthGenRequestId();
        return true;
    }

    bool AuthHandleLeaveLNNFuzzTest(const uint8_t *data, size_t size)
    {
        AuthHandle authHandle = {0};
        GenerateInt64(authHandle.authId);
        GenerateUint32(authHandle.type);
        authHandle.type %= AUTH_LINK_TYPE_MAX;
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authHandle.authId, &info);
        if (auth != nullptr) {
            AuthHandleLeaveLNN(authHandle);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthHandleLeaveLNN(authHandle);
        return true;
    }

    bool TryGetBrConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        string uuid;
        GenerateString(uuid);
        AuthConnInfo info;
        (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
        TryGetBrConnInfo(uuid.c_str(), &info);
        return true;
    }

    bool AuthDeviceGetPreferConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        char udid[UDID_BUF_LEN] = "asjdflkasdjflsd";
        AuthConnInfo info;
        (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
        AuthDeviceGetPreferConnInfo(udid, &info);
        return true;
    }

    bool AuthDeviceGetConnInfoByTypeFuzzTest(const uint8_t *data, size_t size)
    {
        char uuid[UUID_BUF_LEN] = "12341413r43131";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid, UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetConnInfoByType(uuid, info.connInfo.type, &info.connInfo);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetConnInfoByType(uuid, info.connInfo.type, &info.connInfo);
        return true;
    }

    bool AuthDeviceGetP2pConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        char uuid[UUID_BUF_LEN] = "123erjfea";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid, UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetP2pConnInfo(uuid, &info.connInfo);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetP2pConnInfo(uuid, &info.connInfo);
        return true;
    }

    bool AuthDeviceGetHmlConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        char uuid[UUID_BUF_LEN] = "123erjfea";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid, UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetHmlConnInfo(uuid, &info.connInfo);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetHmlConnInfo(uuid, &info.connInfo);
        return true;
    }

    bool AuthDeviceCheckConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        char uuid[UUID_BUF_LEN] = "asdasdfadf";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        bool checkConn = false;
        AuthSessionInfo info = {0};
        if (memcpy_s(info.uuid, UUID_BUF_LEN, uuid, UUID_BUF_LEN) != EOK) {
            return false;
        }
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        info.connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_WIFI, checkConn);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_WIFI, checkConn);
        return true;
    }

    bool AuthGetLatestAuthSeqListByTypeFuzzTest(const uint8_t *data, size_t size)
    {
        char udid[UDID_BUF_LEN] = "abcabcabcabcabc";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        int64_t seqList[1] = {0};
        uint64_t verifyTime[1] = {0};
        GenerateInt64(seqList[0]);
        GenerateUint64(verifyTime[0]);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        DiscoveryType type = DISCOVERY_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthGetLatestAuthSeqListByType(udid, seqList, verifyTime, type);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthGetLatestAuthSeqListByType(udid, seqList, verifyTime, type);
        return true;
    }

    bool AuthGetLatestAuthSeqListFuzzTest(const uint8_t *data, size_t size)
    {
        char udid[UDID_BUF_LEN] = "abcabcabcabcabc";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        int64_t seqList[1] = {0};
        GenerateInt64(seqList[0]);
        DiscoveryType type = DISCOVERY_TYPE_COUNT;
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthGetLatestAuthSeqList(udid, seqList, type);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthGetLatestAuthSeqList(udid, seqList, type);
        return true;
    }

    bool GetHmlOrP2pAuthHandleFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthHandle *authHandle1 = NULL;
        AuthHandle *authHandle2 = NULL;
        int32_t num = 0;
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetHmlOrP2pAuthHandle(&authHandle1, &num);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
            SoftBusFree(authHandle1);
        }
        GetHmlOrP2pAuthHandle(&authHandle2, &num);
        SoftBusFree(authHandle2);
        return true;
    }

    bool AuthDeviceGetLatestIdByUuidFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        char uuid[UUID_BUF_LEN] = "ajsdkfjasdl";
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthHandle authHandle = {0};
        authHandle.authId = authSeq;
        GenerateUint32(authHandle.type);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetLatestIdByUuid(uuid, info.connInfo.type, &authHandle);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetLatestIdByUuid(uuid, info.connInfo.type, &authHandle);
        return true;
    }

    bool AuthDeviceGetIdByConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        char uuid[UUID_BUF_LEN] = "ajsdkfjasdl";
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthHandle authHandle = {0};
        authHandle.authId = authSeq;
        GenerateUint32(authHandle.type);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetLatestIdByUuid(uuid, info.connInfo.type, &authHandle);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetLatestIdByUuid(uuid, info.connInfo.type, &authHandle);
        return true;
    }

    bool AuthDeviceGetIdByUuidFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        char uuid[UUID_BUF_LEN] = "ajsdkfjasdl";
        bool isServer = false;
        GenerateBool(isServer);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = isServer;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthHandle authHandle = {0};
        authHandle.authId = authSeq;
        GenerateUint32(authHandle.type);
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetIdByUuid(uuid, info.connInfo.type, isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetIdByUuid(uuid, info.connInfo.type, isServer);
        return true;
    }

    bool AuthDeviceGetAuthHandleByIndexFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        string udid;
        GenerateString(udid);
        bool isServer = false;
        GenerateBool(isServer);
        int32_t index = 0;
        GenerateInt32(index);
        AuthHandle authHandle = {0};
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = isServer;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthDeviceGetAuthHandleByIndex(udid.c_str(), isServer, index, &authHandle);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthDeviceGetAuthHandleByIndex(udid.c_str(), isServer, index, &authHandle);
        return true;
    }

    bool AuthGetEncryptSizeFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        uint32_t inLen = 0;
        GenerateUint32(inLen);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            AuthGetEncryptSize(authSeq, inLen);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        AuthGetEncryptSize(authSeq, inLen);
        return true;
    }

    bool AuthGetDecryptSizeFuzzTest(const uint8_t *data, size_t size)
    {
        uint32_t inLen = 0;
        GenerateUint32(inLen);
        AuthGetDecryptSize(inLen);
        return true;
    }

    bool AuthDeviceSetP2pMacFuzzTest(const uint8_t *data, size_t size)
    {
        char p2pMac[] = "12:DA:CA:D0:08:3E";
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthDeviceSetP2pMac(authSeq, p2pMac);
        return true;
    }

    bool AuthSendKeepaliveOptionFuzzTest(const uint8_t *data, size_t size)
    {
        string uuid;
        GenerateString(uuid);
        ModeCycle cycle;
        GenerateFromList(cycle, MODE_CYCLE_LIST);
        AuthSendKeepaliveOption(uuid.c_str(), cycle);
        return true;
    }

    bool AuthFlushDeviceFuzzTest(const uint8_t *data, size_t size)
    {
        string uuid;
        GenerateString(uuid);
        AuthFlushDevice(uuid.c_str());
        return true;
    }

    bool FindAuthManagerByUdidFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        string udid;
        GenerateString(udid);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            FindAuthManagerByUdid(udid.c_str(), info.connInfo.type, info.isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        FindAuthManagerByUdid(udid.c_str(), info.connInfo.type, info.isServer);
        return true;
    }

    bool FindAuthManagerByConnIdFuzzTest(const uint8_t *data, size_t size)
    {
        uint64_t connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        string udid;
        GenerateString(udid);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.connId = connId;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            FindAuthManagerByConnId(connId, info.isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        FindAuthManagerByConnId(connId, info.isServer);
        return true;
    }

    bool DestroyAuthManagerListFuzzTest(const uint8_t *data, size_t size)
    {
        DestroyAuthManagerList();
        return true;
    }

    bool SetAuthConnIdFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        string udid;
        GenerateString(udid);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            SetAuthConnId(auth, auth, info.connInfo.type);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        SetAuthConnId(auth, auth, info.connInfo.type);
        return true;
    }

    bool SetAuthP2pMacFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            SetAuthP2pMac(auth, auth, info.connInfo.type);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        SetAuthP2pMac(auth, auth, info.connInfo.type);
        return true;
    }

    bool RemoveAuthManagerByConnInfoFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            RemoveAuthManagerByConnInfo(&info.connInfo, info.isServer);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        RemoveAuthManagerByConnInfo(&info.connInfo, info.isServer);
        return true;
    }

    bool GetAvailableAuthConnInfoByUuidFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        string uuid = {0};
        GenerateString(uuid);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_WIFI;
        info.isServer = true;
        string ip;
        GenerateFromList(ip, AUTH_LINK_TYPE_WIFI_IP_LIST);
        if (memcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip.c_str(), IP_LEN) != EOK) {
            return false;
        }
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            GetAvailableAuthConnInfoByUuid(uuid.c_str(), info.connInfo.type, &info.connInfo);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        GetAvailableAuthConnInfoByUuid(uuid.c_str(), info.connInfo.type, &info.connInfo);
        return true;
    }

    static void OnDataReceived(AuthHandle authHandle, const AuthDataHead *head, const uint8_t *data, uint32_t len)
    {
        (void)authHandle;
        (void)head;
        (void)data;
        (void)len;
    }

    static void OnDisconnected(AuthHandle authHandle)
    {
        (void)authHandle;
    }

    static void OnException(AuthHandle authHandle, int32_t error)
    {
        (void)authHandle;
        (void)error;
    }

    static bool g_isInit = false;

    bool AuthDeviceInitFuzzTest(const uint8_t *data, size_t size)
    {
        if (g_isInit) {
            return true;
        }
        AuthTransCallback transCb = {
            .onDataReceived = OnDataReceived,
            .onDisconnected = OnDisconnected,
            .onException = OnException,
        };
        AuthDeviceInit(&transCb);
        AuthDeviceDeinit();
        g_isInit = true;
        return true;
    }

    bool GenerateUdidHashFuzzTest(const uint8_t *data, size_t size)
    {
        string udid;
        GenerateString(udid);
        uint8_t hash[UDID_HASH_LEN] = {0};
        GenerateUdidHash(udid.c_str(), hash);
        return true;
    }

    bool ProcessEmptySessionKeyFuzzTest(const uint8_t *data, size_t size)
    {
        int64_t authSeq = 0;
        GenerateInt64(authSeq);
        AuthSessionInfo info = {0};
        info.connInfo.type = AUTH_LINK_TYPE_BLE;
        info.isServer = true;
        int32_t index = 0;
        GenerateInt32(index);
        SessionKey key;
        (void)memset_s(&key, sizeof(SessionKey), 0, sizeof(SessionKey));
        AuthManager *auth = NewAuthManager(authSeq, &info);
        if (auth != nullptr) {
            ProcessEmptySessionKey(&info, index, info.isServer, &key);
            DelAuthManager(auth, auth->connInfo[info.connInfo.type].type);
        }
        ProcessEmptySessionKey(&info, index, info.isServer, &key);
        return true;
    }

    bool HandleReconnectResultFuzzTest(const uint8_t *data, size_t size)
    {
        AuthRequest request = {0};
        GenerateUint32(request.requestId);
        uint64_t connId = (uint64_t)(1ULL << INT32_BIT_NUM);
        int32_t result = 0;
        int32_t type = (int32_t)AUTH_LINK_TYPE_WIFI;
        HandleReconnectResult(&request, connId, result, type);
        return true;
    }
}

static void ProcessFuzzRequest(const uint8_t *data, size_t size)
{
    OHOS::AuthDeviceInitFuzzTest(data, size);
    OHOS::NewAuthManagerFuzzTest(data, size);
    OHOS::GetAuthManagerByAuthIdFuzzTest(data, size);
    OHOS::RemoveAuthManagerByAuthIdFuzzTest(data, size);
    OHOS::RemoveNotPassedAuthManagerByUdidFuzzTest(data, size);
    OHOS::GetAuthConnInfoByUuidFuzzTest(data, size);
    OHOS::GetLatestIdByConnInfoFuzzTest(data, size);
    OHOS::GetActiveAuthIdByConnInfoFuzzTest(data, size);
    OHOS::GetDeviceAuthManagerFuzzTest(data, size);
    OHOS::AuthManagerSetSessionKeyFuzzTest(data, size);
    OHOS::AuthManagerGetSessionKeyFuzzTest(data, size);
    OHOS::AuthNotifyAuthPassedFuzzTest(data, size);
    OHOS::AuthManagerSetAuthPassedFuzzTest(data, size);
    OHOS::AuthManagerSetAuthFailedFuzzTest(data, size);
    OHOS::AuthManagerSetAuthFinishedFuzzTest(data, size);
    OHOS::AuthGenRequestIdFuzzTest(data, size);
    OHOS::AuthHandleLeaveLNNFuzzTest(data, size);
    OHOS::TryGetBrConnInfoFuzzTest(data, size);
    OHOS::AuthDeviceGetPreferConnInfoFuzzTest(data, size);
    OHOS::AuthDeviceGetConnInfoByTypeFuzzTest(data, size);
    OHOS::AuthDeviceGetP2pConnInfoFuzzTest(data, size);
    OHOS::AuthDeviceGetHmlConnInfoFuzzTest(data, size);
    OHOS::AuthDeviceCheckConnInfoFuzzTest(data, size);
    OHOS::AuthGetLatestAuthSeqListByTypeFuzzTest(data, size);
    OHOS::AuthGetLatestAuthSeqListFuzzTest(data, size);
    OHOS::GetHmlOrP2pAuthHandleFuzzTest(data, size);
    OHOS::AuthDeviceGetLatestIdByUuidFuzzTest(data, size);
    OHOS::AuthDeviceGetIdByConnInfoFuzzTest(data, size);
    OHOS::AuthDeviceGetIdByUuidFuzzTest(data, size);
    OHOS::AuthDeviceGetAuthHandleByIndexFuzzTest(data, size);
    OHOS::AuthGetEncryptSizeFuzzTest(data, size);
    OHOS::AuthGetDecryptSizeFuzzTest(data, size);
    OHOS::AuthDeviceSetP2pMacFuzzTest(data, size);
    OHOS::FindAuthManagerByUdidFuzzTest(data, size);
    OHOS::FindAuthManagerByConnIdFuzzTest(data, size);
    OHOS::DestroyAuthManagerListFuzzTest(data, size);
    OHOS::SetAuthConnIdFuzzTest(data, size);
    OHOS::SetAuthP2pMacFuzzTest(data, size);
    OHOS::RemoveAuthManagerByConnInfoFuzzTest(data, size);
    OHOS::GetAvailableAuthConnInfoByUuidFuzzTest(data, size);
    OHOS::GenerateUdidHashFuzzTest(data, size);
    OHOS::GetAuthManagerByConnInfoFuzzTest(data, size);
    OHOS::GetAuthIdByConnIdFuzzTest(data, size);
    OHOS::AuthSendKeepaliveOptionFuzzTest(data, size);
    OHOS::AuthFlushDeviceFuzzTest(data, size);
    OHOS::ProcessEmptySessionKeyFuzzTest(data, size);
    OHOS::HandleReconnectResultFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    int32_t ret = FuzzEnvInit(data, size);
    if (ret != 0) {
        return ret;
    }
    ProcessFuzzRequest(data, size);
    FuzzEnvDeinit();
    return 0;
}