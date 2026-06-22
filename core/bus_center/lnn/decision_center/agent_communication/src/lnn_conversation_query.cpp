/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_conversation_query.h"

#include <dlfcn.h>
#include <future>
#include <mutex>
#include <securec.h>
#include <thread>

#include "ability_connect_callback_stub.h"
#include "anonymizer.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_ohos_account.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_compress.h"
#include "lnn_feature_capability_struct.h"
#include "common_list.h"
#include "g_enhance_lnn_func_pack.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "lnn_cloud_query_fragment.h"
#include "lnn_lane_interface_struct.h"
#include "lnn_log.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"
#include "system_ability_definition.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_device_cloud_convergence_struct.h"

#define CAPABILITY_ISACKMAG 0x01
#define CAPABILITY_ISCOMPRESS 0x02
#define MAX_CACHED_MSG_COUNT 500
#define CACHE_TIMEOUT_MS (10 * 60 * 1000)
#define HML_LINK_TIMEOUT_MS (5 * 60 * 1000)
#define ACK_TIMEOUT_MS (20 * 1000)
#define GET_EXTENSION_UPPER_LIMIT 100
#define MAX_TRUSTED_DEVICE_NUM 20
#define COMPARE_SUCCESS 0
#define COMPARE_FAILED 1
#ifdef __aarch64__
#define ABILITY_ADAPTER_PATH "/system/lib64/libability_adapter.z.so"
#else
#define ABILITY_ADAPTER_PATH "/system/lib/libability_adapter.z.so"
#endif

using namespace OHOS;
typedef int32_t (*StartAbilityWrapperFunc)(const char *bundleName, const char *abilityName);
typedef bool (*IsRunningProcessWrapperFunc)(const char *bundleName, int32_t userId);
typedef bool (*IsExtensionAbilityWrapperFunc)(const char *bundleName, const char *abilityName, int32_t upperLimit);

struct AbilityAdapterLoader {
    void *handle;
    StartAbilityWrapperFunc startAbility;
    IsRunningProcessWrapperFunc isRunningProcess;
    IsExtensionAbilityWrapperFunc isExtensionAbility;
};

typedef struct {
    uint32_t laneHandle;
    char networkId[NETWORK_ID_BUF_LEN];
} NearFieldChannelInfo;

typedef enum {
    CONVERSATION_FAR_FIELD_PUSH = 0,
    CONVERSATION_FAR_FIELD_P2P,
    CONVERSATION_NEAR_FIELD_WIFI_DIRECT,
    CONVERSATION_MAX,
} ConversationType;

typedef enum {
    TLV_TYPE_BUNDLE_NAME = 0,
    TLV_TYPE_ABILITY_NAME = 1,
    TLV_TYPE_ERROR_CODE = 2,
} TlvType;

typedef struct {
    char udid[UDID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];
    char *data;
    uint32_t length;
    uint64_t timestamp;
    ConversationType channel;
    ConversationBusiness info;
} CloudQueryMsgCache;

typedef struct {
    ConversationBusiness info;
} ConversationCbListItem;

typedef struct {
    const char *msg;
    uint32_t msgLen;
    bool isNeedCompress;
    const ConversationBusiness *info;
    bool isAckMsg;
    int32_t errCode;
} CloudQueryDataPack;

typedef struct {
    uint8_t *packData;
    uint32_t packLen;
} CloudMsgOutput;

typedef struct {
    bool isAckMsg;
    uint32_t ackMsgId;
    int32_t errCode;
} AckMsgInfo;

typedef struct {
    const char *actualMsg;
    uint32_t actualMsgLen;
    uint8_t *decompressData;
} UnPackDeCompressOutput;

typedef struct {
    CloudQueryDataPack *pack;
    bool *isNeedCompress;
    uint32_t *offset;
    uint16_t *optionLen;
} UnpackHeaderContext;

typedef struct {
    uint8_t **assembledData;
    uint32_t *assembledLen;
    uint32_t *msgId;
} FragmentAggregateResult;

typedef struct {
    const char *udid;
    const ConversationBusiness *info;
    const char *actualMsg;
    uint32_t actualMsgLen;
    ConversationType channel;
    uint32_t msgId;
} ProcessReceivedDataInput;

static std::mutex g_nearFieldChannelLock;
using NearFieldChannelVec = std::vector<NearFieldChannelInfo>;
static NearFieldChannelVec g_nearFieldChannelVec;

using ConversationCbListVec = std::vector<ConversationCbListItem>;
static ConversationCbListVec g_conversationCbListVec;
static std::mutex g_conversationCbLock;

using SendMsgCacheVec = std::vector<CloudQueryMsgCache>;
static SendMsgCacheVec g_sendMsgCacheVec;
static std::mutex g_sendMsgCacheLock;

using CloudQueryMsgCacheVec = std::vector<CloudQueryMsgCache>;
static CloudQueryMsgCacheVec g_recvMsgCacheVec;
static AbilityAdapterLoader g_adapterLoader = { 0 };
static std::mutex g_recvMsgCacheLock;

typedef struct {
    uint32_t msgId;
    char udid[UDID_BUF_LEN];
    ConversationBusiness info;
    uint64_t timestamp;
    std::promise<int32_t> promise;
    bool futureRetrieved;
} AckWaitItem;

static std::vector<AckWaitItem> g_ackWaitList;
static std::mutex g_ackWaitLock;

typedef struct {
    char udid[UDID_BUF_LEN];
    uint32_t lastMsgId;
} AntiReplayEntry;
static std::vector<AntiReplayEntry> g_antiReplayList;
static std::mutex g_antiReplayLock;

static bool IsSameAccount(int64_t accountId)
{
    int64_t localAccountId = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &localAccountId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get local accountId failed");
        return false;
    }
    if (localAccountId == accountId && !LnnIsDefaultOhosAccount()) {
        return true;
    }
    return false;
}

static int LnnLoadAbilityAdapter()
{
    std::lock_guard<std::mutex> lock(g_recvMsgCacheLock);
    if (g_adapterLoader.handle != nullptr) {
        LNN_LOGI(LNN_EVENT, "already opened");
        return SOFTBUS_OK;
    }
    void *handle = dlopen(ABILITY_ADAPTER_PATH, RTLD_LAZY);
    if (handle == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlopen failed");
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }

    g_adapterLoader.startAbility = (StartAbilityWrapperFunc)dlsym(handle, "StartAbility");
    g_adapterLoader.isRunningProcess = (IsRunningProcessWrapperFunc)dlsym(handle, "IsRunningProcess");
    g_adapterLoader.isExtensionAbility = (IsExtensionAbilityWrapperFunc)dlsym(handle, "IsExtensionAbility");
    if (g_adapterLoader.startAbility == nullptr || g_adapterLoader.isRunningProcess == nullptr ||
        g_adapterLoader.isExtensionAbility == nullptr) {
        g_adapterLoader.startAbility = nullptr;
        g_adapterLoader.isRunningProcess = nullptr;
        g_adapterLoader.isExtensionAbility = nullptr;
        g_adapterLoader.handle = nullptr;
        dlclose(handle);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }
    g_adapterLoader.handle = handle;
    return SOFTBUS_OK;
}

static bool IsRegisterListener(const ConversationBusiness *info)
{
    std::lock_guard<std::mutex> lock(g_conversationCbLock);
    for (const auto &item : g_conversationCbListVec) {
        if (strcmp(item.info.bundleName, info->bundleName) == 0 &&
            strcmp(item.info.abilityName, info->abilityName) == 0) {
            return true;
        }
    }
    char *anonyBundlename = nullptr;
    char *anonyAbilityname = nullptr;
    Anonymize(info->bundleName, &anonyBundlename);
    Anonymize(info->abilityName, &anonyAbilityname);
    LNN_LOGE(LNN_EVENT, "no register listener bundleName=%{public}s, abilityName=%{public}s",
        anonyBundlename, anonyAbilityname);
    AnonymizeFree(anonyBundlename);
    AnonymizeFree(anonyAbilityname);
    return false;
}

static bool IsProcExist(const ConversationBusiness *info)
{
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "info is nullptr");
        return false;
    }
    char *anonyBundlename = nullptr;
    char *anonyAbilityname = nullptr;
    Anonymize(info->bundleName, &anonyBundlename);
    Anonymize(info->abilityName, &anonyAbilityname);
    LNN_LOGI(LNN_EVENT, "find bundleName=%{public}s, abilityName=%{public}s",
        anonyBundlename, anonyAbilityname);
    AnonymizeFree(anonyBundlename);
    AnonymizeFree(anonyAbilityname);

    int32_t ret = LnnLoadAbilityAdapter();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "load sym failed. ret=%{public}d", ret);
        return false;
    }
    if (g_adapterLoader.isRunningProcess == nullptr) {
        LNN_LOGE(LNN_EVENT, "isRunningProcess is null");
        return false;
    }
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (!g_adapterLoader.isRunningProcess(info->bundleName, userId)) {
        LNN_LOGE(LNN_EVENT, "process not exist");
        return false;
    }

    if (g_adapterLoader.isExtensionAbility == nullptr) {
        LNN_LOGE(LNN_EVENT, "isExtensionAbility is null");
        return false;
    }
    if (!g_adapterLoader.isExtensionAbility(info->bundleName, info->abilityName, GET_EXTENSION_UPPER_LIMIT)) {
        LNN_LOGE(LNN_EVENT, "not extension ability");
        return false;
    }

    LNN_LOGI(LNN_EVENT, "proc exist");
    return true;
}

static void FreeCacheNodeWithoutLock(CloudQueryMsgCache *node)
{
    if (node == nullptr) {
        return;
    }
    if (node->data != nullptr) {
        SoftBusFree(node->data);
        node->data = nullptr;
    }
    SoftBusFree(node);
}

static void ClearAllCacheWithoutLock(void)
{
    int32_t count = 0;
    for (auto item = g_recvMsgCacheVec.begin(); item != g_recvMsgCacheVec.end();) {
        SoftBusFree(item->data);
        item = g_recvMsgCacheVec.erase(item);
        count++;
    }
    LNN_LOGI(LNN_EVENT, "clear all cache count=%{public}d", count);
    g_recvMsgCacheVec.clear();
}

static CloudQueryMsgCache *CreateCacheNodeWithoutLock(const char *udid, const char *data, uint32_t length,
    const ConversationBusiness *info, ConversationType channel)
{
    if (length == 0) {
        LNN_LOGE(LNN_EVENT, "invalid length=0");
        return nullptr;
    }
    const char *deviceId = nullptr;
    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnRetrieveDeviceInfoByUdidPacked(udid, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get retrieve node failed");
        ret = LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, &nodeInfo);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "use default deviceId");
        deviceId = udid;
    } else {
        deviceId = reinterpret_cast<const char *>(nodeInfo.networkId);
    }

    CloudQueryMsgCache *node = static_cast<CloudQueryMsgCache *>(SoftBusCalloc(sizeof(CloudQueryMsgCache)));
    if (node == nullptr) {
        LNN_LOGE(LNN_EVENT, "calloc cache node failed");
        return nullptr;
    }

    if (strcpy_s(node->udid, UDID_BUF_LEN, udid) != EOK ||
        strcpy_s(node->networkId, NETWORK_ID_BUF_LEN, deviceId) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy udid failed");
        FreeCacheNodeWithoutLock(node);
        return nullptr;
    }

    node->data = static_cast<char *>(SoftBusCalloc(length));
    if (node->data == nullptr) {
        LNN_LOGE(LNN_EVENT, "calloc data failed");
        FreeCacheNodeWithoutLock(node);
        return nullptr;
    }
    if (memcpy_s(node->data, length, data, length) != EOK ||
        strcpy_s(node->info.abilityName, ABILITY_NAME_LEN, info->abilityName) != EOK ||
        strcpy_s(node->info.bundleName, BUNDLE_NAME_LEN, info->bundleName) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy data failed");
        FreeCacheNodeWithoutLock(node);
        return nullptr;
    }

    node->length = length;
    node->channel = channel;
    node->timestamp = SoftBusGetTimeMs();

    return node;
}

static void ClearExpiredCacheWithoutLock(void)
{
    uint64_t currentTime = SoftBusGetTimeMs();
    int32_t timeoutCount = 0;

    for (auto item = g_recvMsgCacheVec.begin(); item != g_recvMsgCacheVec.end();) {
        if (currentTime - item->timestamp > CACHE_TIMEOUT_MS) {
            LNN_LOGI(LNN_EVENT, "cached msg timeout, len=%{public}u, channel=%{public}d", item->length, item->channel);
            SoftBusFree(item->data);
            item = g_recvMsgCacheVec.erase(item);
            timeoutCount++;
        } else {
            ++item;
        }
    }

    LNN_LOGI(LNN_EVENT, "process cached messages done, timeout=%{public}d, remaining=%{public}zu",
        timeoutCount, g_recvMsgCacheVec.size());
}

static CloudQueryMsgCache *DeepCopyCacheNode(const CloudQueryMsgCache *src)
{
    if (src == nullptr) {
        return nullptr;
    }

    CloudQueryMsgCache *dst = static_cast<CloudQueryMsgCache *>(SoftBusCalloc(sizeof(CloudQueryMsgCache)));
    if (dst == nullptr) {
        LNN_LOGE(LNN_EVENT, "calloc cache node failed");
        return nullptr;
    }

    if (memcpy_s(dst->udid, UDID_BUF_LEN, src->udid, strlen(src->udid)) != EOK ||
        memcpy_s(dst->networkId, NETWORK_ID_BUF_LEN, src->networkId, strlen(src->networkId)) != EOK ||
        memcpy_s(&dst->info, sizeof(ConversationBusiness), &src->info, sizeof(ConversationBusiness)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy cache node failed");
        SoftBusFree(dst);
        return nullptr;
    }

    dst->data = static_cast<char *>(SoftBusCalloc(src->length));
    if (dst->data == nullptr) {
        LNN_LOGE(LNN_EVENT, "calloc data failed");
        SoftBusFree(dst);
        return nullptr;
    }

    if (memcpy_s(dst->data, src->length, src->data, src->length) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy data failed");
        SoftBusFree(dst->data);
        SoftBusFree(dst);
        return nullptr;
    }

    dst->length = src->length;
    dst->timestamp = src->timestamp;
    dst->channel = src->channel;

    return dst;
}

static void FreeTempCacheVec(CloudQueryMsgCacheVec &tempVec)
{
    for (auto &item : tempVec) {
        if (item.data != nullptr) {
            SoftBusFree(item.data);
            item.data = nullptr;
        }
    }
    tempVec.clear();
}

static int32_t AddMsgToCache(const char *udid, const char *data, uint32_t length,
    const ConversationBusiness *info, ConversationType channel)
{
    std::lock_guard<std::mutex> lock(g_recvMsgCacheLock);

    if (g_recvMsgCacheVec.size() >= MAX_CACHED_MSG_COUNT) {
        LNN_LOGE(LNN_EVENT, "cache is full, count=%{public}zu", g_recvMsgCacheVec.size());
        ClearExpiredCacheWithoutLock();
    }

    CloudQueryMsgCache *node = CreateCacheNodeWithoutLock(udid, data, length, info, channel);
    if (node == nullptr) {
        LNN_LOGE(LNN_EVENT, "create cache node failed");
        return SOFTBUS_MALLOC_ERR;
    }
    g_recvMsgCacheVec.emplace_back(*node);
    SoftBusFree(node);

    LNN_LOGI(LNN_EVENT, "add msg to cache success, count=%{public}zu", g_recvMsgCacheVec.size());
    return SOFTBUS_OK;
}

static int32_t CalculateCloudQueryDataLength(const CloudQueryDataPack *pack,
    uint32_t *totalLen, uint16_t *optionLen)
{
    if (pack == nullptr || totalLen == nullptr || optionLen == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }

    uint16_t bundleNameLen = static_cast<uint16_t>(strnlen(pack->info->bundleName, BUNDLE_NAME_LEN));
    uint16_t abilityNameLen = static_cast<uint16_t>(strnlen(pack->info->abilityName, ABILITY_NAME_LEN));
    uint16_t bundleNameTlvLen = static_cast<uint16_t>(sizeof(uint8_t) + sizeof(uint16_t) + bundleNameLen);
    uint16_t abilityNameTlvLen = static_cast<uint16_t>(sizeof(uint8_t) + sizeof(uint16_t) + abilityNameLen);
    uint16_t errCodeTlvLen = static_cast<uint16_t>(sizeof(uint8_t) + sizeof(uint16_t) + sizeof(int32_t));
    *optionLen = bundleNameTlvLen + abilityNameTlvLen + errCodeTlvLen;
    *totalLen = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) +
        *optionLen + sizeof(uint16_t) + pack->msgLen;

    return SOFTBUS_OK;
}

static int32_t PackCloudQueryDataHeader(uint8_t *buf, uint32_t totalLen,
    uint16_t optionLen, const CloudQueryDataPack *pack)
{
    uint32_t offset = 0;
    uint8_t capability = 0;

    if (pack->isAckMsg) {
        capability |= CAPABILITY_ISACKMAG;
    }
    if (pack->isNeedCompress) {
        capability |= CAPABILITY_ISCOMPRESS;
    }

    buf[offset] = 0;
    offset += sizeof(uint8_t);
    buf[offset] = capability;
    offset += sizeof(uint8_t);
    *reinterpret_cast<uint16_t *>(buf + offset) = optionLen;
    offset += sizeof(uint16_t);

    return SOFTBUS_OK;
}

static int32_t PackCloudQueryDataTlv(uint8_t *buf, uint32_t totalLen, const CloudQueryDataPack *pack)
{
    uint32_t offset = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
    uint16_t bundleNameLen = static_cast<uint16_t>(strnlen(pack->info->bundleName, BUNDLE_NAME_LEN));
    uint16_t abilityNameLen = static_cast<uint16_t>(strnlen(pack->info->abilityName, ABILITY_NAME_LEN));
    if (bundleNameLen > 0) {
        buf[offset] = TLV_TYPE_BUNDLE_NAME;
        offset += sizeof(uint8_t);
        *reinterpret_cast<uint16_t *>(buf + offset) = bundleNameLen;
        offset += sizeof(uint16_t);
        if (memcpy_s(buf + offset, totalLen - offset,
            pack->info->bundleName, bundleNameLen) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy bundleName failed");
            return SOFTBUS_MEM_ERR;
        }
        offset += bundleNameLen;
    }
    if (abilityNameLen > 0) {
        buf[offset] = TLV_TYPE_ABILITY_NAME;
        offset += sizeof(uint8_t);
        *reinterpret_cast<uint16_t *>(buf + offset) = abilityNameLen;
        offset += sizeof(uint16_t);
        if (memcpy_s(buf + offset, totalLen - offset,
            pack->info->abilityName, abilityNameLen) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy abilityName failed");
            return SOFTBUS_MEM_ERR;
        }
        offset += abilityNameLen;
    }

    buf[offset] = TLV_TYPE_ERROR_CODE;
    offset += sizeof(uint8_t);
    *reinterpret_cast<uint16_t *>(buf + offset) = static_cast<uint16_t>(sizeof(int32_t));
    offset += sizeof(uint16_t);
    if (memcpy_s(buf + offset, totalLen - offset, &pack->errCode, sizeof(int32_t)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy errcode failed");
        return SOFTBUS_MEM_ERR;
    }
    offset += sizeof(int32_t);

    *reinterpret_cast<uint16_t *>(buf + offset) = static_cast<uint16_t>(pack->msgLen);
    offset += sizeof(uint16_t);

    if (pack->msgLen > 0 && memcpy_s(buf + offset, totalLen - offset, pack->msg, pack->msgLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy msg failed");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t PackCloudQueryData(uint8_t **buffer, uint32_t *bufferLen, const CloudQueryDataPack *pack)
{
    if (buffer == nullptr || bufferLen == nullptr || pack == nullptr || pack->info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t totalLen = 0;
    uint16_t optionLen = 0;

    int32_t ret = CalculateCloudQueryDataLength(pack, &totalLen, &optionLen);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    uint8_t *buf = static_cast<uint8_t *>(SoftBusCalloc(totalLen));
    if (buf == nullptr) {
        LNN_LOGE(LNN_EVENT, "alloc buffer failed");
        return SOFTBUS_MALLOC_ERR;
    }

    ret = PackCloudQueryDataHeader(buf, totalLen, optionLen, pack);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(buf);
        return ret;
    }

    ret = PackCloudQueryDataTlv(buf, totalLen, pack);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(buf);
        return ret;
    }

    *buffer = buf;
    *bufferLen = totalLen;
    return SOFTBUS_OK;
}

static int32_t UnpackCloudQueryHeader(const uint8_t *data, uint32_t length, UnpackHeaderContext *ctx)
{
    if (length < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t)) {
        LNN_LOGE(LNN_EVENT, "invalid length=%{public}u", length);
        return SOFTBUS_INVALID_PARAM;
    }

    *(ctx->offset) = 0;
    uint8_t version = data[*(ctx->offset)];
    *(ctx->offset) += sizeof(uint8_t);
    if (version != 0) {
        LNN_LOGE(LNN_EVENT, "unsupported version=%{public}u", version);
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t capability = data[*(ctx->offset)];
    *(ctx->offset) += sizeof(uint8_t);
    ctx->pack->isAckMsg = (capability & CAPABILITY_ISACKMAG) != 0;
    *(ctx->isNeedCompress) = (capability & CAPABILITY_ISCOMPRESS) != 0;

    *(ctx->optionLen) = *reinterpret_cast<const uint16_t *>(data + *(ctx->offset));
    *(ctx->offset) += sizeof(uint16_t);

    if (*(ctx->offset) > length || length - *(ctx->offset) < *(ctx->optionLen)) {
        LNN_LOGE(LNN_EVENT, "length insufficient, length=%{public}u, offset=%{public}u, optionLen=%{public}u",
            length, *(ctx->offset), *(ctx->optionLen));
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackTlvBundleName(const uint8_t *data, uint32_t length,
    CloudQueryDataPack *pack, uint32_t *offset)
{
    if (*offset + sizeof(uint8_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds, offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t type = data[*offset];
    *offset += sizeof(uint8_t);
    if (type != TLV_TYPE_BUNDLE_NAME) {
        LNN_LOGE(LNN_EVENT, "invalid bundleName type=%{public}u", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + sizeof(uint16_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for nameLen, offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint16_t nameLen = *reinterpret_cast<const uint16_t *>(data + *offset);
    *offset += sizeof(uint16_t);
    if (nameLen >= BUNDLE_NAME_LEN) {
        LNN_LOGE(LNN_EVENT, "bundleName too long, len=%{public}u, max=%{public}d",
            nameLen, BUNDLE_NAME_LEN - 1);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + nameLen > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for bundleName, "
            "offset=%{public}u, nameLen=%{public}u, length=%{public}u", *offset, nameLen, length);
        return SOFTBUS_INVALID_PARAM;
    }
    if (nameLen > 0) {
        if (memcpy_s(const_cast<char*>(pack->info->bundleName), BUNDLE_NAME_LEN, data + *offset, nameLen) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy bundleName failed");
            return SOFTBUS_MEM_ERR;
        }
        const_cast<char*>(pack->info->bundleName)[nameLen] = '\0';
        *offset += nameLen;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackTlvAbilityName(const uint8_t *data, uint32_t length,
    CloudQueryDataPack *pack, uint32_t *offset)
{
    if (*offset + sizeof(uint8_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds, offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t type = data[*offset];
    *offset += sizeof(uint8_t);
    if (type != TLV_TYPE_ABILITY_NAME) {
        LNN_LOGE(LNN_EVENT, "invalid abilityName type=%{public}u", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + sizeof(uint16_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for nameLen, offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint16_t nameLen = *reinterpret_cast<const uint16_t *>(data + *offset);
    *offset += sizeof(uint16_t);
    if (nameLen >= ABILITY_NAME_LEN) {
        LNN_LOGE(LNN_EVENT, "abilityName too long, len=%{public}u, max=%{public}d",
            nameLen, ABILITY_NAME_LEN - 1);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + nameLen > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for abilityName, "
            "offset=%{public}u, nameLen=%{public}u, length=%{public}u", *offset, nameLen, length);
        return SOFTBUS_INVALID_PARAM;
    }
    if (nameLen > 0) {
        if (memcpy_s(const_cast<char*>(pack->info->abilityName), ABILITY_NAME_LEN, data + *offset, nameLen) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy abilityName failed");
            return SOFTBUS_MEM_ERR;
        }
        const_cast<char*>(pack->info->abilityName)[nameLen] = '\0';
        *offset += nameLen;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackTlvErrorCode(const uint8_t *data, uint32_t length,
    CloudQueryDataPack *pack, uint32_t *offset)
{
    if (*offset + sizeof(uint8_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds, offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t type = data[*offset];
    *offset += sizeof(uint8_t);
    if (type != TLV_TYPE_ERROR_CODE) {
        LNN_LOGE(LNN_EVENT, "invalid errcode type=%{public}u", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + sizeof(uint16_t) > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for errCodeLen, "
            "offset=%{public}u, length=%{public}u", *offset, length);
        return SOFTBUS_INVALID_PARAM;
    }
    uint16_t errCodeLen = *reinterpret_cast<const uint16_t *>(data + *offset);
    *offset += sizeof(uint16_t);
    if (errCodeLen != sizeof(int32_t)) {
        LNN_LOGE(LNN_EVENT, "invalid errcode len=%{public}u", errCodeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    if (*offset + errCodeLen > length) {
        LNN_LOGE(LNN_EVENT, "offset out of bounds for errCode, "
            "offset=%{public}u, errCodeLen=%{public}u, length=%{public}u", *offset, errCodeLen, length);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t errCode = *reinterpret_cast<const int32_t *>(data + *offset);
    *offset += errCodeLen;
    pack->errCode = errCode;
    LNN_LOGI(LNN_EVENT, "unpack errCode=%{public}d", errCode);
    return SOFTBUS_OK;
}

static int32_t UnpackCloudQueryDataPayload(const uint8_t *data, uint32_t length,
    uint32_t offset, CloudQueryDataPack *pack)
{
    uint16_t dataLen = *reinterpret_cast<const uint16_t *>(data + offset);
    offset += sizeof(uint16_t);

    if (length < offset || length - offset < dataLen) {
        LNN_LOGE(LNN_EVENT, "data length insufficient, length=%{public}u, offset=%{public}u, dataLen=%{public}u",
            length, offset, dataLen);
        return SOFTBUS_INVALID_PARAM;
    }

    char *msgContent = static_cast<char *>(SoftBusCalloc(dataLen));
    if (msgContent == nullptr) {
        LNN_LOGE(LNN_EVENT, "calloc msg failed");
        return SOFTBUS_MALLOC_ERR;
    }

    if (dataLen > 0 && memcpy_s(msgContent, dataLen, data + offset, dataLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy msg failed");
        SoftBusFree(msgContent);
        return SOFTBUS_MEM_ERR;
    }

    pack->msg = msgContent;
    pack->msgLen = dataLen;
    return SOFTBUS_OK;
}

static int32_t UnpackTlvOptions(const uint8_t *data, uint32_t length, CloudQueryDataPack *pack,
    uint32_t *offset, uint16_t optionLen)
{
    uint32_t startOffset = *offset;
    if (optionLen > 0) {
        int32_t ret = UnpackTlvBundleName(data, length, pack, offset);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }

    if (optionLen > 0 && *offset - startOffset < optionLen) {
        int32_t ret = UnpackTlvAbilityName(data, length, pack, offset);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }

    if (optionLen > 0 && *offset - startOffset < optionLen) {
        int32_t ret = UnpackTlvErrorCode(data, length, pack, offset);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t UnpackCloudQueryData(const uint8_t *data, uint32_t length,
    CloudQueryDataPack *pack, bool *isNeedCompress)
{
    if (data == nullptr || pack == nullptr || pack->info == nullptr || isNeedCompress == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t offset = 0;
    uint16_t optionLen = 0;
    UnpackHeaderContext ctx = {pack, isNeedCompress, &offset, &optionLen};
    int32_t ret = UnpackCloudQueryHeader(data, length, &ctx);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    if (length < offset + optionLen + sizeof(uint16_t)) {
        LNN_LOGE(LNN_EVENT, "length insufficient for dataLen, "
            "length=%{public}u, offset=%{public}u, optionLen=%{public}u", length, offset, optionLen);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t dataOffset = offset + optionLen;
    ret = UnpackTlvOptions(data, length, pack, &offset, optionLen);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (pack->isAckMsg) {
        pack->msg = nullptr;
        pack->msgLen = 0;
        return SOFTBUS_OK;
    }
    ret = UnpackCloudQueryDataPayload(data, length, dataOffset, pack);
    return ret;
}

static int32_t DecompressCloudQueryData(CloudQueryDataPack *pack, bool isNeedCompress,
    const char **actualMsg, uint32_t *actualMsgLen, uint8_t **decompressData)
{
    if (isNeedCompress) {
        uint32_t decompressLen = 0;
        LNN_LOGI(LNN_EVENT, "before decompress, msgLen=%{public}u", pack->msgLen);
        int32_t ret = DataDecompress(reinterpret_cast<uint8_t *>(const_cast<char *>(pack->msg)),
            pack->msgLen, decompressData, &decompressLen);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "decompress cloud msg fail, ret=%{public}d", ret);
            return ret;
        }
        LNN_LOGI(LNN_EVENT, "after decompress, datalen=%{public}u", decompressLen);
        *actualMsg = reinterpret_cast<const char *>(*decompressData);
        *actualMsgLen = decompressLen;
    } else {
        *actualMsg = pack->msg;
        *actualMsgLen = pack->msgLen;
        *decompressData = nullptr;
    }
    return SOFTBUS_OK;
}

static int32_t AddAckWaitItem(uint32_t msgId, const char *udid, const ConversationBusiness *info)
{
    if (udid == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_ackWaitLock);
    for (auto &item : g_ackWaitList) {
        if (strcmp(item.udid, udid) == 0 &&
            strcmp(item.info.bundleName, info->bundleName) == 0 &&
            strcmp(item.info.abilityName, info->abilityName) == 0) {
            char *anonyUdid = nullptr;
            Anonymize(udid, &anonyUdid);
            LNN_LOGE(LNN_EVENT, "ack wait item already exists for udid=%{public}s", anonyUdid);
            AnonymizeFree(anonyUdid);
            return SOFTBUS_AGENT_BUSY;
        }
    }

    AckWaitItem item;
    item.msgId = msgId;
    item.timestamp = SoftBusGetSysTimeMs();
    item.futureRetrieved = false;
    if (strcpy_s(item.udid, UDID_BUF_LEN, udid) != EOK ||
        strcpy_s(item.info.bundleName, BUNDLE_NAME_LEN, info->bundleName) != EOK ||
        strcpy_s(item.info.abilityName, ABILITY_NAME_LEN, info->abilityName) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy ack wait item failed");
        return SOFTBUS_MEM_ERR;
    }
    g_ackWaitList.push_back(std::move(item));
    LNN_LOGI(LNN_EVENT, "add ack wait item, msgId=%{public}u", msgId);
    return SOFTBUS_OK;
}

static void RemoveAckWaitItem(uint32_t msgId, int32_t errCode)
{
    std::unique_lock<std::mutex> lock(g_ackWaitLock);
    for (auto it = g_ackWaitList.begin(); it != g_ackWaitList.end(); ++it) {
        if (it->msgId == msgId) {
            if (errCode != SOFTBUS_OK && it->futureRetrieved) {
                it->promise.set_value(errCode);
                it->futureRetrieved = true;
            }
            g_ackWaitList.erase(it);
            LNN_LOGI(LNN_EVENT, "remove ack wait item, msgId=%{public}u", msgId);
            return;
        }
    }
    LNN_LOGW(LNN_EVENT, "ack wait item not found, msgId=%{public}u", msgId);
}

static int32_t WaitForAck(uint32_t msgId, const ConversationBusiness *info)
{
    AckWaitItem *waitItem = nullptr;
    {
        std::unique_lock<std::mutex> lock(g_ackWaitLock);
        for (auto &item : g_ackWaitList) {
            if (item.msgId == msgId) {
                waitItem = &item;
                break;
            }
        }
    }

    int32_t ret = SOFTBUS_OK;
    if (waitItem != nullptr) {
        if (waitItem->futureRetrieved) {
            LNN_LOGE(LNN_EVENT, "future already retrieved, msgId=%{public}u", msgId);
            return SOFTBUS_INVALID_PARAM;
        }
        auto future = waitItem->promise.get_future();
        waitItem->futureRetrieved = true;
        std::chrono::milliseconds timeout(ACK_TIMEOUT_MS);

        if (future.wait_for(timeout) == std::future_status::timeout) {
            LNN_LOGE(LNN_EVENT, "wait ack timeout, msgId=%{public}u", msgId);
            RemoveAckWaitItem(msgId, SOFTBUS_TIMOUT);
            ret = SOFTBUS_TIMOUT;
        } else {
            ret = future.get();
            LNN_LOGI(LNN_EVENT, "ack received, msgId=%{public}u, ret=%{public}d", msgId, ret);
            RemoveAckWaitItem(msgId, SOFTBUS_OK);
        }
    } else {
        LNN_LOGE(LNN_EVENT, "wait item not found, msgId=%{public}u", msgId);
        ret = SOFTBUS_NOT_FIND;
    }

    return ret;
}

static void HandleAckReceived(uint32_t msgId, int32_t errCode)
{
    LNN_LOGI(LNN_EVENT, "handle ack received, msgId=%{public}u, errCode=%{public}d", msgId, errCode);
    std::unique_lock<std::mutex> lock(g_ackWaitLock);
    for (auto it = g_ackWaitList.begin(); it != g_ackWaitList.end(); ++it) {
        if (it->msgId == msgId) {
            it->promise.set_value(errCode);
            LNN_LOGI(LNN_EVENT, "ack signal sent, msgId=%{public}u, errCode=%{public}d", msgId, errCode);
            return;
        }
    }
    LNN_LOGW(LNN_EVENT, "ack wait item not found, msgId=%{public}u", msgId);
}

static int32_t UnPackAndDeCompressCloudMsg(const uint8_t *data, uint32_t length,
    CloudQueryDataPack *pack, UnPackDeCompressOutput *output)
{
    if (data == nullptr || pack == nullptr || pack->info == nullptr || output == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    bool isNeedCompress = false;
    int32_t ret = UnpackCloudQueryData(data, length, pack, &isNeedCompress);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "unpack data failed");
        return ret;
    }

    ret = DecompressCloudQueryData(pack, isNeedCompress, &output->actualMsg,
        &output->actualMsgLen, &output->decompressData);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "decompress data failed");
        SoftBusFree(const_cast<char*>(pack->msg));
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "unpack and decompress data done, len=%{public}u", output->actualMsgLen);
    return SOFTBUS_OK;
}

static int32_t PullUpHap(const ConversationBusiness *info)
{
    int32_t ret = LnnLoadAbilityAdapter();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_META_NODE, "load sym failed. ret=%{public}d", ret);
        return ret;
    }
    if (g_adapterLoader.startAbility == nullptr) {
        LNN_LOGE(LNN_EVENT, "startAbility func is null");
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }
    ret = g_adapterLoader.startAbility(info->bundleName, info->abilityName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "pull up hap failed. ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "pull up hap success.");
    return SOFTBUS_OK;
}

static int32_t TryAggregateFragment(const char *data, uint32_t length, FragmentAggregateResult *result)
{
    LNN_LOGI(LNN_EVENT, "try aggregate fragment message, dataLen=%{public}u", length);
    if (length < FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_BUILDER, "invalid data length, length=%{public}u", length);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = DataAggregate(reinterpret_cast<const uint8_t *>(data),
        length, result->assembledData, result->assembledLen, result->msgId);
    if (ret == SOFTBUS_OK && *(result->assembledData) != nullptr) {
        LNN_LOGI(LNN_EVENT, "aggregate success, assembledLen=%{public}u", *(result->assembledLen));
        return SOFTBUS_OK;
    }

    LNN_LOGI(LNN_EVENT, "aggregate not complete, ret=%{public}d, waiting for more fragments", ret);
    return SOFTBUS_DATA_NOT_ENOUGH;
}

static void ProcessCachedMessages(const ConversationBusiness *info)
{
    CloudQueryMsgCacheVec tempMsgVec;
    int32_t timeoutCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_recvMsgCacheLock);
        uint64_t currentTime = SoftBusGetTimeMs();
        for (auto item = g_recvMsgCacheVec.begin(); item != g_recvMsgCacheVec.end();) {
            if (currentTime - item->timestamp > CACHE_TIMEOUT_MS) {
                ++item;
                timeoutCount++;
                continue;
            }
            if (strcmp(item->info.bundleName, info->bundleName) == 0 &&
                strcmp(item->info.abilityName, info->abilityName) == 0) {
                CloudQueryMsgCache *copyNode = DeepCopyCacheNode(&(*item));
                if (copyNode != nullptr) {
                    tempMsgVec.push_back(*copyNode);
                    SoftBusFree(copyNode);
                }
            }
            ++item;
        }
    }

    int32_t processedCount = 0;
    for (auto &item : tempMsgVec) {
        OnConversationRecvMsg(&item.info, item.networkId,
            reinterpret_cast<const char *>(item.data), item.length);
        processedCount++;
    }

    FreeTempCacheVec(tempMsgVec);

    {
        std::lock_guard<std::mutex> lock(g_recvMsgCacheLock);
        ClearAllCacheWithoutLock();
    }

    LNN_LOGI(LNN_EVENT, "process cached messages done, processed=%{public}d, timeoutCount=%{public}d",
        processedCount, timeoutCount);
}

static bool IsSupportNearField(const NodeInfo *nodeInfo)
{
    if (!LnnGetOnlineStateById(nodeInfo->networkId, CATEGORY_NETWORK_ID)) {
        LNN_LOGE(LNN_EVENT, "device not online");
        return false;
    }
    if (!IsSameAccount(nodeInfo->accountId)) {
        LNN_LOGE(LNN_EVENT, "not same account or local dev");
        return false;
    }
    if (!IsFeatureSupport(nodeInfo->feature, BIT_SUPPORT_AGENT_COMMUNICATION)) {
        LNN_LOGE(LNN_EVENT, "peer not support agent communication");
        return false;
    }
    return true;
}

static bool IsSupportFarField(const NodeInfo *nodeInfo)
{
    if (!IsFeatureSupport(nodeInfo->feature, BIT_SUPPORT_AGENT_COMMUNICATION)) {
        LNN_LOGE(LNN_EVENT, "peer not support agent communication");
        return false;
    }
    if (!IsFeatureSupport(nodeInfo->feature, BIT_DEVICE_CLOUD_CONVERGENCE_CAPABILITY)) {
        LNN_LOGE(LNN_EVENT, "peer not support cloud convergence");
        return false;
    }
    return true;
}

static int32_t PackCloudQueryDataWithCompress(const char *msg, uint32_t msgLen,
    const ConversationBusiness *info, CloudMsgOutput *output, AckMsgInfo *ackInfo)
{
    uint8_t *compressData = nullptr;
    uint32_t compressLen = 0;
    LNN_LOGI(LNN_EVENT, "before compress, msgLen=%{public}u", msgLen);
    int32_t ret = DataCompress(reinterpret_cast<uint8_t *>(const_cast<char *>(msg)),
        msgLen, &compressData, &compressLen);
    bool isAckMsg = (ackInfo != nullptr) ? ackInfo->isAckMsg : false;
    int32_t errCode = isAckMsg ? ackInfo->errCode : SOFTBUS_OK;
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "compress cloud msg fail, ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "after compress, datalen=%{public}u", compressLen);
    CloudQueryDataPack pack = {
        .msg = reinterpret_cast<char *>(compressData),
        .msgLen = compressLen,
        .isNeedCompress = true,
        .info = info,
        .isAckMsg = isAckMsg,
        .errCode = errCode,
    };
    ret = PackCloudQueryData(&output->packData, &output->packLen, &pack);
    SoftBusFree(compressData);
    return ret;
}

static int32_t PackCloudQueryDataWithoutCompress(const char *msg, uint32_t msgLen,
    const ConversationBusiness *info, CloudMsgOutput *output, AckMsgInfo *ackInfo)
{
    bool isAckMsg = (ackInfo != nullptr) ? ackInfo->isAckMsg : false;
    int32_t errCode = isAckMsg ? ackInfo->errCode : SOFTBUS_OK;
    CloudQueryDataPack pack = {
        .msg = msg,
        .msgLen = msgLen,
        .isNeedCompress = false,
        .info = info,
        .isAckMsg = isAckMsg,
        .errCode = errCode,
    };
    return PackCloudQueryData(&output->packData, &output->packLen, &pack);
}

static int32_t PackAndCompressCloudMsg(const char *msg, uint32_t msgLen,
    const ConversationBusiness *info, CloudMsgOutput *output, AckMsgInfo *ackInfo = nullptr)
{
    if (info == nullptr || output == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    output->packData = nullptr;
    output->packLen = 0;

    bool isNeedCompress = (msgLen > MAX_SLICE_LEN) ? true : false;

    int32_t ret = SOFTBUS_OK;
    if (isNeedCompress) {
        ret = PackCloudQueryDataWithCompress(msg, msgLen, info, output, ackInfo);
    } else {
        ret = PackCloudQueryDataWithoutCompress(msg, msgLen, info, output, ackInfo);
    }

    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "pack cloud info failed");
    }
    return ret;
}

static int32_t GetMsgId(bool isAckMsg, uint32_t ackMsgId, uint32_t *msgId,
    const char *udid, const ConversationBusiness *info)
{
    if (isAckMsg) {
        *msgId = ackMsgId;
        return SOFTBUS_OK;
    }
    std::unique_lock<std::mutex> lock(g_ackWaitLock);
    for (auto &item : g_ackWaitList) {
        if (strcmp(item.udid, udid) == 0 &&
            strcmp(item.info.bundleName, info->bundleName) == 0 &&
            strcmp(item.info.abilityName, info->abilityName) == 0) {
            *msgId = item.msgId;
            return SOFTBUS_OK;
        }
    }
    char *anonyUdid = nullptr;
    Anonymize(udid, &anonyUdid);
    LNN_LOGE(LNN_EVENT, "ack wait item not exists for udid=%{public}s", anonyUdid);
    AnonymizeFree(anonyUdid);
    return SOFTBUS_NOT_FIND;
}

static int32_t LnnSendCtrlMsgByFarField(const char *msg, uint32_t msgLen, const char *udid,
    const ConversationBusiness *info, AckMsgInfo *ackInfo = nullptr)
{
    if (udid == nullptr || info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    bool isAckMsg = (ackInfo != nullptr) ? ackInfo->isAckMsg : false;
    uint32_t ackMsgId = (ackInfo != nullptr) ? ackInfo->ackMsgId : 0;

    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (userId != PRIMARY_USER_ID && !isAckMsg) {
        LNN_LOGE(LNN_BUILDER, "not primary user, not supported to send far field msg");
        return SOFTBUS_SOURCE_IS_NOT_PRIMARY_USER;
    }

    if (!isAckMsg && (msg == nullptr || msgLen == 0 || msgLen > COMMUNICATION_DATA_MAX_LEN)) {
        LNN_LOGE(LNN_EVENT, "invalid param, msgLen=%{public}u", msgLen);
        return SOFTBUS_INVALID_PARAM;
    }

    CloudMsgOutput output = {nullptr, 0};
    int32_t ret = PackAndCompressCloudMsg(msg, msgLen, info, &output, ackInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    uint32_t msgId = 0;
    ret = GetMsgId(isAckMsg, ackMsgId, &msgId, udid, info);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(output.packData);
        return ret;
    }

    ret = DataSlice(output.packData, output.packLen, MAX_SLICE_LEN, udid, msgId);
    SoftBusFree(output.packData);

    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "DataSlice failed, ret=%{public}d", ret);
        return ret;
    }

    LNN_LOGI(LNN_EVENT, "send far field msg done, ret=%{public}d, isAck=%{public}d",
        ret, isAckMsg);
    return ret;
}

static uint64_t GetDeviceTimestamp(const char *networkId, NodeInfo *basicInfo, int32_t basicInfoNum)
{
    for (int32_t k = 0; k < basicInfoNum; ++k) {
        if (strcmp(basicInfo[k].networkId, networkId) == 0) {
            return basicInfo[k].lastCommTimestamp;
        }
    }
    return 0;
}

static uint64_t CalcTimeDiff(uint64_t timestamp, uint64_t currentTime)
{
    return (currentTime > timestamp) ? (currentTime - timestamp) : 0;
}

static bool CompareDeviceForSort(const DeviceNodeInfo *keyNode, const DeviceNodeInfo *nodeJ,
    uint64_t diffJ, uint64_t keyDiff)
{
    if (keyNode->nearby && !nodeJ->nearby) {
        return true;
    }
    if (!keyNode->nearby && nodeJ->nearby) {
        return false;
    }
    if (!keyNode->nearby && !nodeJ->nearby) {
        return diffJ > keyDiff;
    }
    return false;
}

static void SortInfoArrayByTimestamp(NodeInfo *basicInfo, int32_t basicInfoNum,
    DeviceNodeInfo *infoArray, int32_t count)
{
    uint64_t currentTime = SoftBusGetCalendarTime();

    for (int32_t i = 1; i < count; ++i) {
        DeviceNodeInfo keyNode = infoArray[i];
        uint64_t keyTimestamp = GetDeviceTimestamp(keyNode.networkId, basicInfo, basicInfoNum);
        uint64_t keyDiff = CalcTimeDiff(keyTimestamp, currentTime);

        int32_t j = i - 1;
        while (j >= 0) {
            DeviceNodeInfo nodeJ = infoArray[j];
            uint64_t timestampJ = GetDeviceTimestamp(nodeJ.networkId, basicInfo, basicInfoNum);
            uint64_t diffJ = CalcTimeDiff(timestampJ, currentTime);
            bool shouldMove = CompareDeviceForSort(&keyNode, &nodeJ, diffJ, keyDiff);
            if (shouldMove) {
                infoArray[j + 1] = infoArray[j];
                j--;
            } else {
                break;
            }
        }
        infoArray[j + 1] = keyNode;
    }
}

static bool IsLocalDeviceInfo(const char *udid)
{
    if (udid == nullptr) {
        LNN_LOGE(LNN_LANE, "SH invalid param");
        return false;
    }
    NodeInfo info;
    if (memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "SH memset_s failed");
        return false;
    }
    if (LnnGetLocalNodeInfoSafe(&info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "SH get local info failed");
        return false;
    }
    if (strcmp(udid, info.deviceInfo.deviceUdid) == EOK) {
        return true;
    }
    return false;
}

static int32_t CollectCloudDevices(NodeInfo *basicInfo, int32_t basicInfoNum,
    DeviceNodeInfo *infoArray, int32_t *index)
{
    int32_t count = 0;
    for (int32_t i = 0; i < basicInfoNum; ++i) {
        char *anonyNetworkId = nullptr;
        Anonymize(basicInfo[i].networkId, &anonyNetworkId);
        if (!IsFeatureSupport(basicInfo[i].feature, BIT_SUPPORT_AGENT_COMMUNICATION)) {
            LNN_LOGE(LNN_EVENT, "conversation not support, networkid=%{public}s, feature=%{public}" PRIu64,
            anonyNetworkId, basicInfo[i].feature);
            AnonymizeFree(anonyNetworkId);
            continue;
        }
        if (!IsSameAccount(basicInfo[i].accountId) || IsLocalDeviceInfo(basicInfo[i].deviceInfo.deviceUdid)) {
            LNN_LOGE(LNN_EVENT, "not same account or local dev, networkid=%{public}s", anonyNetworkId);
            AnonymizeFree(anonyNetworkId);
            continue;
        }

        bool isDuplicate = false;
        for (int32_t j = 0; j < count; ++j) {
            if (strcmp(infoArray[j].networkId, basicInfo[i].networkId) == 0) {
                LNN_LOGE(LNN_EVENT, "duplicate device found, networkid=%{public}s, skip", anonyNetworkId);
                isDuplicate = true;
                break;
            }
        }
        if (isDuplicate) {
            AnonymizeFree(anonyNetworkId);
            continue;
        }
        LNN_LOGI(LNN_EVENT, "get device, networkid=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        if (strcpy_s(infoArray[count].deviceName, DEVICE_NAME_BUF_LEN, basicInfo[i].deviceInfo.deviceName) != EOK ||
            strcpy_s(infoArray[count].networkId, NETWORK_ID_BUF_LEN, basicInfo[i].networkId) != EOK ||
            strcpy_s(infoArray[count].udid, UDID_BUF_LEN, basicInfo[i].deviceInfo.deviceUdid) != EOK) {
            LNN_LOGE(LNN_EVENT, "string copy for networkId or device name or deviceUdid failed");
            continue;
        }
        infoArray[count].deviceTypeId = basicInfo[i].deviceInfo.deviceTypeId;
        infoArray[count].nearby = LnnGetOnlineStateById(basicInfo[i].networkId, CATEGORY_NETWORK_ID);
        count++;
    }
    *index = count;
    return SOFTBUS_OK;
}

static int32_t ReallocateDeviceInfoArray(const DeviceNodeInfo *infoArray,
    DeviceNodeInfo **actualArray, int32_t actualCount)
{
    if (actualCount == 0) {
        *actualArray = nullptr;
        return SOFTBUS_OK;
    }

    *actualArray = static_cast<DeviceNodeInfo *>(SoftBusCalloc(sizeof(DeviceNodeInfo) * actualCount));
    if (*actualArray == nullptr) {
        LNN_LOGE(LNN_EVENT, "realloc failed");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(*actualArray, sizeof(DeviceNodeInfo) * actualCount, infoArray,
        sizeof(DeviceNodeInfo) * actualCount) != EOK) {
        SoftBusFree(*actualArray);
        *actualArray = nullptr;
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetTrustedDevices(DeviceNodeInfo **info, int32_t *nums)
{
    if (info == nullptr || nums == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t basicInfoNum = 0;
    NodeInfo *basicInfo = nullptr;
    int32_t ret = LnnGetAllRemoteDevInfoPacked(&basicInfo, &basicInfoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get all remote dev info failed");
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "get all remote dev num=%{public}d", basicInfoNum);

    DeviceNodeInfo *infoArray = static_cast<DeviceNodeInfo *>(SoftBusCalloc(sizeof(DeviceNodeInfo) * basicInfoNum));
    if (infoArray == nullptr) {
        SoftBusFree(basicInfo);
        LNN_LOGE(LNN_EVENT, "malloc failed");
        return SOFTBUS_MEM_ERR;
    }

    int32_t actualCount = 0;
    ret = CollectCloudDevices(basicInfo, basicInfoNum, infoArray, &actualCount);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(basicInfo);
        SoftBusFree(infoArray);
        return ret;
    }

    if (actualCount > 1) {
        SortInfoArrayByTimestamp(basicInfo, basicInfoNum, infoArray, actualCount);
    }
    actualCount = (actualCount > MAX_TRUSTED_DEVICE_NUM) ? MAX_TRUSTED_DEVICE_NUM : actualCount;

    DeviceNodeInfo *actualArray = nullptr;
    ret = ReallocateDeviceInfoArray(infoArray, &actualArray, actualCount);
    SoftBusFree(basicInfo);
    SoftBusFree(infoArray);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    *info = actualArray;
    *nums = actualCount;
    LNN_LOGI(LNN_EVENT, "get cloud dev num=%{public}d", actualCount);
    return SOFTBUS_OK;
}

int32_t LnnRegisterConversationListener(const ConversationBusiness *info)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    {
        std::unique_lock<std::mutex> lock(g_conversationCbLock);

        for (const auto &item : g_conversationCbListVec) {
            if (strcmp(item.info.bundleName, info->bundleName) == 0 &&
                strcmp(item.info.abilityName, info->abilityName) == 0) {
                LNN_LOGE(LNN_EVENT, "conversation listener already exist");
                if (!g_recvMsgCacheVec.empty()) {
                    LNN_LOGI(LNN_EVENT, "process cached messages, count=%{public}zu", g_recvMsgCacheVec.size());
                    lock.unlock();
                    ProcessCachedMessages(info);
                }
                return SOFTBUS_OK;
            }
        }

        ConversationCbListItem newItem;
        if (strcpy_s(newItem.info.bundleName, BUNDLE_NAME_LEN, info->bundleName) != EOK ||
            strcpy_s(newItem.info.abilityName, ABILITY_NAME_LEN, info->abilityName) != EOK) {
            LNN_LOGE(LNN_EVENT, "cpy info failed");
            return SOFTBUS_STRCPY_ERR;
        }

        g_conversationCbListVec.push_back(newItem);
        char *anonyBundlename = nullptr;
        char *anonyAbilityname = nullptr;
        Anonymize(info->bundleName, &anonyBundlename);
        Anonymize(info->abilityName, &anonyAbilityname);
        LNN_LOGI(LNN_EVENT, "register success, bundleName=%{public}s, abilityName=%{public}s",
            anonyBundlename, anonyAbilityname);
        AnonymizeFree(anonyBundlename);
        AnonymizeFree(anonyAbilityname);
    }

    if (!g_recvMsgCacheVec.empty()) {
        LNN_LOGI(LNN_EVENT, "process cached messages, count=%{public}zu", g_recvMsgCacheVec.size());
        ProcessCachedMessages(info);
    }
    return SOFTBUS_OK;
}

void LnnUnregisterConversationListener(const ConversationBusiness *info)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid para");
        return;
    }

    std::lock_guard<std::mutex> lock(g_conversationCbLock);

    if (g_conversationCbListVec.empty()) {
        LNN_LOGI(LNN_EVENT, "g_conversationCbListVec is empty");
        return;
    }
    char *anonyBundlename = nullptr;
    char *anonyAbilityname = nullptr;
    Anonymize(info->bundleName, &anonyBundlename);
    Anonymize(info->abilityName, &anonyAbilityname);

    bool found = false;
    for (auto it = g_conversationCbListVec.begin(); it != g_conversationCbListVec.end();) {
        if (strcmp(it->info.bundleName, info->bundleName) == 0 &&
            strcmp(it->info.abilityName, info->abilityName) == 0) {
            it = g_conversationCbListVec.erase(it);
            found = true;
            LNN_LOGI(LNN_EVENT, "remove listener success, abilityName=%{public}s, bundleName=%{public}s",
                anonyAbilityname, anonyBundlename);
        } else {
            ++it;
        }
    }

    if (!found) {
        LNN_LOGE(LNN_EVENT, "remove listener failed, abilityName=%{public}s, bundleName=%{public}s",
            anonyAbilityname, anonyBundlename);
    }
    AnonymizeFree(anonyBundlename);
    AnonymizeFree(anonyAbilityname);
}

static void HandleHmlLinkTimeout(const void *para)
{
    if (para == nullptr) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    const char *networkId = static_cast<const char *>(para);

    DestroyNearFieldChannel(networkId);
}

static int32_t RemoveMessageHmlLinkTimeOutCustom(const void *obj, void *param)
{
    if (obj == nullptr || param == nullptr) {
        return COMPARE_FAILED;
    }
    if (static_cast<const char *>(obj) == static_cast<const char *>(param)) {
        return COMPARE_SUCCESS;
    }
    return COMPARE_FAILED;
}

static int32_t CreateFragmentDataForNearField(uint32_t msgId, CloudMsgOutput *output,
    uint8_t **fragmentData, uint32_t *totalLen)
{
    *totalLen = FRAGMENT_HEADER_LEN + output->packLen;
    *fragmentData = reinterpret_cast<uint8_t *>(SoftBusCalloc(*totalLen));
    if (*fragmentData == nullptr) {
        LNN_LOGE(LNN_LANE, "alloc fragment data failed");
        return SOFTBUS_MALLOC_ERR;
    }

    DataFragmentInfo header = {msgId, output->packLen, 0, output->packLen};
    WriteFragmentHeader(*fragmentData, *totalLen, &header);
    if (memcpy_s(*fragmentData + FRAGMENT_HEADER_LEN, *totalLen - FRAGMENT_HEADER_LEN,
        output->packData, output->packLen) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy_s failed");
        SoftBusFree(*fragmentData);
        *fragmentData = nullptr;
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SendNearFieldFragmentData(const char *networkId, AuthHandle authHandle,
    const uint8_t *fragmentData, uint32_t totalLen)
{
    AuthTransData dataInfo = {
        .module = MODULE_AGENT_COMMUNICATION,
        .flag = 0,
        .seq = 0,
        .len = totalLen,
        .data = fragmentData,
    };
    int32_t ret = AuthPostTransData(authHandle, &dataInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "AuthPostTransData failed, ret=%{public}d", ret);
        return ret;
    }

    LNN_LOGI(LNN_LANE, "SendNearFieldMsg done. ret=%{public}d", ret);
    RemoveLnnCloudEventPacked(MSG_TYPE_HML_TIMEOUT, RemoveMessageHmlLinkTimeOutCustom, const_cast<char *>(networkId));
    PostLnnCloudEventPacked(MSG_TYPE_HML_TIMEOUT, HandleHmlLinkTimeout, networkId,
        NETWORK_ID_BUF_LEN, HML_LINK_TIMEOUT_MS);
    return ret;
}

static int32_t SendNearFieldMsg(const char *msg, uint32_t msgLen, const char *networkId,
    const ConversationBusiness *info, AckMsgInfo *ackInfo = nullptr)
{
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK ||
        LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }

    bool isAckMsg = (ackInfo != nullptr) ? ackInfo->isAckMsg : false;
    uint32_t ackMsgId = (ackInfo != nullptr) ? ackInfo->ackMsgId : 0;

    LNN_LOGI(LNN_LANE, "isAck=%{public}s, ackMsgId=%{public}u", isAckMsg ? "true" : "false", ackMsgId);
    AuthHandle authHandle = { 0 };
    AuthDeviceGetLatestIdByUuid(uuid, AUTH_LINK_TYPE_ENHANCED_P2P, &authHandle);
    if (authHandle.authId == AUTH_INVALID_ID) {
        LNN_LOGI(LNN_LANE, "find authHandle fail, authId=%{public}" PRId64, authHandle.authId);
        return SOFTBUS_INVALID_PARAM;
    }

    CloudMsgOutput output = {nullptr, 0};
    int32_t ret = PackAndCompressCloudMsg(msg, msgLen, info, &output, ackInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    uint32_t msgId = 0;
    ret = GetMsgId(isAckMsg, ackMsgId, &msgId, udid, info);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(output.packData);
        return ret;
    }

    uint8_t *fragmentData = nullptr;
    uint32_t totalLen = 0;
    ret = CreateFragmentDataForNearField(msgId, &output, &fragmentData, &totalLen);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(output.packData);
        return ret;
    }
    SoftBusFree(output.packData);

    ret = SendNearFieldFragmentData(networkId, authHandle, fragmentData, totalLen);
    SoftBusFree(fragmentData);

    if (ret != SOFTBUS_OK) {
        return ret;
    }

    LNN_LOGI(LNN_LANE, "send msg done, isAck=%{public}d, msgId=%{public}u, ret=%{public}d", isAckMsg, msgId, ret);
    return ret;
}

static int32_t AddNearFieldChannelNode(const char *networkId, uint32_t laneHandle)
{
    if (networkId == nullptr || laneHandle == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_EVENT, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    NearFieldChannelInfo newItem;
    (void)memset_s(&newItem, sizeof(NearFieldChannelInfo), 0, sizeof(NearFieldChannelInfo));
    if (strcpy_s(newItem.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_EVENT, "strcpy_s networkId failed");
        return SOFTBUS_STRCPY_ERR;
    }
    newItem.laneHandle = laneHandle;
    std::unique_lock<std::mutex> lock(g_nearFieldChannelLock);
    g_nearFieldChannelVec.push_back(newItem);
    return SOFTBUS_OK;
}

static void DelNearFieldChannelNodeByLaneHandle(uint32_t laneHandle)
{
    std::unique_lock<std::mutex> lock(g_nearFieldChannelLock);
    LNN_LOGI(LNN_EVENT, "del near field channel node, laneHandle=%{public}u", laneHandle);
    for (auto it = g_nearFieldChannelVec.begin(); it != g_nearFieldChannelVec.end(); ++it) {
        if (it->laneHandle == laneHandle) {
            g_nearFieldChannelVec.erase(it);
            return;
        }
    }
    LNN_LOGE(LNN_EVENT, "not found, laneHandle=%{public}u", laneHandle);
}

static int32_t GetNearFieldNetworkIdByLaneHandle(uint32_t laneHandle, char *networkId)
{
    std::unique_lock<std::mutex> lock(g_nearFieldChannelLock);
    LNN_LOGI(LNN_EVENT, "get near field channel node, laneHandle=%{public}u", laneHandle);
    for (const auto &item : g_nearFieldChannelVec) {
        if (item.laneHandle == laneHandle) {
            if (memcpy_s(networkId, NETWORK_ID_BUF_LEN, item.networkId, NETWORK_ID_BUF_LEN) != EOK) {
                LNN_LOGE(LNN_EVENT, "memcpy failed");
                return SOFTBUS_MEM_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    LNN_LOGE(LNN_EVENT, "not found");
    return SOFTBUS_NOT_FIND;
}

static bool CheckAndSendPrimaryUserAck(const ProcessReceivedDataInput *input)
{
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (userId != PRIMARY_USER_ID && input->channel != CONVERSATION_NEAR_FIELD_WIFI_DIRECT) {
        AckMsgInfo ackInfo = {true, input->msgId, SOFTBUS_SINK_IS_NOT_PRIMARY_USER};
        int32_t sendRet = LnnSendCtrlMsgByFarField("", 0, input->udid, input->info, &ackInfo);
        LNN_LOGI(LNN_EVENT, "send ack done, msgId=%{public}u, errCode=%{public}d, sendRet=%{public}d",
            input->msgId, SOFTBUS_SOURCE_IS_NOT_PRIMARY_USER, sendRet);
        return true;
    }
    return false;
}

static const char *GetDeviceIdByUdid(const char *udid, NodeInfo *nodeInfo)
{
    int32_t ret = LnnRetrieveDeviceInfoByUdidPacked(udid, nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get retrieve node failed");
        ret = LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, nodeInfo);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "use default deviceId");
        return udid;
    }
    return reinterpret_cast<const char *>(nodeInfo->networkId);
}

static bool IsReplayMessage(const char *udid, uint32_t msgId)
{
    if (udid == nullptr) {
        return false;
    }
    std::unique_lock<std::mutex> lock(g_antiReplayLock);
    for (auto &item : g_antiReplayList) {
        if (strcmp(item.udid, udid) == 0 && item.lastMsgId == msgId) {
            char *anonyUdid = nullptr;
            Anonymize(udid, &anonyUdid);
            LNN_LOGI(LNN_EVENT, "del send mag cache, udid=%{public}s", AnonymizeWrapper(anonyUdid));
            AnonymizeFree(anonyUdid);
            return true;
        }
    }
    return false;
}

static void UpdateAntiReplayList(const char *udid, uint32_t msgId)
{
    if (udid == nullptr) {
        return;
    }
    std::unique_lock<std::mutex> lock(g_antiReplayLock);
    for (auto &item : g_antiReplayList) {
        if (strcmp(item.udid, udid) == 0) {
            item.lastMsgId = msgId;
            return;
        }
    }
    if (g_antiReplayList.size() > MAX_TRUSTED_DEVICE_NUM) {
        g_antiReplayList.erase(g_antiReplayList.begin());
    }
    AntiReplayEntry entry;
    (void)memset_s(&entry, sizeof(AntiReplayEntry), 0, sizeof(AntiReplayEntry));
    if (strcpy_s(entry.udid, UDID_BUF_LEN, udid) == EOK) {
        entry.lastMsgId = msgId;
        g_antiReplayList.push_back(entry);
    }
}

static int32_t ProcessReceivedCloudQueryData(const ProcessReceivedDataInput *input)
{
    if (input->actualMsg == nullptr || input->actualMsgLen == 0) {
        LNN_LOGI(LNN_EVENT, "received ack message or empty message");
        return SOFTBUS_OK;
    }
    if (IsReplayMessage(input->udid, input->msgId)) {
        return SOFTBUS_OK;
    }
    UpdateAntiReplayList(input->udid, input->msgId);
    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *deviceId = GetDeviceIdByUdid(input->udid, &nodeInfo);
    int32_t ret = SOFTBUS_OK;

    if (CheckAndSendPrimaryUserAck(input)) {
        return SOFTBUS_OK;
    }

    if (!IsProcExist(input->info)) {
        ret = AddMsgToCache(input->udid, input->actualMsg, input->actualMsgLen,
            input->info, input->channel);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "add msg to cache failed, ret=%{public}d", ret);
        }
        ret = PullUpHap(input->info);
    } else if (!IsRegisterListener(input->info)) {
        ret = AddMsgToCache(input->udid, input->actualMsg, input->actualMsgLen,
            input->info, input->channel);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "add msg to cache failed, ret=%{public}d", ret);
        }
    } else {
        OnConversationRecvMsg(input->info, deviceId, input->actualMsg, input->actualMsgLen);
    }

    if (input->channel == CONVERSATION_NEAR_FIELD_WIFI_DIRECT) {
        AckMsgInfo ackInfo = {true, input->msgId, ret};
        int32_t sendRet = SendNearFieldMsg("", 0, nodeInfo.networkId, input->info, &ackInfo);
        LNN_LOGI(LNN_EVENT, "send ack done, msgId=%{public}u, errCode=%{public}d, sendRet=%{public}d",
            input->msgId, ret, sendRet);
    } else {
        AckMsgInfo ackInfo = {true, input->msgId, ret};
        int32_t sendRet = LnnSendCtrlMsgByFarField("", 0, input->udid, input->info, &ackInfo);
        LNN_LOGI(LNN_EVENT, "send ack done, msgId=%{public}u, errCode=%{public}d, sendRet=%{public}d",
            input->msgId, ret, sendRet);
    }

    return ret;
}

void OnRecvCloudQueryInfo(const char *udid, const char *data, uint32_t length)
{
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;

    FragmentAggregateResult result = {&assembledData, &assembledLen, &msgId};
    int32_t ret = TryAggregateFragment(data, length, &result);
    if (ret != SOFTBUS_OK) {
        return;
    }

    ConversationBusiness info;
    (void)memset_s(&info, sizeof(ConversationBusiness), 0, sizeof(ConversationBusiness));
    CloudQueryDataPack pack = {nullptr, 0, false, &info};
    UnPackDeCompressOutput output = {nullptr, 0, nullptr};

    if (UnPackAndDeCompressCloudMsg(reinterpret_cast<const uint8_t *>(assembledData),
        assembledLen, &pack, &output) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "unpack and decompress data failed");
        if (assembledData != nullptr) {
            SoftBusFree(assembledData);
        }
        return;
    }

    if (pack.isAckMsg) {
        LNN_LOGI(LNN_EVENT, "received ack message, msgId=%{public}u, errCode=%{public}d", msgId, pack.errCode);
        HandleAckReceived(msgId, pack.errCode);
    } else {
        ProcessReceivedDataInput input = {udid, &info, output.actualMsg, output.actualMsgLen,
            CONVERSATION_FAR_FIELD_PUSH, msgId};
        ProcessReceivedCloudQueryData(&input);
    }

    if (assembledData != nullptr) {
        SoftBusFree(assembledData);
    }
    if (output.decompressData != nullptr) {
        SoftBusFree(output.decompressData);
    }
    SoftBusFree(const_cast<char*>(pack.msg));
}

static int32_t GetNearFieldLaneHandleByNetworkId(const char *networkId, uint32_t *laneHandle)
{
    std::unique_lock<std::mutex> lock(g_nearFieldChannelLock);
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    for (const auto &item : g_nearFieldChannelVec) {
        if (strcmp(item.networkId, networkId) == 0) {
            *laneHandle = item.laneHandle;
            LNN_LOGI(LNN_EVENT, "get near field channel node, networkId=%{public}s", anonyNetworkId);
            AnonymizeFree(anonyNetworkId);
            return SOFTBUS_OK;
        }
    }
    LNN_LOGE(LNN_EVENT, "not found, networkId=%{public}s", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    return SOFTBUS_NOT_FIND;
}

static int32_t AddSendMsgCache(const char *networkId, const char *msg, uint32_t msgLen,
    const ConversationBusiness *info)
{
    if (networkId == nullptr || msg == nullptr || msgLen == 0 || info == nullptr) {
        LNN_LOGE(LNN_EVENT, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    CloudQueryMsgCache *newItem = static_cast<CloudQueryMsgCache *>(SoftBusCalloc(sizeof(CloudQueryMsgCache)));
    if (newItem == nullptr) {
        LNN_LOGE(LNN_EVENT, "send msg cache calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    newItem->data = static_cast<char *>(SoftBusCalloc(msgLen));
    if (newItem->data == nullptr) {
        LNN_LOGE(LNN_EVENT, "send msg data calloc failed");
        SoftBusFree(newItem);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(newItem->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK ||
        memcpy_s(newItem->data, msgLen, msg, msgLen) != EOK ||
        strcpy_s(newItem->info.abilityName, ABILITY_NAME_LEN, info->abilityName) != EOK ||
        strcpy_s(newItem->info.bundleName, BUNDLE_NAME_LEN, info->bundleName) != EOK) {
        LNN_LOGE(LNN_EVENT, "strcpy_s or memcpy_s failed");
        SoftBusFree(newItem->data);
        SoftBusFree(newItem);
        return SOFTBUS_MEM_ERR;
    }
    newItem->length = msgLen;
    newItem->channel = CONVERSATION_NEAR_FIELD_WIFI_DIRECT;
    newItem->timestamp = SoftBusGetSysTimeMs();
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "add send msg cache success, networkId=%{public}s, len=%{public}u", anonyNetworkId, msgLen);
    AnonymizeFree(anonyNetworkId);

    std::unique_lock<std::mutex> lock(g_sendMsgCacheLock);
    g_sendMsgCacheVec.push_back(*newItem);
    SoftBusFree(newItem);
    return SOFTBUS_OK;
}

static void DelSendMsgCacheByNetworkId(const char *networkId)
{
    if (networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "param invalid");
        return;
    }
    std::unique_lock<std::mutex> lock(g_sendMsgCacheLock);
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    for (auto it = g_sendMsgCacheVec.begin(); it != g_sendMsgCacheVec.end();) {
        if (strcmp(it->networkId, networkId) == 0) {
            SoftBusFree(it->data);
            it = g_sendMsgCacheVec.erase(it);
            LNN_LOGI(LNN_EVENT, "del send msg cache, networkId=%{public}s", anonyNetworkId);
            continue;
        } else {
            ++it;
        }
    }
    LNN_LOGE(LNN_EVENT, "not found, networkId=%{public}s", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
}

typedef struct {
    char *data;
    uint32_t length;
    char networkId[NETWORK_ID_BUF_LEN];
    ConversationBusiness info;
} CachedMsgToSend;

static std::vector<CachedMsgToSend> ExtractCachedMessagesToSend(const char *networkId, ConversationType channel)
{
    std::vector<CachedMsgToSend> msgsToSend;

    std::unique_lock<std::mutex> lock(g_sendMsgCacheLock);
    for (auto it = g_sendMsgCacheVec.begin(); it != g_sendMsgCacheVec.end();) {
        if (it->channel != channel) {
            ++it;
            continue;
        }

        LNN_LOGI(LNN_EVENT, "found cached msg, will send it, len=%{public}u", it->length);
        CachedMsgToSend msgToSend;
        msgToSend.data = static_cast<char *>(SoftBusCalloc(it->length));
        if (msgToSend.data == nullptr) {
            LNN_LOGE(LNN_EVENT, "calloc msg data failed");
            ++it;
            continue;
        }
        if (memcpy_s(msgToSend.data, it->length, it->data, it->length) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy msg data failed");
            SoftBusFree(msgToSend.data);
            ++it;
            continue;
        }
        msgToSend.length = it->length;
        if (strcpy_s(msgToSend.networkId, NETWORK_ID_BUF_LEN, it->networkId) != EOK) {
            LNN_LOGE(LNN_EVENT, "networkId memcpy_s failed");
            SoftBusFree(msgToSend.data);
            ++it;
            continue;
        }
        msgToSend.info = it->info;
        msgsToSend.push_back(msgToSend);
        SoftBusFree(it->data);
        it = g_sendMsgCacheVec.erase(it);
    }

    return msgsToSend;
}

static int32_t GetDeviceNodeInfo(const char *deviceId, NodeInfo *nodeInfo)
{
    if (LnnRetrieveDeviceInfoByNetworkIdPacked(deviceId, nodeInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "get retrieve node by networkId success");
        return SOFTBUS_OK;
    }
    if (LnnRetrieveDeviceInfoByUdidPacked(deviceId, nodeInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "get retrieve node by udid success");
        return SOFTBUS_OK;
    }
    if (LnnGetRemoteNodeInfoById(deviceId, CATEGORY_NETWORK_ID, nodeInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "get remote node by networkId success");
        return SOFTBUS_OK;
    }
    if (LnnGetRemoteNodeInfoById(deviceId, CATEGORY_UDID, nodeInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "get remote node by udid success");
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *connInfo)
{
    LNN_LOGI(LNN_EVENT, "near field lane alloc success, laneHandle=%{public}u", laneHandle);
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = GetNearFieldNetworkIdByLaneHandle(laneHandle, networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get near field channel node failed");
        return;
    }

    std::vector<CachedMsgToSend> msgsToSend =
        ExtractCachedMessagesToSend(networkId, CONVERSATION_NEAR_FIELD_WIFI_DIRECT);

    for (const auto &msg : msgsToSend) {
        int32_t sendRet = SendNearFieldMsg(msg.data, msg.length, msg.networkId, &msg.info, nullptr);
        LNN_LOGI(LNN_EVENT, "send cached msg done, ret=%{public}d", sendRet);
        SoftBusFree(msg.data);
    }
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "send cached msg count=%{public}zu, networkId=%{public}s",
        msgsToSend.size(), anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    PostLnnCloudEventPacked(MSG_TYPE_HML_TIMEOUT, HandleHmlLinkTimeout,
        networkId, NETWORK_ID_BUF_LEN, HML_LINK_TIMEOUT_MS);
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t reason)
{
    LNN_LOGE(LNN_EVENT, "near field lane alloc fail, laneHandle=%{public}u, reason=%{public}d", laneHandle, reason);
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = GetNearFieldNetworkIdByLaneHandle(laneHandle, networkId);
    if (ret == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "near field lane alloc fail, try far field");

        std::vector<CachedMsgToSend> msgsToSend =
            ExtractCachedMessagesToSend(networkId, CONVERSATION_NEAR_FIELD_WIFI_DIRECT);

        for (const auto &msg : msgsToSend) {
            NodeInfo nodeInfo;
            ret = GetDeviceNodeInfo(msg.networkId, &nodeInfo);
            if (ret != SOFTBUS_OK) {
                SoftBusFree(msg.data);
                continue;
            }
            int32_t sendRet = LnnSendCtrlMsgByFarField(msg.data, msg.length,
                nodeInfo.deviceInfo.deviceUdid, &msg.info, nullptr);
            LNN_LOGI(LNN_EVENT, "send cached msg done, ret=%{public}d", sendRet);
            SoftBusFree(msg.data);
        }
        LNN_LOGI(LNN_EVENT, "send cached msg count=%{public}zu", msgsToSend.size());
    }
    DelNearFieldChannelNodeByLaneHandle(laneHandle);
}

static void OnNearFieldDisconnected(AuthHandle authHandle)
{
    LNN_LOGI(LNN_EVENT, "near field disconnected, authId=%{public}" PRId64, authHandle.authId);
    if (authHandle.type != AUTH_LINK_TYPE_ENHANCED_P2P) {
        LNN_LOGI(LNN_CLOCK, "auth type is not enhance p2p! do nothing");
        return;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == nullptr) {
        LNN_LOGE(LNN_EVENT, "auth is nullptr");
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUdid(auth->udid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId failed");
        DelDupAuthManager(auth);
        return;
    }
    DelDupAuthManager(auth);
    uint32_t laneHandle = 0;
    if (GetNearFieldLaneHandleByNetworkId(networkId, &laneHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get near field channel node failed");
        return;
    }
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "destroy near field channel, laneHandle=%{public}u, networkId=%{public}s",
        laneHandle, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    DelNearFieldChannelNodeByLaneHandle(laneHandle);
}

static bool ValidateNearFieldDataRecvParams(const AuthTransData *data, AuthHandle authHandle)
{
    if (data == nullptr || data->data == nullptr || data->len < FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_EVENT, "invalid param.");
        return false;
    }
    if (data->module != MODULE_AGENT_COMMUNICATION || authHandle.type != AUTH_LINK_TYPE_ENHANCED_P2P) {
        LNN_LOGE(LNN_EVENT, "other auth channel data recv");
        return false;
    }
    return true;
}

static bool ParseAndValidateFragmentHeader(const AuthTransData *data, DataFragmentInfo *header)
{
    int32_t parseRet = ParseFragmentHeader(reinterpret_cast<const uint8_t *>(data->data), data->len, header);
    if (parseRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "parse fragment header failed, ret=%{public}d", parseRet);
        return false;
    }

    LNN_LOGI(LNN_EVENT, "FragmentHeader: msgId=%{public}u, size=%{public}u, offset=%{public}u, total=%{public}u",
        header->msgId, header->size, header->offset, header->total);

    if (header->size != data->len - FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_EVENT, "fragment data length mismatch, header size=%{public}u, actual=%{public}u",
            header->size, data->len - FRAGMENT_HEADER_LEN);
        return false;
    }
    return true;
}

static void ProcessNearFieldReceivedData(AuthManager *auth, const AuthTransData *data,
    const DataFragmentInfo *header)
{
    const uint8_t *actualData = reinterpret_cast<const uint8_t *>(data->data) + FRAGMENT_HEADER_LEN;
    uint32_t actualDataLen = data->len - FRAGMENT_HEADER_LEN;

    ConversationBusiness info;
    (void)memset_s(&info, sizeof(ConversationBusiness), 0, sizeof(ConversationBusiness));
    CloudQueryDataPack pack = {nullptr, 0, false, &info};
    UnPackDeCompressOutput output = {nullptr, 0, nullptr};

    if (UnPackAndDeCompressCloudMsg(actualData, actualDataLen, &pack, &output) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "unpack and decompress data failed");
        return;
    }

    if (pack.isAckMsg) {
        LNN_LOGI(LNN_EVENT, "received ack message, msgId=%{public}u", header->msgId);
        HandleAckReceived(header->msgId, pack.errCode);
    } else {
        ProcessReceivedDataInput input = {auth->udid, &info, output.actualMsg,
            output.actualMsgLen, CONVERSATION_NEAR_FIELD_WIFI_DIRECT, header->msgId};
        int32_t ret = ProcessReceivedCloudQueryData(&input);
        LNN_LOGI(LNN_EVENT, "process received messages done, ret=%{public}d", ret);
    }

    if (output.decompressData != nullptr) {
        SoftBusFree(output.decompressData);
    }
    SoftBusFree(const_cast<char*>(pack.msg));
}

static void OnNearFieldDataRecv(AuthHandle authHandle, const AuthTransData *data)
{
    LNN_LOGI(LNN_EVENT, "Enter");
    if (!ValidateNearFieldDataRecvParams(data, authHandle)) {
        return;
    }
    LNN_LOGI(LNN_EVENT, "module=%{public}d, seq=%{public}" PRId64 ", len=%{public}u",
        data->module, data->seq, data->len);

    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == nullptr) {
        LNN_LOGE(LNN_EVENT, "auth is nullptr");
        return;
    }

    DataFragmentInfo header = { 0 };
    if (!ParseAndValidateFragmentHeader(data, &header)) {
        DelDupAuthManager(auth);
        return;
    }

    ProcessNearFieldReceivedData(auth, data, &header);
    DelDupAuthManager(auth);
}

int32_t InitConversationQuery(void)
{
    LNN_LOGI(LNN_EVENT, "regist near field listener");
    AuthTransListener listener = {
        .onDataReceived = OnNearFieldDataRecv,
        .onDisconnected = OnNearFieldDisconnected,
    };
    DataFragmentInit();
    return RegAuthTransListener(MODULE_AGENT_COMMUNICATION, &listener);
}

void DeinitConversationQuery(void)
{
    (void)UnregAuthTransListener(MODULE_AGENT_COMMUNICATION);
    LNN_LOGI(LNN_EVENT, "unreg conversation sync looper success");
}

int32_t CreateNearFieldChannel(const char *networkId)
{
    if (GetLaneManager() == nullptr || GetLaneManager()->lnnGetLaneHandle == nullptr ||
        GetLaneManager()->lnnFreeLane == nullptr || GetLaneManager()->lnnAllocTargetLane == nullptr) {
        LNN_LOGE(LNN_EVENT, "get lane manager failed");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_TRANS);
    if (AddNearFieldChannelNode(networkId, laneHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "add near field channel node failed");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_ADD_LIST_ERR;
    }
    LaneAllocInfoExt allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfoExt), 0, sizeof(LaneAllocInfoExt));
    if (strcpy_s(allocInfo.commInfo.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_EVENT, "networkId memcpy_s failed");
        DelNearFieldChannelNodeByLaneHandle(laneHandle);
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_STRCPY_ERR;
    }
    allocInfo.linkList.linkTypeNum = 1;
    allocInfo.linkList.linkType[0] = LANE_HML;
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.commInfo.transType = LANE_T_MSG;
    allocInfo.commInfo.isVirtualLink = false;
    LaneAllocListener listener;
    listener.onLaneAllocSuccess = OnLaneAllocSuccess;
    listener.onLaneAllocFail = OnLaneAllocFail;
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "near field channel alloc lane, laneHandle=%{public}u, networkId=%{public}s",
        laneHandle, AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    if (GetLaneManager()->lnnAllocTargetLane(laneHandle, &allocInfo, &listener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "near field channel alloc lane failed");
        DelNearFieldChannelNodeByLaneHandle(laneHandle);
        /* no need to free laneHandle when alloc lane failed*/
        return SOFTBUS_AUTH_ALLOC_LANE_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t DestroyNearFieldChannel(const char *networkId)
{
    if (networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle = 0;
    if (GetNearFieldLaneHandleByNetworkId(networkId, &laneHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get near field channel node failed");
        return SOFTBUS_NOT_FIND;
    }
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "destroy near field channel, laneHandle=%{public}u, networkId=%{public}s",
        laneHandle, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    DelNearFieldChannelNodeByLaneHandle(laneHandle);
    if (GetLaneManager() == nullptr || GetLaneManager()->lnnFreeLane == nullptr) {
        LNN_LOGE(LNN_EVENT, "get lane manager failed");
        return SOFTBUS_INVALID_PARAM;
    }
    GetLaneManager()->lnnFreeLane(laneHandle);
    return SOFTBUS_OK;
}

static int32_t LnnSendCtrlMsgByNearField(const char *msg, uint32_t msgLen, const char *networkId,
    const ConversationBusiness *info)
{
    if (msg == nullptr || networkId == nullptr || info == nullptr || msgLen > COMMUNICATION_DATA_MAX_LEN) {
        LNN_LOGE(LNN_EVENT, "invalid param, msgLen=%{public}u", msgLen);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle = 0;
    int32_t ret = GetNearFieldLaneHandleByNetworkId(networkId, &laneHandle);
    if (ret == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "exist hml channel, send the message directly.");
        ret = SendNearFieldMsg(msg, msgLen, networkId, info, nullptr);
        return ret;
    }
    ret = AddSendMsgCache(networkId, msg, msgLen, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "add send msg cache failed");
        return ret;
    }
    ret = CreateNearFieldChannel(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "create near field channel failed");
        DelSendMsgCacheByNetworkId(networkId);
        return ret;
    }
    LNN_LOGI(LNN_EVENT, "create near field channel success, wait for lane alloc callback");
    return ret;
}

static bool IsLocalDeviceId(const char *deviceId)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalNodeInfoSafe(&info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info failed");
        return false;
    }
    if (strcmp(deviceId, info.deviceInfo.deviceUdid) == 0 || strcmp(deviceId, info.networkId) == 0) {
        return true;
    }
    return false;
}

int32_t LnnPostConversationData(const char *deviceId, const ConversationBusiness *info, const char *data, uint32_t len)
{
    if (data == nullptr || deviceId == nullptr || info == nullptr || len == 0 || len > COMMUNICATION_DATA_MAX_LEN ||
        IsLocalDeviceId(deviceId)) {
        LNN_LOGE(LNN_EVENT, "invalid param, len=%{public}u", len);
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyDeviceId = nullptr;
    Anonymize(deviceId, &anonyDeviceId);
    LNN_LOGI(LNN_EVENT, "post agent data, deviceId=%{public}s, datalen=%{public}u",
        AnonymizeWrapper(anonyDeviceId), len);
    AnonymizeFree(anonyDeviceId);
    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = GetDeviceNodeInfo(deviceId, &nodeInfo);
    uint32_t msgId = GenerateMsgId();
    if (msgId == 0) {
        LNN_LOGE(LNN_EVENT, "generate msgId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ret == SOFTBUS_OK) {
        ret = AddAckWaitItem(msgId, nodeInfo.deviceInfo.deviceUdid, info);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
        ret = SOFTBUS_NETWORK_NOT_SUPPORT;
        if (IsSupportNearField(&nodeInfo)) {
            ret = LnnSendCtrlMsgByNearField(data, len, nodeInfo.networkId, info);
            LNN_LOGI(LNN_EVENT, "send by near field ret=%{public}d", ret);
        }
        if (ret != SOFTBUS_OK && IsSupportFarField(&nodeInfo)) {
            ret = LnnSendCtrlMsgByFarField(data, len, nodeInfo.deviceInfo.deviceUdid, info);
            LNN_LOGI(LNN_EVENT, "send by far field ret=%{public}d", ret);
        }
    } else {
        ret = AddAckWaitItem(msgId, deviceId, info);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
        LNN_LOGI(LNN_EVENT, "device not found, just try send far field");
        ret = LnnSendCtrlMsgByFarField(data, len, deviceId, info);
    }

    if (ret != SOFTBUS_OK) {
        RemoveAckWaitItem(msgId, ret);
        return ret;
    }
    ret = WaitForAck(msgId, info);
    return ret;
}
