/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "agent_communication_utils_taihe.h"

#include <map>
#include <algorithm>
#include "accesstoken_kit.h"
#include "access_token.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "comm_log.h"
#include "napi_agent_communication_error_code.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "taihe/runtime.hpp"

namespace Communication {
namespace OHOS::Softbus {

static std::map<int32_t, std::string> taiheErrMsgMap {
    {CONVERSATION_PERMISSION_ERR, "Permission denied."},
    {CONVERSATION_PERMISSION_SYSTEMAPI_ERR, "Permission denied. A non-system application calls a system API."},
    {CONVERSATION_INVALID_PARAM, "Invalid argument."},
    {CONVERSATION_INTERNAL_ERR, "Internal error."},
    {CONVERSATION_INTERNAL_REMOTE_NOT_SUPPORT, "Remote not support."},
    {CONVERSATION_DUPLICATE_CALLS, "Duplicate calls, previous call still in progress."},
    {CONVERSATION_SEND_DATA_FAILED, "Send data failed."},
    {CONVERSATION_WAIT_ACK_TIMEOUT, "Wait remote ack timeout."},
};

int32_t ConvertToJsErrcode(int32_t err)
{
    switch (err) {
        case SOFTBUS_OK:
            return CONVERSATION_OK;
        case SOFTBUS_INVALID_PARAM:
            return CONVERSATION_INVALID_PARAM;
        case SOFTBUS_PERMISSION_DENIED:
            return CONVERSATION_PERMISSION_ERR;
        case SOFTBUS_NETWORK_NOT_SUPPORT:
            return CONVERSATION_INTERNAL_REMOTE_NOT_SUPPORT;
        case SOFTBUS_AGENT_BUSY:
            return CONVERSATION_DUPLICATE_CALLS;
        case SOFTBUS_CLOUD_SEND_FAIL:
            return CONVERSATION_SEND_DATA_FAILED;
        case SOFTBUS_TIMOUT:
            return CONVERSATION_WAIT_ACK_TIMEOUT;
        default:
            return CONVERSATION_INTERNAL_ERR;
    }
}

void ThrowBusinessException(int32_t err)
{
    if (err == CONVERSATION_OK) {
        return;
    }
    COMM_LOGI(COMM_SDK, "business error code=%{public}d", err);
    auto it = taiheErrMsgMap.find(err);
    if (it != taiheErrMsgMap.end()) {
        taihe::set_business_error(err, it->second);
    }
}

bool IsSystemApp(void)
{
    uint64_t tokenId = ::OHOS::IPCSkeleton::GetSelfTokenID();
    return ::OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

bool CheckPermission(void)
{
    uint32_t tokenId = ::OHOS::IPCSkeleton::GetCallingTokenID();
    if (::OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, OHOS_PERMISSION_SEC_ACCESS_UDID) != ::OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        COMM_LOGE(COMM_SDK, "permission %{public}s denied.", OHOS_PERMISSION_SEC_ACCESS_UDID);
        return false;
    }
    if (::OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, OHOS_PERMISSION_DISTRIBUTED_DATASYNC) != ::OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        COMM_LOGE(COMM_SDK, "permission %{public}s denied.", OHOS_PERMISSION_DISTRIBUTED_DATASYNC);
        return false;
    }
    return true;
}

void FillConversationBusiness(ConversationBusiness &business, const std::string &bundleName,
    const std::string &abilityName)
{
    business = {};
    const size_t bundleLen = std::min(bundleName.size(), sizeof(business.bundleName) - 1);
    std::copy_n(bundleName.c_str(), bundleLen, business.bundleName);
    const size_t abilityLen = std::min(abilityName.size(), sizeof(business.abilityName) - 1);
    std::copy_n(abilityName.c_str(), abilityLen, business.abilityName);
}

} // namespace Softbus
} // namespace Communication
