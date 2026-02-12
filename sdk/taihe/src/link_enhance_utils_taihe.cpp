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

#include "link_enhance_utils_taihe.h"
#include "taihe/runtime.hpp"
#include "napi_link_enhance_error_code.h"
#include "securec.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace Communication {
namespace OHOS::Softbus {
using namespace std;

static std::map<int32_t, std::string> taiheErrMsgMap {
    {LINK_ENHANCE_PERMISSION_DENIED, "Permission denied."},
    {LINK_ENHANCE_CONNECT_TIMEOUT, "Connect timeout."},
    {LINK_ENHANCE_CONNECT_PEER_NOT_START_SERVICE, "Peer server is not started."},
    {LINK_ENHANCE_SERVERS_EXCEEDS, "The number of servers exceeds the limit."},
    {LINK_ENHANCE_DUPLICATE_SERVER_NAME, "Duplicate server name."},
    {LINK_ENHANCE_CONNECTIONS_EXCEEDS, "The number of connection exceeds the limit."},
    {LINK_ENHANCE_CONNECTION_NOT_READY, "Connection is not ready."},
    {LINK_ENHANCE_PARAMETER_INVALID, "Invalid parameter."},
    {LINK_ENHANCE_INTERNAL_ERR, "Internal error."},
};
int32_t ConvertToJsErrcode(int32_t err)
{
    switch (err) {
        case SOFTBUS_ACCESS_TOKEN_DENIED:
            return LINK_ENHANCE_PERMISSION_DENIED;
        case SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX:
            return LINK_ENHANCE_CONNECTIONS_EXCEEDS;
        case SOFTBUS_CONN_GENERAL_CONNECT_TIMEOUT:
            return LINK_ENHANCE_CONNECT_TIMEOUT;
        case SOFTBUS_CONN_GENERAL_SERVER_NOT_OPENED:
            return LINK_ENHANCE_CONNECT_PEER_NOT_START_SERVICE;
        case SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER:
            return LINK_ENHANCE_DUPLICATE_SERVER_NAME;
        case SOFTBUS_CONN_GENERAL_CONNECTION_NOT_READY:
            return LINK_ENHANCE_CONNECTION_NOT_READY;
        case SOFTBUS_INVALID_PARAM:
            return LINK_ENHANCE_PARAMETER_INVALID;
        case SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX:
            return LINK_ENHANCE_SERVERS_EXCEEDS;
        default:
            return LINK_ENHANCE_INTERNAL_ERR;
    }
}

void ThrowException(int32_t err)
{
    COMM_LOGI(COMM_SDK, "error code is=%{public}d", err);
    bool flag = false;
    int32_t ret = ConvertToJsErrcode(err);
    auto it = taiheErrMsgMap.find(ret);
    if (it != taiheErrMsgMap.end()) {
        taihe::set_business_error(it->first, it->second);
    }
}

bool CheckAccessToken(void)
{
    bool isAccessToken = SoftBusCheckIsAccess();
    if (!isAccessToken) {
        COMM_LOGW(COMM_SDK, "no access token");
    }
    return isAccessToken;
}
} // namespace Softbus
} // namespace Communication