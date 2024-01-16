/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "softbus_adapter_hiview.h"

#include <cstdlib>

#include "hiview.h"
#include "comm_log.h"
#include "parameter.h"
#include "securec.h"
#include "softbus_adapter_mem.h"

#define PROP_USER_TYPE            "ro.logsystem.usertype"
#define PROP_USER_TYPE_VALUE_LEN  8
#define PROP_USER_TYPE_CHANA_BETA 3

SoftBusLogSysType SoftBusGetLogSysType(void)
{
    static SoftBusLogSysType userType = SOFTBUS_LOG_SYS_UNKNOWN;
    static bool isUserTypeObtained = false;

    if (isUserTypeObtained) {
        return userType;
    }

    char value[PROP_USER_TYPE_VALUE_LEN] = { 0 };
    int32_t ret = GetParameter(PROP_USER_TYPE, "", value, sizeof(value));
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "GetProp fail. userType=%{public}s, ret=%{public}d", PROP_USER_TYPE, ret);
        return SOFTBUS_LOG_SYS_UNKNOWN;
    }
    isUserTypeObtained = true;
    COMM_LOGI(COMM_ADAPTER, "userType=%{public}s, value=%{public}s", PROP_USER_TYPE, value);

    // is beta or not: 1 china release, 3 china beta, 5 oversea beta, 6 oversea release
    if (atoi(value) == PROP_USER_TYPE_CHANA_BETA) {
        userType = SOFTBUS_LOG_SYS_BETA;
        return userType;
    }
    userType = SOFTBUS_LOG_SYS_RELEASE;
    return userType;
}

void SoftBusGenHiviewHash(const char *deviceId, char *buf, uint32_t size)
{
    if (deviceId == nullptr || buf == NULL || size < HiView::DEFAULT_TRUNCATED_LENGTH) {
        COMM_LOGE(COMM_ADAPTER, "invalid param");
        return;
    }
    std::string input(deviceId);
    std::string hash = HiView::GenTruncatedHash(input, HiView::ALGORITHM_SHA_256, HiView::DEFAULT_TRUNCATED_LENGTH);
    if (hash.empty()) {
        COMM_LOGE(COMM_ADAPTER, "HiView::genTruncatedHash return empty hash");
        return;
    }
    if (strcpy_s(buf, size, hash.c_str()) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "HiView::genTruncatedHash strcpy_s fail");
        return;
    }
}