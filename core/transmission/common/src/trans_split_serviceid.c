/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "string.h"

#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_split_serviceid.h"

#define TARGET        "serviceId"
#define TARGET_LENGTH 9
#define STR_SIZE_MAX  31
#define DEC           10

bool SplitToGetServiceId(const char *str, int64_t *serviceId)
{
    if (str == NULL || strlen(str) > STR_SIZE_MAX) {
        return false;
    }
 
    const char *underscore = strchr(str, '_');
    if (underscore == NULL) {
        return false;
    }
    const char *substring = underscore + 1;
    char *endptr;
    errno = 0;
    *serviceId = (int64_t)strtoll(substring, &endptr, DEC);
    if ((*serviceId == INT64_MAX || *serviceId == INT64_MIN) && errno == ERANGE) {
        return false;
    }

    if (endptr == substring || *endptr != '\0') {
        return false;
    }
    return true;
}

bool CheckNameContainServiceId(const char *str)
{
    if (str == NULL || strlen(str) > STR_SIZE_MAX) {
        return false;
    }

    const char *underscore = strchr(str, '_');
    if (underscore == NULL) {
        return false;
    }
    size_t length = underscore - str;
    if (length != TARGET_LENGTH) {
        return false;
    }
    return strncmp(str, TARGET, TARGET_LENGTH) == 0;
}