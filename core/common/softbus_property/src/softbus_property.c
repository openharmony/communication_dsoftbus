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

#include "softbus_property.h"

#include "softbus_config.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

static cJSON *GetConfigText()
{
    cJSON *config = cJSON_Parse(SOFTBUS_CONFIG);
    if (config == NULL) {
        LOG_ERR("json parse failed. %s\n", cJSON_GetErrorPtr());
        return NULL;
    }
    return config;
}

int GetPropertyString(const char *string, char *target, size_t targetLen)
{
    if (string == NULL || target == NULL || targetLen == 0) {
        LOG_ERR("Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *config = GetConfigText();
    if (config == NULL) {
        LOG_ERR("Get config text failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    bool res = GetJsonObjectStringItem(config, string, target, targetLen);
    cJSON_Delete(config);
    if (!res) {
        LOG_ERR("Get config item with %s failed.", string);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int GetPropertyInt(const char *string, int *target)
{
    if (string == NULL || target == NULL) {
        LOG_ERR("Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *config = GetConfigText();
    if (config == NULL) {
        LOG_ERR("Get config text failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    bool res = GetJsonObjectNumberItem(config, string, target);
    cJSON_Delete(config);
    if (!res) {
        LOG_ERR("Get config item with %s failed.", string);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int GetPropertyDouble(const char *string, double *target)
{
    if (string == NULL || target == NULL) {
        LOG_ERR("Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *config = GetConfigText();
    if (config == NULL) {
        LOG_ERR("Get config text failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    bool res = GetJsonObjectDoubleItem(config, string, target);
    cJSON_Delete(config);
    if (!res) {
        LOG_ERR("Get config item with %s failed.", string);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int GetPropertyBool(const char *string, bool *target)
{
    if (string == NULL || target == NULL) {
        LOG_ERR("Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *config = GetConfigText();
    if (config == NULL) {
        LOG_ERR("Get config text failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    bool res = GetJsonObjectBoolItem(config, string, target);
    cJSON_Delete(config);
    if (!res) {
        LOG_ERR("Get config item with %s failed.", string);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}