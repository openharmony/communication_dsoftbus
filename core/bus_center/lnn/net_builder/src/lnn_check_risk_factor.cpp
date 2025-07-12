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

#include <json.hpp>
#include <map>
#include <string>

#include "lnn_log.h"
#include "safety_detect_manager.h"
#include "softbus_adapter_json.h"

extern "C" {
bool IsDeviceHasRiskFactor(void)
{
    JsonObj *paramObj = JSON_CreateObject();
    if (paramObj == nullptr) {
        return false;
    }
    const char *keys[] = {"efuse", "fastbootlock", "rootPackage", "processPrivilege"};
    for (const char *key : keys) {
        if (!JSON_AddStringToObject(paramObj, key, "")) {
            JSON_Delete(paramObj);
            return false;
        }
    }
    nlohmann::json *paramJson = reinterpret_cast<nlohmann::json *>(paramObj->context);
    std::string paramStr = paramJson->dump();
    std::string result;
    int32_t ret = OHOS::Security::SecurityAudit::SafetyDetectManager::
        GetInstance().CheckRiskFactorSync(paramStr, result);
    if (ret != 0) {
        JSON_Delete(paramObj);
        return false;
    }
    JsonObj *resultObj = JSON_Parse(result.c_str(), result.size());
    if (resultObj == nullptr) {
        JSON_Delete(paramObj);
        return false; 
    }
    std::map<std::string, std::string> riskResult;
    for (const char *key : keys) {
        char resultBuffer[100];
        std::string resultKey = std::string(key) + ".result";
        if (!JSON_GetStringFromObject(resultObj, resultKey.c_str(), resultBuffer, sizeof(resultBuffer))) {
            JSON_Delete(paramObj);
            JSON_Delete(resultObj);
            return false;
        }
        riskResult[key] = resultBuffer;
    }
    LNN_LOGI(LNN_BUILDER, "Risk Factor Results:");
    for (const char *key : keys) {
        LNN_LOGI(LNN_BUILDER, "%s: %s", key, riskResult[key].c_str());
    }
    JSON_Delete(paramObj);
    JSON_Delete(resultObj);
}
}