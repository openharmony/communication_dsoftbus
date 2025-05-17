/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NAPI_SOFTBUS_LINK_ENHANCE_OBJECT_H_
#define NAPI_SOFTBUS_LINK_ENHANCE_OBJECT_H_

#include "napi_link_enhance_utils.h"

namespace Communication {
namespace OHOS::Softbus {

class NapiConnectionChangeState {
public:
    NapiConnectionChangeState(std::string &deviceId, bool success, int32_t reason)
        : deviceId_(deviceId), success_(success), reason_(reason) { }
    ~NapiConnectionChangeState() = default;

    napi_value ToNapiValue(napi_env env);

private:
    std::string deviceId_ = "";
    bool success_ = false;
    int32_t reason_ = -1;
};

} // namespace Softbus
} // namespace Communication
#endif /* NAPI_SOFTBUS_LINK_ENHANCE_OBJECT_H_ */