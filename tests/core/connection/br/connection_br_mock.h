/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CONNECTION_BR_MOCK_H
#define CONNECTION_BR_MOCK_H

#include <gmock/gmock.h>
#include <mutex>
#include "cJSON.h"

#include "disc_interface.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_config_type.h"
#include "softbus_conn_br_connection.h"

namespace OHOS {
class ConnectionBrInterface {
public:
    ConnectionBrInterface() {};
    virtual ~ConnectionBrInterface() {};
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int *target) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int num) = 0;
    virtual bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num) = 0;
};

class ConnectionBrInterfaceMock : public ConnectionBrInterface {
public:
    ConnectionBrInterfaceMock();
    ~ConnectionBrInterfaceMock() override;
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool (const cJSON *, const char * const, int *));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool (const cJSON *, const char * const, int64_t *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int));
    MOCK_METHOD3(AddNumber64ToJsonObject, bool (cJSON *, const char * const, int64_t));
};
} // namespace OHOS
#endif // CONNECTION_BR_MOCK_H
