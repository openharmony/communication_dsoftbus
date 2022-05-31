/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef SOFTBUS_OPTIMIZATION_FILE_TEST_ENTERY_H
#define SOFTBUS_OPTIMIZATION_FILE_TEST_ENTERY_H

#include <string>
#include <unordered_map>

const std::string FILE_TEST_PKG_NAME = "com.huawei.plrdtest.dsoftbus";
const std::string FILE_TEST_PKG_NAME_DEMO = "com.huawei.plrdtest.dsoftbus1";
const std::string FILE_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.JtSendFile_10";
const std::string FILE_SESSION_NAME_DEMO = "com.huawei.plrdtest.dsoftbus.JtSendFile_demo";

enum TEST_SIDE {
    PASSIVE_OPENSESSION_WAY = 0,
    ACTIVE_OPENSESSION_WAY,
    ACTIVE_ANOTHER_OPENSESSION_WAY
};

struct SoftbusTestEntry {
    int testSide_;
    bool isTestWithPhone_;
    int aliveTime_;
    int transNums_;
    int pressureNums_;
};

const SoftbusTestEntry *GetTestEntry(void);

#endif