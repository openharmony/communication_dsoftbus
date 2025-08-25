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

#ifndef PARAMETER_H
#define PARAMETER_H

#include <gmock/gmock.h>
#include "parameter.h"
 
class ParameterInterface {
public:
    virtual int GetParameter(const char *key, const char *def, char *value, uint32_t len) = 0;
};

class ParameterMock : public ParameterInterface {
public:
    static ParameterMock* GetMock();

    ParameterMock();
    ~ParameterMock();

    MOCK_METHOD(int, GetParameter, (const char *key, const char *def, char *value, uint32_t len), (override));

    static int ActionOfGetParameter1(const char *key, const char *def, char *value, uint32_t len);
    static int ActionOfGetParameter2(const char *key, const char *def, char *value, uint32_t len);
    static int ActionOfGetParameter3(const char *key, const char *def, char *value, uint32_t len);
    static int ActionOfGetParameter4(const char *key, const char *def, char *value, uint32_t len);
private:
    static ParameterMock *parameterMock;
};
#endif