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

#include "securec.h"

#include "parameter_mock.h"


static const char* CHINESE_LANGUAGE = "zh-Hans";
static const char* TRADITIONAL_CHINESE_LANGUAGE = "zh-Hant";
static const char* NON_CHINESE_LANGUAGE = "English";
ParameterMock *ParameterMock::parameterMock = nullptr;

ParameterMock::ParameterMock()
{
    ParameterMock::parameterMock = this;
}

ParameterMock::~ParameterMock()
{
    ParameterMock::parameterMock = nullptr;
}

ParameterMock *ParameterMock::GetMock()
{
    return parameterMock;
}

int GetParameter(const char *key, const char *def, char *value, uint32_t len)
{
    return ParameterMock::GetMock()->GetParameter(key, def, value, len);
}

int ParameterMock::ActionOfGetParameter1(const char *key, const char *def, char *value, uint32_t len)
{
    (void)key;
    (void)def;
    (void)value;
    (void)len;
    return -1;
}

int ParameterMock::ActionOfGetParameter2(const char *key, const char *def, char *value, uint32_t len)
{
    (void)key;
    (void)def;
    (void)strcpy_s(value, len, CHINESE_LANGUAGE);
    return 1;
}

int ParameterMock::ActionOfGetParameter3(const char *key, const char *def, char *value, uint32_t len)
{
    (void)key;
    (void)def;
    (void)strcpy_s(value, len, TRADITIONAL_CHINESE_LANGUAGE);
    return 1;
}

int ParameterMock::ActionOfGetParameter4(const char *key, const char *def, char *value, uint32_t len)
{
    (void)key;
    (void)def;
    (void)strcpy_s(value, len, NON_CHINESE_LANGUAGE);
    return 1;
}