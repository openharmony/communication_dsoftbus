/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ASSERT_HELPER_H
#define ASSERT_HELPER_H

#include "softbus_broadcast_adapter_type.h"

#include "gmock/gmock.h"
#include <cstring>
#include <securec.h>

class RecordCtx {
public:
    explicit RecordCtx(const char *identifier) : id(-1)
    {
        this->identifier = identifier;
    }

    bool Update(int32_t idParam)
    {
        this->id = idParam;
        return true;
    }

    testing::AssertionResult Expect(int32_t idParam)
    {
        testing::AssertionResult result = testing::AssertionSuccess();
        if (this->id != idParam) {
            result = testing::AssertionFailure() << identifier << " is call by unexpectedly id,"
                                                 << "want: " << idParam << ", actual: " << this->id;
            this->id = -1;
        }
        return result;
    }

protected:
    // static c string
    const char *identifier;

private:
    int32_t id;
};

class StRecordCtx : public RecordCtx {
public:
    explicit StRecordCtx(const char *identifier) : RecordCtx(identifier), st(-1) { }

    bool Update(int32_t id, int32_t stParam)
    {
        if (!RecordCtx::Update(id)) {
            return false;
        }
        this->st = stParam;
        return true;
    }

    testing::AssertionResult Expect(int32_t id, int32_t stParam)
    {
        auto result = RecordCtx::Expect(id);
        if (!result) {
            goto ClEANUP;
        }
        if (this->st != stParam) {
            result = testing::AssertionFailure() << identifier << " is call by unexpectedly state,"
                                                 << "want: " << stParam << ", actual: " << this->st;
            goto ClEANUP;
        }
        result = testing::AssertionSuccess();
    ClEANUP:
        this->st = -1;
        return result;
    }

private:
    int32_t st;
};

class BtAddrRecordCtx : public StRecordCtx {
public:
    explicit BtAddrRecordCtx(const char *identifier) : StRecordCtx(identifier)
    {
        Reset();
    }

    bool Update(int32_t id, const SoftbusMacAddr *addr, int32_t st = 0)
    {
        if (!StRecordCtx::Update(id, st)) {
            return false;
        }
        addrVal = *addr;
        return true;
    }

    testing::AssertionResult Expect(int32_t id, SoftbusMacAddr *addrParam, int32_t st = 0)
    {
        auto result = StRecordCtx::Expect(id, st);
        if (!result) {
            goto ClEANUP;
        }
        if (memcmp(addrParam->addr, addrVal.addr, SOFTBUS_ADDR_MAC_LEN) != 0) {
            result = testing::AssertionFailure() << identifier << "is call by unexpectedly addr";
            goto ClEANUP;
        }
        result = testing::AssertionSuccess();
    ClEANUP:
        Reset();
        return result;
    }

private:
    SoftbusMacAddr addrVal;
    void Reset()
    {
        memset_s(&addrVal, sizeof(SoftbusMacAddr), 0, sizeof(SoftbusMacAddr));
    }
};

class IntRecordCtx : public StRecordCtx {
public:
    explicit IntRecordCtx(const char *identifier) : StRecordCtx(identifier), val(-1) { }

    bool Update(int32_t id, int32_t st, int32_t valParam)
    {
        if (!StRecordCtx::Update(id, st)) {
            return false;
        }
        this->val = valParam;
        return true;
    }

    testing::AssertionResult Expect(int32_t id, int32_t st, int32_t valParam)
    {
        auto result = StRecordCtx::Expect(id, st);
        if (!result) {
            goto ClEANUP;
        }
        if (this->val != valParam) {
            result = testing::AssertionFailure() << identifier << " is call by unexpectedly int32_t value,"
                                                 << "want: " << valParam << ", actual: " << this->val;
        } else {
            result = testing::AssertionSuccess();
        }
    ClEANUP:
        this->val = -1;
        return result;
    }

private:
    int32_t val;
};

#endif