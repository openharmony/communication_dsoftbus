/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
static SoftBusCond g_cond;
static SoftBusMutex g_mutex;
const int32_t DELAY_TIME = 1000;

class SoftbusThreadTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusThreadTest::SetUpTestCase(void) { }

void SoftbusThreadTest::TearDownTestCase(void) { }

void SoftbusThreadTest::SetUp() { }

void SoftbusThreadTest::TearDown() { }

static void *SoftBusThreadTask(void *arg)
{
    printf("----------%s--------\n", __FUNCTION__);
    SoftBusSleepMs(DELAY_TIME);
    return static_cast<void *>(const_cast<char *>("SoftBusThreadTask"));
}

static void *ThreadSelfTest(void *arg)
{
    printf("----------%s--------\n", __FUNCTION__);
    SoftBusThread thread = SoftBusThreadGetSelf();
    EXPECT_TRUE(thread != 0);
    SoftBusSleepMs(DELAY_TIME);
    return nullptr;
}

static void *ThreadWaitTest(void *arg)
{
    printf("----------%s--------\n", __FUNCTION__);
    int32_t ret = SoftBusCondWait(&g_cond, &g_mutex, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(DELAY_TIME);
    return nullptr;
}

static void *ThreadSignalTest(void *arg)
{
    printf("----------%s--------\n", __FUNCTION__);
    SoftBusSleepMs(DELAY_TIME);
    int32_t ret = SoftBusCondSignal(&g_cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    return nullptr;
}

/*
 * @tc.name: SoftbusMutexAttrInitTest001
 * @tc.desc: mutexAttr is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftbusMutexAttrInitTest001, TestSize.Level0)
{
    int32_t ret = SoftBusMutexAttrInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusMutexAttrInitTest002
 * @tc.desc: mutexAttr is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftbusMutexAttrInitTest002, TestSize.Level0)
{
    SoftBusMutexAttr mutexAttr;
    int32_t ret = SoftBusMutexAttrInit(&mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_MUTEX_NORMAL, mutexAttr.type);
}

/*
 * @tc.name: SoftBusMutexInitTest001
 * @tc.desc: mutexAttr is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexInitTest001, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexInit(&mutex, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexInitTest002
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_NORMAL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexInitTest002, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexInitTest003
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_RECURSIVE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexInitTest003, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexLockTest001
 * @tc.desc: mutex is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockTest001, TestSize.Level0)
{
    int32_t ret = SoftBusMutexLock(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexLockTest002
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_NORMAL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockTest002, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexLockTest003
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_RECURSIVE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockTest003, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexLockTest004
 * @tc.desc: mutex is default
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockTest004, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexInit(&mutex, nullptr);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexLockTest005
 * @tc.desc: mutex value is 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockTest005, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexUnlockTest001
 * @tc.desc: mutex is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexUnlockTest001, TestSize.Level0)
{
    int32_t ret = SoftBusMutexUnlock(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexUnlockTest002
 * @tc.desc: mutex value is 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexUnlockTest002, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexUnlock(&mutex);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexUnlockTest003
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_NORMAL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexUnlockTest003, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexUnlock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexUnlockTest004
 * @tc.desc: mutexAttr type is SOFTBUS_MUTEX_NORMAL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexUnlockTest004, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexUnlock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexUnlockTest005
 * @tc.desc: mutex value is default
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexUnlockTest005, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexInit(&mutex, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexLock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusMutexUnlock(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexDestroyTest001
 * @tc.desc: mutex is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexDestroyTest001, TestSize.Level0)
{
    int32_t ret = SoftBusMutexDestroy(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexDestroyTest002
 * @tc.desc: mutex value is 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexDestroyTest002, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexDestroy(&mutex);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusMutexDestroyTest003
 * @tc.desc: mutexAttr is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexDestroyTest003, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexInit(&mutex, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusMutexDestroy(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexDestroyTest004
 * @tc.desc: mutexAttr is SOFTBUS_MUTEX_NORMAL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexDestroyTest004, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusMutexDestroy(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexDestroyTest005
 * @tc.desc: mutexAttr is SOFTBUS_MUTEX_RECURSIVE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexDestroyTest005, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusMutexDestroy(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusMutexLockGuardTest001
 * @tc.desc: should call SoftBusMutexUnlock automatically when leave bracket scope
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusThreadTest, SoftBusMutexLockGuardTest001, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusMutexInit(&mutex, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    {
        ret = SoftBusMutexLock(&mutex);
        EXPECT_EQ(SOFTBUS_OK, ret);
        SOFTBUS_LOCK_GUARD(mutex);
    }
    {
        ret = SoftBusMutexLock(&mutex);
        EXPECT_EQ(SOFTBUS_OK, ret);
        SOFTBUS_LOCK_GUARD(mutex);
    }
    ret = SoftBusMutexDestroy(&mutex);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusThreadAttrInitTest001
 * @tc.desc: threadAttr is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadAttrInitTest001, TestSize.Level0)
{
    int32_t ret = SoftBusThreadAttrInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadAttrInitTest002
 * @tc.desc: threadAttr is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadAttrInitTest002, TestSize.Level0)
{
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusThreadCreateTest001
 * @tc.desc: thread is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest001, TestSize.Level0)
{
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(nullptr, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadCreateTest002
 * @tc.desc: threadAttr is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest002, TestSize.Level0)
{
    SoftBusThread thread = 0;

    int32_t ret = SoftBusThreadCreate(&thread, nullptr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusThreadCreateTest003
 * @tc.desc: threadAttr is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest003, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

#if HAVE_PRO
/*
 * @tc.name: SoftBusThreadCreateTest004
 * @tc.desc: threadAttr add taskName
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest004, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.taskName = "ThreadTask";
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    EXPECT_TRUE(thread != 0);
}
#endif

/*
 * @tc.name: SoftBusThreadCreateTest005
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest005, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_HIGHEST;
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusThreadCreateTest006
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest006, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_HIGH;
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusThreadCreateTest007
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest007, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_DEFAULT;
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusThreadCreateTest008
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest008, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_LOW;
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusThreadCreateTest009
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest009, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_LOWEST;
    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

#if HAVE_PRO
/*
 * @tc.name: SoftBusThreadCreateTest010
 * @tc.desc: threadEntry is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadCreateTest010, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest001
 * @tc.desc: name is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest001, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_HIGHEST;

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest002
 * @tc.desc: name is large than TASK_NAME_MAX_LEN
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest002, TestSize.Level0)
{
    const char *name = "abcdefghijklmnopqrstuvwxyz";
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_HIGHEST;

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, name);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest003
 * @tc.desc: name is equal to TASK_NAME_MAX_LEN
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest003, TestSize.Level0)
{
    const char *name = "abcdefghijklmnop";
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    threadAttr.prior = SOFTBUS_PRIORITY_HIGHEST;

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, name);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest004
 * @tc.desc: name include chinese character
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest004, TestSize.Level0)
{
    const char *name = "a中文p";
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, name);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest005
 * @tc.desc: name is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest005, TestSize.Level0)
{
    const char *name = "testThread";
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, name);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: SoftBusThreadSetNameTest006
 * @tc.desc: threadAttr is nullptr, name is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadSetNameTest006, TestSize.Level0)
{
    const char *name = "testThread";
    SoftBusThread thread = 0;

    int32_t ret = SoftBusThreadCreate(&thread, nullptr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);

    ret = SoftBusThreadSetName(thread, name);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
#endif

/*
 * @tc.name: SoftBusThreadGetSelfTest001
 * @tc.desc: threadAttr modify prior
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadGetSelfTest001, TestSize.Level0)
{
    SoftBusThread thread = 0;

    int32_t ret = SoftBusThreadCreate(&thread, NULL, ThreadSelfTest, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
}

/*
 * @tc.name: SoftBusCondInitTest001
 * @tc.desc: cond is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondInitTest001, TestSize.Level0)
{
    int32_t ret = SoftBusCondInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondInitTest002
 * @tc.desc: cond is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondInitTest002, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);
}

/*
 * @tc.name: SoftBusCondSignalTest001
 * @tc.desc: cond is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondSignalTest001, TestSize.Level0)
{
    int32_t ret = SoftBusCondSignal(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondSignalTest002
 * @tc.desc: no wait thread
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondSignalTest002, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondSignal(&cond);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondSignalTest003
 * @tc.desc: no wait thread
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondSignalTest003, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);
    ret = SoftBusCondSignal(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusCondBroadcastTest001
 * @tc.desc: cond is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondBroadcastTest001, TestSize.Level0)
{
    int32_t ret = SoftBusCondBroadcast(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondBroadcastTest002
 * @tc.desc: cond is not init
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondBroadcastTest002, TestSize.Level0)
{
    SoftBusCond cond = 0;

    int32_t ret = SoftBusCondBroadcast(&cond);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondBroadcastTest003
 * @tc.desc: cond is init value
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondBroadcastTest003, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);

    ret = SoftBusCondBroadcast(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusCondWaitTest001
 * @tc.desc: cond is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondWaitTest001, TestSize.Level0)
{
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusCondWait(nullptr, &mutex, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondWaitTest002
 * @tc.desc: cond value is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondWaitTest002, TestSize.Level0)
{
    SoftBusCond cond = 0;
    SoftBusMutex mutex = 0;
    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_NORMAL,
    };
    int32_t ret = SoftBusMutexInit(&mutex, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusCondWait(&cond, &mutex, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondWaitTest003
 * @tc.desc: mutex is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondWaitTest003, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);
    ret = SoftBusCondWait(&cond, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondWaitTest004
 * @tc.desc: mutex value is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondWaitTest004, TestSize.Level0)
{
    SoftBusCond cond = 0;
    SoftBusMutex mutex = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);

    ret = SoftBusCondWait(&cond, &mutex, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondDestroyTest001
 * @tc.desc: cond is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondDestroyTest001, TestSize.Level0)
{
    int32_t ret = SoftBusCondDestroy(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusCondDestroyTest002
 * @tc.desc: cond is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondDestroyTest002, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondInit(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(cond != 0);

    ret = SoftBusCondDestroy(&cond);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusCondDestroyTest003
 * @tc.desc: cond is valid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusCondDestroyTest003, TestSize.Level0)
{
    SoftBusCond cond = 0;
    int32_t ret = SoftBusCondDestroy(&cond);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusThreadJoinTest001
 * @tc.desc: value is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadJoinTest001, TestSize.Level0)
{
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
    ret = SoftBusThreadJoin(thread, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusThreadJoinTest002
 * @tc.desc: value is not nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadJoinTest002, TestSize.Level0)
{
    char *value = nullptr;
    SoftBusThread thread = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    int32_t ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&thread, &threadAttr, SoftBusThreadTask, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(thread != 0);
    ret = SoftBusThreadJoin(thread, (void **)&value);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(value != nullptr);
}

/*
 * @tc.name: SoftBusThreadFullTest001
 * @tc.desc: thread process test
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(SoftbusThreadTest, SoftBusThreadFullTest001, TestSize.Level0)
{
    int32_t ret = SoftBusMutexInit(&g_mutex, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusCondInit(&g_cond);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusThread threadWait = 0;
    SoftBusThread threadSignal = 0;
    SoftBusThreadAttr threadAttr = { 0 };
    ret = SoftBusThreadAttrInit(&threadAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusThreadCreate(&threadWait, &threadAttr, ThreadWaitTest, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(threadWait != 0);

    ret = SoftBusThreadCreate(&threadSignal, &threadAttr, ThreadSignalTest, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(threadSignal != 0);

    ret = SoftBusThreadJoin(threadWait, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusThreadJoin(threadSignal, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
