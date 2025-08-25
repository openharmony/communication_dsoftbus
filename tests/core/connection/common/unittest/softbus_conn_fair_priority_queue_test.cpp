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

#include "softbus_conn_fair_priority_queue.h"

#include <list>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "softbus_adapter_timer.h"

#include "conn_log.h"

using namespace testing::ext;
using namespace testing;

extern "C" {
struct DummyQueueItem {
    CONN_QUEUE_ITEM_BASE;
    int payload;
};
}

namespace OHOS::SoftBus {
class ConnQueueTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }
};

struct TestAction;
struct TestAction {
    // 0: enqueue, other: dequeue
    int operation_;
    // it should declare as pointer type, as we should assert it is the same object or not
    std::shared_ptr<DummyQueueItem> item_;
    int32_t timeoutMs_;
    bool wait_;
    int32_t ret_;

    TestAction(int operation, std::shared_ptr<DummyQueueItem> &item, int32_t timeoutMs, bool wait, int32_t ret)
    {
        operation_ = operation;
        item_ = std::shared_ptr(item);
        timeoutMs_ = timeoutMs;
        wait_ = wait;
        ret_ = ret;
    }

    ~TestAction() = default;
};

static void Dump(const TestAction &action, const DummyQueueItem *item)
{
    if (item != nullptr) {
        CONN_LOGI(CONN_TEST,
            "operation=%{public}d, timeout=%{public}dms, wait=%{public}d, ret code=%{public}d;"
            "id=%{public}d, priority=%{public}d, payload=%{public}d",
            action.operation_, action.timeoutMs_, action.wait_, action.ret_, item->id, item->priority,
            item->payload);
    } else {
        CONN_LOGI(CONN_TEST,
            "operation=%{public}d, timeout=%{public}dms, wait=%{public}d, ret code=%{public}d, item is not exist",
            action.operation_, action.timeoutMs_, action.wait_, action.ret_);
    }
}

static bool RunTestCase(const std::string &name, ConnFairPriorityQueue *queue,
    std::list<std::shared_ptr<TestAction>> &actions, bool verbose = false)
{
    int32_t i = 0;

    if (verbose) {
        for (const auto &action : actions) {
            CONN_LOGI(CONN_TEST, "%{public}s: the %{public}d th dump before any action", name.c_str(), i);
            Dump(*action, action->item_.get());
        }
    }

    i = 0;
    for (const auto &action : actions) {
        int32_t ret;
        DummyQueueItem *item = nullptr;
        auto before = SoftBusGetSysTimeMs();
        if (action->operation_ == 0) {
            item = action->item_.get();
            ret = ConnEnqueue(queue, (struct ConnQueueItem *)item, action->timeoutMs_);
        } else {
            item = nullptr;
            ret = ConnDequeue(queue, (struct ConnQueueItem **)&item, action->timeoutMs_);
        }

        auto duration = SoftBusGetSysTimeMs() - before;
        if (action->ret_ != ret) {
            ADD_FAILURE() << name << ", failed on " << i << "th action, expect code " << action->ret_ << " actual is "
                          << ret;
            return false;
        }

        if (action->ret_ == SOFTBUS_OK) {
            DummyQueueItem *expected = action->item_.get();
            if (expected != nullptr && item != expected) {
                ADD_FAILURE() << name << ", failed on " << i << "th action, item not match";
                return false;
            }
        }

        if (action->wait_ && duration < action->timeoutMs_) {
            ADD_FAILURE() << name << ", failed on " << i << "th action, expect wait " << action->timeoutMs_
                          << ", actual just passed " << duration << " ms";
            return false;
        }
        if (!action->wait_ && duration >= action->timeoutMs_) {
            ADD_FAILURE() << name << ", failed on " << i << "th action, expect not wait " << action->timeoutMs_
                          << ", actual passed " << duration << " ms";
            return false;
        }
        i++;
    }
    return true;
}

static int32_t PickTestcase(int id, ConnPriority lastPriority, std::list<std::shared_ptr<TestAction>> &actions,
    std::list<std::shared_ptr<TestAction>> &result)
{
    for (int32_t priority = CONN_PRIORITY_HIGH; priority <= lastPriority; priority++) {
        for (auto it = actions.begin(); it != actions.end(); it++) {
            auto action = *it;
            if (action->item_->id == id && action->item_->priority == priority) {
                result.push_back(action);
                actions.erase(it);
                return SOFTBUS_OK;
            }
        }
    }
    return SOFTBUS_NOT_FIND;
}

static void FairPrioritySort(std::list<std::shared_ptr<TestAction>> &actions)
{
    std::list<int> idSequence;
    std::list<std::shared_ptr<TestAction>> result;

    for (auto &action : actions) {
        auto id = action->item_->id;
        if (id == 0) {
            continue;
        }
        auto it = std::find(idSequence.begin(), idSequence.end(), id);
        if (it == idSequence.end()) {
            idSequence.push_back(id);
        }
    }

    int32_t ret;
    do {
        ret = PickTestcase(0, CONN_PRIORITY_MIDDLE, actions, result);
    } while (ret == SOFTBUS_OK);

    while (!idSequence.empty()) {
        auto id = idSequence.front();
        idSequence.pop_front();
        ret = PickTestcase(id, CONN_PRIORITY_LOW, actions, result);
        if (ret == SOFTBUS_OK) {
            idSequence.push_back(id);
        }
    }
    do {
        ret = PickTestcase(0, CONN_PRIORITY_LOW, actions, result);
    } while (ret == SOFTBUS_OK);

    for (auto it = result.begin(); it != result.end(); it = result.erase(it)) {
        auto action = *it;
        actions.push_back(action);
    }
}

/*
 * @tc.name: DequeueDequeueAlternateTest
 * @tc.desc: alternate enqueue and dequeue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnQueueTest, DequeueDequeueAlternateTest, TestSize.Level1)
{
    constexpr uint32_t size = 4;
    auto queue = ConnCreateQueue(size);
    ASSERT_NE(queue, nullptr);

    auto actions = std::list<std::shared_ptr<TestAction>>();
    for (int i = 0; i < 10; i++) {
        auto item = std::make_shared<DummyQueueItem>();
        item->id = 0;
        item->priority = CONN_PRIORITY_HIGH;
        item->payload = i;

        auto ea = std::make_shared<TestAction>(0, item, 1500, false, SOFTBUS_OK);
        actions.push_back(ea);

        auto da = std::make_shared<TestAction>(1, item, 1500, false, SOFTBUS_OK);
        actions.push_back(da);
    }
    auto result = RunTestCase("enqueue dequeue alternate test", queue, actions, false);
    EXPECT_TRUE(result);
    ConnDestroyQueue(queue);
}

/*
 * @tc.name: EnqueueBlockTest
 * @tc.desc: enqueue block
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(ConnQueueTest, EnqueueDequeueBlockTest, TestSize.Level1)
{
    constexpr uint32_t size = 4;
    auto queue = ConnCreateQueue(size);
    ASSERT_NE(queue, nullptr);

    auto enqueueActions = std::list<std::shared_ptr<TestAction>>();
    auto dequeueActions = std::list<std::shared_ptr<TestAction>>();
    for (int i = 0; i < size - 1; i++) {
        auto item = std::make_shared<DummyQueueItem>();
        item->id = 1;
        item->priority = CONN_PRIORITY_HIGH;
        item->payload = i;

        auto ea = std::make_shared<TestAction>(0, item, 100, false, SOFTBUS_OK);
        enqueueActions.push_back(ea);

        auto da = std::make_shared<TestAction>(1, item, 100, false, SOFTBUS_OK);
        dequeueActions.push_back(da);
    }

    for (int i = 0; i < 3; i++) {
        auto item = std::make_shared<DummyQueueItem>();
        item->id = 1;
        item->priority = CONN_PRIORITY_HIGH;
        item->payload = i;

        auto ea = std::make_shared<TestAction>(0, item, 100, true, SOFTBUS_TIMOUT);
        enqueueActions.push_back(ea);

        auto da = std::make_shared<TestAction>(1, item, 100, true, SOFTBUS_TIMOUT);
        dequeueActions.push_back(da);
    }

    auto result = RunTestCase("enqueue block test", queue, enqueueActions, true);
    EXPECT_TRUE(result);
    result = RunTestCase("dequeue block test", queue, dequeueActions, true);
    EXPECT_TRUE(result);
    ConnDestroyQueue(queue);
}

/*
 * @tc.name: PriorityQueueTest
 * @tc.desc: test priority queue behavior
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(ConnQueueTest, PriorityQueueTest, TestSize.Level1)
{
    constexpr uint32_t size = 1 << 8;
    auto queue = ConnCreateQueue(size);
    ASSERT_NE(queue, nullptr);

    auto enqueueActions = std::list<std::shared_ptr<TestAction>>();
    auto dequeueActions = std::list<std::shared_ptr<TestAction>>();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distId(0, 3);
    std::uniform_int_distribution<> distPriority(0, 2);
    for (auto i = 0; i < 10; i++) {
        auto item = std::make_shared<DummyQueueItem>();
        item->id = distId(gen);
        item->priority = static_cast<ConnPriority>(distPriority(gen));
        item->payload = i;

        auto ea = std::make_shared<TestAction>(0, item, 100, false, SOFTBUS_OK);
        enqueueActions.push_back(ea);

        auto da = std::make_shared<TestAction>(1, item, 100, false, SOFTBUS_OK);
        dequeueActions.push_back(da);
    }
    FairPrioritySort(dequeueActions);

    // add one more dequeue action, check all item is dequeued
    std::shared_ptr<DummyQueueItem> item = nullptr;
    auto dta = std::make_shared<TestAction>(1, item, 100, true, SOFTBUS_TIMOUT);
    dequeueActions.push_back(dta);

    auto result = RunTestCase("priority enqueue test", queue, enqueueActions, true);
    EXPECT_TRUE(result);
    result = RunTestCase("priority dequeue test", queue, dequeueActions, true);
    EXPECT_TRUE(result);

    ConnDestroyQueue(queue);
}

} // namespace OHOS::SoftBus