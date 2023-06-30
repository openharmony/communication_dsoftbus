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

#ifndef SOFTBUS_QUEUE_H
#define SOFTBUS_QUEUE_H

#include <stdbool.h>
#include <stdint.h>
#include "securec.h"

#include "softbus_adapter_cpu.h"
#include "softbus_adapter_atomic.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    QUEUE_INVAL = -10,
    QUEUE_FULL,
    QUEUE_EMPTY
} QueueError;

/** @brief Lock free ring queue */
typedef struct {
    uint32_t magic;
    uint32_t unitNum;  /* queue node limit */
    uint8_t pad[56];   /* cache line pad */

    /* producer status */
    struct {
        uint32_t size;              /* queue size */
        uint32_t mask;              /* mask(size-1). */
        volatile uint32_t head;     /* producer head */
        volatile uint32_t tail;     /* producer tail */
        uint8_t pad[48];            /* cache line pad */
    } producer;

    /* consumer status */
    struct {
        uint32_t size;              /* queue size */
        uint32_t mask;              /* mask(size-1). */
        volatile uint32_t head;     /* consumer head */
        volatile uint32_t tail;     /* consumer tail */
        uint8_t pad[48];            /* cache line pad */
    } consumer;

    uintptr_t nodes[0]; /* queue nodes */
} LockFreeQueue;

extern int32_t QueueSizeCalc(uint32_t unitNum, uint32_t* queueSize);

extern int32_t QueueCountGet(const LockFreeQueue* queue, uint32_t* count);

extern int32_t QueueInit(LockFreeQueue* queue, uint32_t unitNum);

extern LockFreeQueue* CreateQueue(uint32_t unitNum);

static inline int32_t QueueIsEmpty(LockFreeQueue* queue)
{
    uint32_t producerTail;
    uint32_t consumerTail;
    uint32_t mask;

    if (queue == NULL) {
        return QUEUE_INVAL;
    }

    producerTail = queue->producer.tail;
    consumerTail = queue->consumer.tail;
    mask = queue->producer.mask;

    if (((producerTail - consumerTail) & mask) == 0) {
        return 0;
    }
    return -1;
}

/** @brief Enqueue operation, thread unsafe */
static inline int32_t QueueSingleProducerEnqueue(LockFreeQueue *queue, const void *node)
{
    uint32_t producerHead;
    uint32_t producerNext;
    uint32_t consumerTail;
    uint32_t availableCount;
    uint32_t mask;

    if (queue == NULL || node == NULL) {
        return QUEUE_INVAL;
    }
    mask = queue->producer.mask;

    producerHead = queue->producer.head;
    RMB();
    consumerTail = queue->consumer.tail;

    /*
     * 1. In normal cases, producerHead > consumerTail and producerHead < consumerTail + mask
     * 2. If only producerHead is reversed, producerHead > consumerTail - 0xFFFFFFFF and
     *    producerHead < consumerTail + mask - 0xFFFFFFFF
     * The subtraction of two 32-bit integers results in 32-bit modulo.
     * Therefore, the availableCount must be between 0 and the queue length.
     */
    availableCount = (mask + consumerTail) - producerHead;

    if (availableCount < 1) {
        return QUEUE_FULL;
    }

    producerNext = producerHead + 1;
    queue->producer.head = producerNext;

    queue->nodes[producerHead & mask] = (uintptr_t)node;

    /*
     * Make sure that the queue is filled with elements before updating the producer tail.
     * Prevents problems when the producer tail is updated first:
     * 1. The consumer thinks that the elements in this area have been queued and can be consumed,
     *    but the consumer actually reads dirty elements.
     * 2. The process is abnormal. In this case, elements in the memory block in the queue are dirty elements.
     */
    WMB();

    queue->producer.tail = producerNext;
    return 0;
}

/** @brief Enqueue operation, thread safe */
static inline int32_t QueueMultiProducerEnqueue(LockFreeQueue* queue, const void* node)
{
    uint32_t producerHead;
    uint32_t producerNext;
    uint32_t consumerTail;
    uint32_t availableCount;
    bool success = false;
    uint32_t mask;

    if (queue == NULL || node == NULL) {
        return QUEUE_INVAL;
    }

    mask = queue->producer.mask;
    do {
        producerHead = queue->producer.head;
        /*
         * Make sure the producer's head is read before the consumer's tail.
         * If the consumer tail is read first, then the consumer consumes the queue,and then other producers
         * produce the queue, the producer header may cross the consumer tail reversely.
         */
        RMB();
        consumerTail = queue->consumer.tail;

        /*
         * 1. In normal cases, producerHead > consumerTail and producerHead < consumerTail + mask
         * 2. If only producerHead is reversed, producerHead > consumerTail - 0xFFFFFFFF and
         *    producerHead < consumerTail + mask - 0xFFFFFFFF
         * The subtraction of two 32-bit integers results in 32-bit modulo.
         * Therefore, the availableCount must be between 0 and the queue length.
         */

        availableCount = (mask + consumerTail) - producerHead;

        if (availableCount < 1) {
            return QUEUE_FULL;
        }

        producerNext = producerHead + 1;
        success = SoftBusAtomicCmpAndSwap32(&queue->producer.head, producerHead, producerNext);
    } while (success == false);

    queue->nodes[producerHead & mask] = (uintptr_t)node;

    /*
     * Make sure that the queue is filled with elements before updating the producer tail.
     * Prevents problems when the producer tail is updated first:
     * 1. The consumer thinks that the elements in this area have been queued and can be consumed,
     *    but the consumer actually reads dirty elements.
     * 2. The process is abnormal. In this case, elements in the memory block in the queue are dirty elements.
     */

    WMB();

    /* Waiting for other producers to complete enqueuing. */
    while (queue->producer.tail != producerHead) {
        SoftBusYieldCpu();
    }

    queue->producer.tail += 1;
    return 0;
}

/** @brief Dequeue operation, thread unsafe */
static inline int32_t QueueSingleConsumerDequeue(LockFreeQueue* queue, void** node)
{
    uint32_t consumerHead;
    uint32_t producerTail;
    uint32_t consumerNext;
    uint32_t availableCount;
    uint32_t mask;

    if (queue == NULL || node == NULL) {
        return QUEUE_INVAL;
    }
    mask = queue->producer.mask;

    consumerHead = queue->consumer.head;

    /* Prevent producerTail from being read before consumerHead, causing queue head and tail reversal. */
    RMB();

    producerTail = queue->producer.tail;

    /*
     * 1. In normal cases, producerTail > consumerHead and producerTail < consumerHead + mask
     * 2. If only producerTail is reversed, producerTail > consumerHead - 0xFFFFFFFF and
     *    producerTail < consumerHead + mask - 0xFFFFFFFF
     * The subtraction of two 32-bit integers results in 32-bit modulo.
     * Therefore, the availableCount must be between 0 and the queue length.
     */
    availableCount = (producerTail - consumerHead);

    if (availableCount < 1) {
        return QUEUE_EMPTY;
    }

    consumerNext = consumerHead + 1;
    queue->consumer.head = consumerNext;

    /* Prevent the read of queue->nodes before the read of ProdTail. */
    RMB();

    *node = (void *)(queue->nodes[consumerHead & mask]);

    /*
     * Ensure that the queue element is dequeued before updating the consumer's tail.
     * After the consumer tail is updated, the producer considers that the elements in this area have been dequeued
     * and can fill in new elements, which actually overwrites the elements that are not dequeued.
     */
    RMB();

    queue->consumer.tail = consumerNext;
    return 0;
}

/** @brief Dequeue operation, thread safe */
static inline int32_t QueueMultiConsumerDequeue(LockFreeQueue *queue, void **node)
{
    bool success = false;
    uint32_t consumerHead;
    uint32_t producerTail;
    uint32_t consumerNext;
    uint32_t availableCount;
    uint32_t mask;

    if (queue == NULL || node == NULL) {
        return QUEUE_INVAL;
    }
    mask = queue->producer.mask;

    do {
        consumerHead = queue->consumer.head;

        /*
         * Make sure the consumer's head is read before the producer's tail.
         * If the producer tail is read first, then other consumers consume the queue,
         * and finally the generator produces the queue, the consumer head may cross the producer tail.
         */
        RMB();

        producerTail = queue->producer.tail;

        /*
         * 1. In normal cases, producerTail > consumerHead and producerTail < consumerHead + mask
         * 2. If only producerTail is reversed, producerTail > consumerHead - 0xFFFFFFFF and
         *    producerTail < consumerHead + mask - 0xFFFFFFFF
         * The subtraction of two 32-bit integers results in 32-bit modulo.
         * Therefore, the availableCount must be between 0 and the queue length.
         */

        availableCount = (producerTail - consumerHead);

        if (availableCount < 1) {
            return QUEUE_EMPTY;
        }

        consumerNext = consumerHead + 1;
        success = SoftBusAtomicCmpAndSwap32(&queue->consumer.head, consumerHead, consumerNext);
    } while (success == false);

    /* Prevent the read of queue->nodes before the read of ProdTail. */
    RMB();

    *node = (void *)(queue->nodes[consumerHead & mask]);

    /*
     * Ensure that the queue element is dequeued before updating the consumer's tail.
     * After the consumer tail is updated, the producer considers that the elements in this area have been dequeued
     * and can fill in new elements, which actually overwrites the elements that are not dequeued.
     */
    RMB();

    /* Waiting for other consumers to finish dequeuing. */
    while (queue->consumer.tail != consumerHead) {
        SoftBusYieldCpu();
    }

    queue->consumer.tail += 1;

    return 0;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif // SOFTBUS_QUEUE_H
