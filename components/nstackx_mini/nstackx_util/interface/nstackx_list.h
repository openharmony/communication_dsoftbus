/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_LIST_H
#define NSTACKX_LIST_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct List {
    struct List *prev;
    struct List *next;
} List;

static inline void ListInitHead(List *head)
{
    head->next = head;
    head->prev = head;
}

static inline void ListInsertHead(List *head, List *node)
{
    node->next = head->next;
    node->next->prev = node;
    node->prev = head;
    head->next = node;
}

static inline void ListInsertTail(List *head, List *node)
{
    node->prev = head->prev;
    node->prev->next = node;
    node->next = head;
    head->prev = node;
}

static inline void ListRemoveNode(List *node)
{
    if (node == NULL) {
        return;
    }
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = NULL;
    node->prev = NULL;
}

static inline uint8_t ListIsEmpty(const List *head)
{
    return (head == head->next);
}

static inline List *ListGetFront(List *head)
{
    return head->next;
}

static inline List *ListPopFront(List *head)
{
    List *element = NULL;
    if (head == NULL || ListIsEmpty(head)) {
        return NULL;
    }

    element = head->next;
    ListRemoveNode(element);
    return element;
}

static inline void ListInsertNewHead(List *prevHead, List *newHead)
{
    prevHead->prev->next = newHead->next;
    newHead->next->prev = prevHead->prev;
    newHead->prev->next = prevHead;
    prevHead->prev = newHead->prev;
}

static inline void ListMove(List *from, List *to)
{
    List *first = from->next;
    List *last = from->prev;

    to->next = first;
    to->prev = last;
    first->prev = to;
    last->next = to;
    ListInitHead(from);
}

#define LIST_FOR_EACH(curr, head) \
    for ((curr) = (head)->next; (curr) != (head); (curr) = (curr)->next)

#define LIST_FOR_EACH_SAFE(pos, tmp, head) \
    for ((pos) = (head)->next, (tmp) = (pos)->next; (pos) != (head); \
        (pos) = (tmp), (tmp) = (pos)->next)

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_LIST_H
