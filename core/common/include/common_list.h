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

#ifndef COMMON_LIST_H
#define COMMON_LIST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct ListNode {
    struct ListNode *prev; /* Current node's pointer to the previous node */
    struct ListNode *next; /* Current node's pointer to the next node */
} ListNode;

/* list initialize */
__attribute__((always_inline)) static inline void ListInit(ListNode *list)
{
    list->next = list;
    list->prev = list;
}

/* Get list head node */
#define GET_LIST_HEAD(object) ((object)->next)

/* Get list tail node */
#define GET_LIST_TAIL(object) ((object)->prev)

/* Insert a new node to list. */
__attribute__((always_inline)) static inline void ListAdd(ListNode *list, ListNode *node)
{
    node->next = list->next;
    node->prev = list;
    list->next->prev = node;
    list->next = node;
}

/* Insert a node to the tail of a list. */
__attribute__((always_inline)) static inline void ListTailInsert(ListNode *list, ListNode *node)
{
    ListAdd(list->prev, node);
}

/* Insert a new node to list. */
__attribute__((always_inline)) static inline void ListNodeInsert(ListNode *list, ListNode *node)
{
    ListAdd(list, node);
}

/* Delete a specified node from list. */
__attribute__((always_inline)) static inline void ListDelete(ListNode *node)
{
    if (node->next != 0 && node->prev != 0) {
        node->next->prev = node->prev;
        node->prev->next = node->next;
    }
    node->next = node;
    node->prev = node;
}

__attribute__((always_inline)) static inline bool IsListEmpty(const ListNode *node)
{
    return (bool)(node->next == node);
}

/*
 * @brief Obtain the pointer to a list in a structure
 *
 * @param type    [IN] Structure name.
 * @param member  [IN] Member name of the list in the structure.
 */
#define OFF_SET_OF(type, member) ((size_t)&(((type *)0)->member))

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, member) \
    (type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

/*
 * @brief Obtain the pointer to a structure that contains a list.
 * @param item    [IN] Current node's pointer to the next node.
 * @param type    [IN] Structure name.
 * @param member  [IN] Member name of the list in the structure.
 */
#define LIST_ENTRY(item, type, member) \
    ((type *)(void *)((char *)(item) - OFF_SET_OF(type, member))) \

/* Iterate over a list of given type. */
#define LIST_FOR_EACH_ENTRY(item, list, type, member) \
    for ((item) = LIST_ENTRY((list)->next, type, member); \
            ((item) != NULL) && (&(item)->member != (list)); \
            (item) = LIST_ENTRY((item)->member.next, type, member))

/* Iterate over a list safe against removal of list entry. */
#define LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, list, type, member) \
    for ((item) = LIST_ENTRY((list)->next, type, member), \
            (nextItem) = LIST_ENTRY((item)->member.next, type, member); \
            &((item)->member) != (list); \
            (item) = (nextItem), (nextItem) = LIST_ENTRY((item)->member.next, type, member))

__attribute__((always_inline)) static inline void ListDel(ListNode *prevNode, ListNode *nextNode)
{
    nextNode->prev = prevNode;
    prevNode->next = nextNode;
}

/* Delete node and initialize list */
__attribute__((always_inline)) static inline void ListDelInit(ListNode *list)
{
    ListDel(list->prev, list->next);
    ListInit(list);
}

/* Iterate over a list. */
#define LIST_FOR_EACH(item, list) \
    for ((item) = (list)->next; (item) != (list); (item) = (item)->next)

/* Iterate over a list safe against removal of list entry. */
#define LIST_FOR_EACH_SAFE(item, nextItem, list) \
    for ((item) = (list)->next, (nextItem) = (item)->next; (item) != (list); \
            (item) = (nextItem), (nextItem) = (item)->next)

/* Initialize a list. */
#define LIST_HEAD(list) ListNode list = { &(list), &(list) }

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* COMMON_LIST_H */
