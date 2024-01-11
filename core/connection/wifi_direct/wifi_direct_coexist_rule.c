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

#include "wifi_direct_coexist_rule.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "wifi_direct_p2p_adapter.h"

#define RULE_BUFFER_LEN 128

struct CombinationHead {
    ListNode node;
    ListNode subList;
};

static void SetBypass(void)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    self->bypass = true;
}

static void ShowRulesList(ListNode *rulesList)
{
    int32_t index = 0;
    struct CombinationHead *head = NULL;
    LIST_FOR_EACH_ENTRY(head, rulesList, struct CombinationHead, node) {
        int32_t pos = 0;
        char buffer[RULE_BUFFER_LEN] = {0};
        struct CombinationEntry *entry = NULL;
        LIST_FOR_EACH_ENTRY(entry, &head->subList, struct CombinationEntry, node) {
            int32_t ret = sprintf_s(buffer + pos, RULE_BUFFER_LEN - pos, " %s", entry->interface);
            if (ret > 0) {
                pos += ret;
            }
        }
        CONN_LOGI(CONN_WIFI_DIRECT, "index=%{public}d, rule=%{public}s", index, buffer);
        index++;
    }
}

static int32_t SetCoexistRule(const char *rule)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();

    cJSON *coexistObj = cJSON_ParseWithLength(rule, strlen(rule) + 1);
    CONN_CHECK_AND_RETURN_RET_LOGW(coexistObj, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "create json object failed");
    if (!cJSON_IsArray(coexistObj)) {
        cJSON_Delete(coexistObj);
        CONN_LOGE(CONN_WIFI_DIRECT, "coexistObj is not a array");
        return SOFTBUS_INVALID_PARAM;
    }

    for (int i = 0; i < cJSON_GetArraySize(coexistObj); i++) {
        cJSON *subItems = cJSON_GetArrayItem(coexistObj, i);
        if (!cJSON_IsArray(subItems)) {
            CONN_LOGW(CONN_WIFI_DIRECT, "item is not array. i=%{public}d", i);
            continue;
        }

        struct CombinationHead *head = SoftBusCalloc(sizeof(*head));
        if (head == NULL) {
            CONN_LOGE(CONN_WIFI_DIRECT, "malloc head failed");
            continue;
        }

        ListInit(&head->node);
        ListInit(&head->subList);
        for (int j = 0; j < cJSON_GetArraySize(subItems); j++) {
            cJSON *subItem = cJSON_GetArrayItem(subItems, j);
            char interface[IF_NAME_LEN] = {0};
            if (!GetJsonObjectStringItem(subItem, "IF", interface, sizeof(interface))) {
                CONN_LOGW(CONN_WIFI_DIRECT, "get if failed");
                continue;
            }

            struct CombinationEntry *entry = SoftBusMalloc(sizeof(*entry));
            if (entry == NULL) {
                CONN_LOGE(CONN_WIFI_DIRECT, "malloc entry failed");
                continue;
            }

            ListInit(&entry->node);
            if (strcpy_s(entry->interface, sizeof(entry->interface), interface) != EOK) {
                CONN_LOGW(CONN_WIFI_DIRECT, "copy interface failed");
                SoftBusFree(entry);
                entry = NULL;
                continue;
            }
            ListTailInsert(&head->subList, &entry->node);
        }

        ListTailInsert(&self->rulesList, &head->node);
    }

    ShowRulesList(&self->rulesList);
    cJSON_Delete(coexistObj);
    return SOFTBUS_OK;
}

static bool RuleContainsAll(struct CombinationHead *rule, ListNode *combinations)
{
    struct CombinationEntry *entry = NULL;
    LIST_FOR_EACH_ENTRY(entry, combinations, struct CombinationEntry, node) {
        bool contain = false;
        struct CombinationEntry *ruleEntry = NULL;
        LIST_FOR_EACH_ENTRY(ruleEntry, &rule->subList, struct CombinationEntry, node) {
            if (strcmp(entry->interface, ruleEntry->interface) == 0) {
                contain = true;
                break;
            }
        }

        if (!contain) {
            return false;
        }
    }

    return true;
}

static void ShowCombinations(ListNode *combinations)
{
    int32_t pos = 0;
    char buffer[RULE_BUFFER_LEN] = {0};
    struct CombinationEntry *entry = NULL;
    LIST_FOR_EACH_ENTRY(entry, combinations, struct CombinationEntry, node) {
        int32_t ret = sprintf_s(buffer + pos, sizeof(buffer) - pos, " %s", entry->interface);
        if (ret > 0) {
            pos += ret;
        }
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "buffer=%{public}s", buffer);
}

static bool RecoverCoexistRule(void)
{
    char *coexistCap = NULL;
    int32_t ret = GetWifiDirectP2pAdapter()->getInterfaceCoexistCap(&coexistCap);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get interface coexist cap failed");

    if (coexistCap == NULL || strlen(coexistCap) == 0) {
        CONN_LOGW(CONN_WIFI_DIRECT, "coexistCap is empty");
        GetWifiDirectCoexistRule()->bypass = true;
        return true;
    }

    if (GetWifiDirectCoexistRule()->setCoexistRule(coexistCap) != SOFTBUS_OK) {
        SoftBusFree(coexistCap);
        return false;
    }

    SoftBusFree(coexistCap);
    return true;
}

static bool IsCombinationAvailable(ListNode *combinations)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();

    if (self->bypass) {
        return true;
    }

    struct CombinationHead *rule = NULL;
    LIST_FOR_EACH_ENTRY(rule, &self->rulesList, struct CombinationHead, node) {
        if (RuleContainsAll(rule, combinations)) {
            return true;
        }
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "conflict coexist rules");
    ShowRulesList(&self->rulesList);
    ShowCombinations(combinations);

    if (IsListEmpty(&self->rulesList)) {
        CONN_LOGW(CONN_WIFI_DIRECT, "rule list empty");
        if (!RecoverCoexistRule()) {
            CONN_LOGE(CONN_WIFI_DIRECT, "recover coexist rule failed");
            return false;
        }
        CONN_LOGI(CONN_WIFI_DIRECT, "recover coexist rule success");
        return IsCombinationAvailable(combinations);
    }

    return false;
}

static struct WifiDirectCoexistRule g_coexistRule = {
    .setBypass = SetBypass,
    .setCoexistRule = SetCoexistRule,
    .isCombinationAvailable = IsCombinationAvailable,
    .bypass = false,
    .rulesList = { &g_coexistRule.rulesList, &g_coexistRule.rulesList },
};

struct WifiDirectCoexistRule* GetWifiDirectCoexistRule(void)
{
    return &g_coexistRule;
}