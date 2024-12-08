/*

Copyright (c) 2023 Felipe Zipitria <felipe.zipitria@owasp.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

parser grammar SecLangParser;

options { tokenVocab=SecLangLexer; }

configuration
     : stmt* EOF
     ;

stmt:
    comment? rules_directive variables operator actions?
    | comment? rule_script_directive file_path actions?
    | comment? rule_script_directive QUOTE file_path QUOTE actions?
    | comment? remove_rules values+
    | comment? remove_rules QUOTE values QUOTE
    | comment? update_target_rules update_target_rules_values update_variables
    | comment? update_action_rule id actions
    | comment? engine_config_directive
    | comment;

comment:
    COMMENT
    ;

rules_directive:
    DIRECTIVE
    ;

engine_config_directive:
    stmt_audit_log
    | engine_config_action_directive actions
    | string_engine_config_directive QUOTE values QUOTE
    | sec_marker_directive QUOTE values QUOTE
    | engine_config_directive_with_param values
    | engine_config_sec_cache_transformations values option_list
    ;

string_engine_config_directive:
    | CONFIG_COMPONENT_SIG
    | CONFIG_SEC_SERVER_SIG
    | CONFIG_SEC_WEB_APP_ID
    ;

sec_marker_directive:
    CONFIG_DIR_SEC_MARKER
    ;

engine_config_directive_with_param:
    CONFIG_CONN_ENGINE
    | CONFIG_CONTENT_INJECTION
    | CONFIG_DIR_ARGS_LIMIT
    | CONFIG_DIR_DEBUG_LOG
    | CONFIG_DIR_DEBUG_LVL
    | CONFIG_DIR_GEO_DB
    | CONFIG_DIR_GSB_DB
    | CONFIG_DIR_PCRE_MATCH_LIMIT
    | CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION
    | CONFIG_DIR_REQ_BODY
    | CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT
    | CONFIG_DIR_REQ_BODY_LIMIT
    | CONFIG_DIR_REQ_BODY_LIMIT_ACTION
    | CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT
    | CONFIG_DIR_RESPONSE_BODY_MP
    | CONFIG_DIR_RESPONSE_BODY_MP_CLEAR
    | CONFIG_DIR_RES_BODY
    | CONFIG_DIR_RES_BODY_LIMIT
    | CONFIG_DIR_RES_BODY_LIMIT_ACTION
    | CONFIG_DIR_RULE_ENG
    | CONFIG_DIR_SEC_COOKIE_FORMAT
    | CONFIG_DIR_SEC_DATA_DIR
    | CONFIG_DIR_SEC_STATUS_ENGINE
    | CONFIG_DIR_SEC_TMP_DIR
    | CONFIG_DIR_UNICODE_MAP_FILE
    | CONFIG_SEC_ARGUMENT_SEPARATOR
    | CONFIG_SEC_CHROOT_DIR
    | CONFIG_SEC_COLLECTION_TIMEOUT
    | CONFIG_SEC_CONN_R_STATE_LIMIT
    | CONFIG_SEC_CONN_W_STATE_LIMIT
    | CONFIG_SEC_COOKIEV0_SEPARATOR
    | CONFIG_SEC_DISABLE_BACKEND_COMPRESS
    | CONFIG_SEC_GUARDIAN_LOG
    | CONFIG_SEC_HASH_ENGINE
    | CONFIG_SEC_HASH_KEY
    | CONFIG_SEC_HASH_METHOD_PM
    | CONFIG_SEC_HASH_METHOD_RX
    | CONFIG_SEC_HASH_PARAM
    | CONFIG_SEC_HTTP_BLKEY
    | CONFIG_SEC_INTERCEPT_ON_ERROR
    | CONFIG_SEC_REMOTE_RULES_FAIL_ACTION
    | CONFIG_SEC_RULE_INHERITANCE
    | CONFIG_SEC_RULE_PERF_TIME
    | CONFIG_SEC_SENSOR_ID
    | CONFIG_SEC_STREAM_IN_BODY_INSPECTION
    | CONFIG_SEC_STREAM_OUT_BODY_INSPECTION
    | CONFIG_XML_EXTERNAL_ENTITY
    ;

rule_script_directive:
    DIRECTIVE_SECRULESCRIPT
    ;

file_path:
    CONFIG_VALUE_PATH
    ;

remove_rules:
    CONFIG_SEC_RULE_REMOVE_BY_ID
    | CONFIG_SEC_RULE_REMOVE_BY_MSG
    | CONFIG_SEC_RULE_REMOVE_BY_TAG
    ;

update_target_rules:
    CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID
    | CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG
    | CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG
    ;

update_action_rule:
    CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID
    ;

id:
    INT
    ;


engine_config_sec_cache_transformations:
    CONFIG_SEC_CACHE_TRANSFORMATIONS
    ;

option_list:
    QUOTE option (COMMA option)* QUOTE
    ;

option:
    option_name COLON values
    ;

option_name:
    OPTION_NAME
    ;

engine_config_action_directive:
    CONFIG_DIR_SEC_ACTION # config_dir_sec_action
    | CONFIG_DIR_SEC_DEFAULT_ACTION # config_dir_sec_default_action
    ;

stmt_audit_log:
    CONFIG_DIR_AUDIT_DIR_MOD
    | CONFIG_DIR_AUDIT_DIR
    | CONFIG_DIR_AUDIT_ENG
    | CONFIG_DIR_AUDIT_FILE_MODE
    | CONFIG_DIR_AUDIT_LOG2
    | CONFIG_DIR_AUDIT_LOG_P
    | CONFIG_DIR_AUDIT_LOG
    | CONFIG_DIR_AUDIT_LOG_FMT
    | CONFIG_DIR_AUDIT_STS
    | CONFIG_DIR_AUDIT_TYPE
    | CONFIG_UPLOAD_KEEP_FILES
    | CONFIG_UPLOAD_FILE_LIMIT
    | CONFIG_UPLOAD_FILE_MODE
    | CONFIG_UPLOAD_DIR
    | CONFIG_UPLOAD_SAVE_TMP_FILES
    | INT
    ;

values:
    INT
    | INT_RANGE
    | CONFIG_VALUE_ON
    | CONFIG_VALUE_OFF
    | CONFIG_VALUE_SERIAL
    | CONFIG_VALUE_PARALLEL
    | CONFIG_VALUE_HTTPS
    | CONFIG_VALUE_RELEVANT_ONLY
    | NATIVE
    | CONFIG_VALUE_ABORT
    | CONFIG_VALUE_WARN
    | CONFIG_VALUE_DETC
    | CONFIG_VALUE_PROCESS_PARTIAL
    | CONFIG_VALUE_REJECT
    | CONFIG_VALUE_PATH
    | STRING
    | VARIABLE_NAME
    | VAR_ASSIGNMENT
    | COMMA_SEPARATED_STRING
    | ACTION_CTL_BODY_PROCESSOR_TYPE
    | AUDIT_PARTS
    | action_ctl_target_value
    ;

action_ctl_target_value:
    (INT | IDENT | SINGLE_QUOTE string_literal SINGLE_QUOTE | VARIABLE_NAME) SEMI variable_enum (COLON variable_value)?
    ;

update_target_rules_values:
    INT
    | INT_RANGE
    | STRING
    ;

operator:
    QUOTE NOT? AT operator_name operator_value? QUOTE
    | QUOTE operator_value QUOTE
    | operator_value
    ;

operator_name:
    OPERATOR_UNCONDITIONAL_MATCH
    | OPERATOR_DETECT_SQLI
    | OPERATOR_DETECT_XSS
    | OPERATOR_VALIDATE_URL_ENCODING
    | OPERATOR_VALIDATE_UTF8_ENCODING
    | OPERATOR_INSPECT_FILE
    | OPERATOR_FUZZY_HASH
    | OPERATOR_VALIDATE_BYTE_RANGE
    | OPERATOR_VALIDATE_DTD
    | OPERATOR_VALIDATE_HASH
    | OPERATOR_VALIDATE_SCHEMA
    | OPERATOR_VERIFY_CC
    | OPERATOR_VERIFY_CPF
    | OPERATOR_VERIFY_SSN
    | OPERATOR_VERIFY_SVNR
    | OPERATOR_GSB_LOOKUP
    | OPERATOR_RSUB
    | OPERATOR_WITHIN
    | OPERATOR_CONTAINS_WORD
    | OPERATOR_CONTAINS
    | OPERATOR_ENDS_WITH
    | OPERATOR_EQ
    | OPERATOR_GE
    | OPERATOR_GT
    | OPERATOR_IP_MATCH_FROM_FILE
    | OPERATOR_IP_MATCH
    | OPERATOR_LE
    | OPERATOR_LT
    | OPERATOR_PM_FROM_FILE
    | OPERATOR_PM
    | OPERATOR_RBL
    | OPERATOR_RX
    | OPERATOR_RX_GLOBAL
    | OPERATOR_STR_EQ
    | OPERATOR_STR_MATCH
    | OPERATOR_BEGINS_WITH
    | OPERATOR_GEOLOOKUP
    ;

operator_value:
    variable_enum
    | STRING
    | (INT | INT_RANGE) (COMMA (INT | INT_RANGE))*
    | OPERATOR_UNQUOTED_STRING
    | OPERATOR_QUOTED_STRING
    ;

variables:
    QUOTE? NOT? VAR_COUNT? var_stmt QUOTE? (PIPE QUOTE? NOT? var_stmt QUOTE?)*
    ;

update_variables:
    QUOTE? NOT? VAR_COUNT? var_stmt QUOTE? (COMMA QUOTE? NOT? var_stmt QUOTE?)*
    ;

var_stmt:
    variable_enum (COLON variable_value)?
    ;

variable_enum:
    VARIABLE_NAME_ENUM
    | COLLECTION_NAME_ENUM
    | UNKNOWN_VARIABLES
    | RUN_TIME_VAR_XML
    ;

actions:
    QUOTE action (COMMA action)* QUOTE
    ;

action:
    action_with_params COLON NOT? EQUAL? action_value
    | action_with_params COLON action_value
    | action_only
    ;

action_only:
    disruptive_action_only
    | non_disruptive_action_only
    | flow_action_only
    | ACTION_TRANSFORMATION COLON transformation_action_value
    ;

disruptive_action_only:
    ACTION_ALLOW
    | ACTION_BLOCK
    | ACTION_DENY
    | ACTION_DROP
    | ACTION_PASS
    | ACTION_PAUSE
    ;

non_disruptive_action_only:
    ACTION_AUDIT_LOG
    | ACTION_CAPTURE
    | ACTION_SANITISE_MATCHED
    | ACTION_LOG
    | ACTION_MULTI_MATCH
    | ACTION_NO_AUDIT_LOG
    | ACTION_NO_LOG
    ;

flow_action_only:
    ACTION_CHAIN
    ;

action_with_params:
    metadata_action_with_params
    | disruptive_action_with_params
    | non_disruptive_action_with_params
    | flow_action_with_params
    | data_action_with_params
    ;

metadata_action_with_params:
    ACTION_PHASE # ACTION_PHASE
    | ACTION_ID # ACTION_ID
    | ACTION_MATURITY # ACTION_MATURITY
    | ACTION_MSG # ACTION_MSG
    | ACTION_REV # ACTION_REV
    | ACTION_SEVERITY # ACTION_SEVERITY
    | ACTION_TAG # ACTION_TAG
    | ACTION_VER # ACTION_VER
    ;

disruptive_action_with_params:
    ACTION_PROXY
    | ACTION_REDIRECT
    ;

non_disruptive_action_with_params:
    ACTION_APPEND
    | ACTION_CTL
    | ACTION_EXEC
    | ACTION_EXPIRE_VAR
    | ACTION_DEPRECATE_VAR
    | ACTION_INITCOL
    | ACTION_LOG_DATA
    | ACTION_PREPEND
    | ACTION_SANITISE_ARG
    | ACTION_SANITISE_MATCHED_BYTES
    | ACTION_SANITISE_REQUEST_HEADER
    | ACTION_SANITISE_RESPONSE_HEADER
    | ACTION_SETUID
    | ACTION_SETRSC
    | ACTION_SETSID
    | ACTION_SETENV
    | ACTION_SETVAR
    ;

data_action_with_params:
    ACTION_XMLNS
    | ACTION_STATUS
    ;

flow_action_with_params:
    ACTION_SKIP
    | ACTION_SKIP_AFTER
    ;

action_value:
    action_value_types
    | SINGLE_QUOTE string_literal SINGLE_QUOTE
    ;

action_value_types:
    INT
    | variable_value
    | setvar_action
    | ctl_action assignment values
    | VARIABLE_NAME
    | ACTION_SEVERITY_VALUE
    | FREE_TEXT_QUOTE_MACRO_EXPANSION
    | COMMA_SEPARATED_STRING
    ;

string_literal:
    STRING_LITERAL;

ctl_action:
    ACTION_CTL_FORCE_REQ_BODY_VAR
    | ACTION_CTL_REQUEST_BODY_ACCESS
    | ACTION_CTL_RULE_ENGINE
    | ACTION_CTL_RULE_REMOVE_BY_ID
    | ACTION_CTL_RULE_REMOVE_BY_TAG
    | ACTION_CTL_RULE_REMOVE_TARGET_BY_ID
    | ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG
    | ACTION_CTL_AUDIT_ENGINE
    | ACTION_CTL_AUDIT_LOG_PARTS
    | ACTION_CTL_REQUEST_BODY_PROCESSOR
    ;

transformation_action_value:
    TRANSFORMATION_VALUE
    ;

variable_value:
    | XPATH_EXPRESSION
    | COLLECTION_ELEMENT_VALUE
    ;

setvar_action:
    setvar_stmt assignment values
    ;

setvar_stmt:
    COLLECTION_ELEMENT
    | COLLECTION_WITH_MACRO
    | VARIABLE_NAME
    ;

assignment:
    EQUAL
    | EQUALS_PLUS
    | EQUALS_MINUS
    ;