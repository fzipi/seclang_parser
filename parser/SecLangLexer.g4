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

lexer grammar SecLangLexer;

tokens {
	QUOTE, SINGLE_QUOTE, EQUAL, COLON, EQUALS_PLUS, EQUALS_MINUS, COMMA, PIPE, CONFIG_VALUE_PATH
}

WS
   : ([ \t\r\n]+ | '\\' '\n' | '\\')  -> skip 
   ;

COMMENT
   : ('#' .*? '\r'? '\n')+ '\n'?
   ;

SPACE
    : ' '
    ;

PIPE_DEFAULT
    : '|' -> type(PIPE)
    ;

PLUS
   : '+'
   ;

MINUS
   : '-'
   ;

STAR
   : '*'
   ;

SLASH
   : '/'
   ;

ASSIGN
   : ':='
   ;

COMMA_DEFAULT
   : ',' -> type(COMMA)
   ;

SEMI
   : ';'
   ;

COLON_DEFAULT
   : ':' -> type(COLON)
   ;

EQUAL_DEFAULT
   : '=' -> type(EQUAL)
   ;

EQUALS_PLUS_DEFAULT
	: EQUAL_DEFAULT '+' -> type(EQUALS_PLUS)
	;

EQUALS_MINUS_DEFAULT
	: EQUAL_DEFAULT '-' -> type(EQUALS_MINUS)
	;

NOT_EQUAL
   : '<>'
   ;

NOT
    : '!'
    ;

LT
   : '<'
   ;

LE
   : '<='
   ;

GE
   : '>='
   ;

GT
   : '>'
   ;

LPAREN
   : '('
   ;

RPAREN
   : ')'
   ;

// MODSEC CONFIG
ACTION_ACCURACY
	: 'accuracy'
	; 
	
ACTION_ALLOW
	: 'allow:' ('REQUEST'|'PHASE') | ('phase:' ('REQUEST|PHASE') | 'allow')
	;

ACTION_APPEND
	: 'append'
	;

ACTION_AUDIT_LOG
	: 'auditlog'
	;

ACTION_BLOCK
	: 'block'
	;

ACTION_CAPTURE
	: 'capture'
	;

ACTION_CHAIN
	: 'chain'
	;

ACTION_CTL
    : 'ctl'
    ;

ACTION_CTL_AUDIT_ENGINE
	: 'auditEngine'
	;

ACTION_CTL_AUDIT_LOG_PARTS
	: 'auditLogParts'
	;

ACTION_CTL_REQUEST_BODY_PROCESSOR
	: 'requestBodyProcessor' -> pushMode(BODY_PROCESSOR_MODE)
	;

ACTION_CTL_FORCE_REQ_BODY_VAR
	: 'forceRequestBodyVariable'
	;

ACTION_CTL_REQUEST_BODY_ACCESS
	: 'requestBodyAccess'
	;

ACTION_CTL_RULE_ENGINE
	: 'ruleEngine'
	;

ACTION_CTL_RULE_REMOVE_BY_TAG
	: 'ruleRemoveByTag'
	;

ACTION_CTL_RULE_REMOVE_BY_ID
	: 'ruleRemoveById'
	;

ACTION_CTL_RULE_REMOVE_TARGET_BY_ID
	: 'ruleRemoveTargetById'
	;

ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG
	: 'ruleRemoveTargetByTag'
	;

ACTION_DENY
	: 'deny'
	;

ACTION_DEPRECATE_VAR
	: 'deprecatevar'
	;

ACTION_DROP
	: 'drop'
	;

ACTION_EXEC
	: 'exec'
	;

ACTION_EXPIRE_VAR
	: 'expirevar'
	;

ACTION_ID
	: 'id'
	;

ACTION_INITCOL
	: 'initcol' -> pushMode(COMMA_SEPARATED_STRING_MODE)
	;

ACTION_LOG_DATA
	: 'logdata'
	;

ACTION_LOG
	: 'log'
	;

ACTION_MATURITY
	: 'maturity'
	;

ACTION_MSG
	: 'msg'
	;

ACTION_MULTI_MATCH
	: 'multiMatch'
	;

ACTION_NO_AUDIT_LOG
	: 'noauditlog'
	;

ACTION_NO_LOG
	: 'nolog'
	;

ACTION_PASS
	: 'pass'
	;

ACTION_PAUSE
	: 'pause'
	;

ACTION_PHASE
	: 'phase' //'(REQUEST|RESPONSE|LOGGING|[0-9]+)'
	;

ACTION_PREPEND
	: 'prepend'
	;

ACTION_PROXY
	: 'proxy'
	;

ACTION_REDIRECT
	: 'redirect'
	;

ACTION_REV
	: 'rev'
	;

ACTION_SANITISE_ARG
	: 'sanitiseArg'
	;

ACTION_SANITISE_MATCHED_BYTES
	: 'sanitiseMatchedBytes'
	;

ACTION_SANITISE_MATCHED
	: 'sanitiseMatched'
	;

ACTION_SANITISE_REQUEST_HEADER
	: 'sanitiseRequestHeader'
	;

ACTION_SANITISE_RESPONSE_HEADER
	: 'sanitiseResponseHeader'
	;

ACTION_SETENV
	: 'setenv'
	;

ACTION_SETRSC
	: 'setrsc'
	;

ACTION_SETSID
	: 'setsid'
	;

ACTION_SETUID
	: 'setuid'
	;

ACTION_SETVAR
	: 'setvar'
	;

ACTION_SEVERITY
	: 'severity'
	;

ACTION_SEVERITY_VALUE
	: ('EMERGENCY'|'ALERT'|'CRITICAL'|'ERROR'|'WARNING'|'NOTICE'|'INFO'|'DEBUG')
	;

ACTION_SKIP_AFTER
	: 'skipAfter'
	;

ACTION_SKIP
	: 'skip'
	;

ACTION_STATUS
	: 'status'
	;

ACTION_TAG
	: 'tag'
	;

ACTION_VER
	: 'ver'
	;

ACTION_XMLNS
	: 'xmlns'
	;

ACTION_TRANSFORMATION
	: 't'
	;

TRANSFORMATION_VALUE
	: 'base64Decode'
	| 'base64DecodeExt'
	| 'base64Encode'
	| 'cmdLine'
	| 'compressWhitespace'
	| 'escapeSeqDecode'
	| 'cssDecode'
	| 'hexEncode'
	| 'hexDecode'
	| 'htmlEntityDecode'
	| 'jsDecode'
	| 'length'
	| 'lowercase'
	| 'md5'
	| 'none'
	| 'normalisePath'|'normalizePath'
	| 'normalisePathWin'|'normalizePathWin'
	| 'parityEven7bit'
	| 'parityOdd7bit'
	| 'parityZero7bit'
	| 'removeComments'
	| 'removeCommentsChar'
	| 'removeNulls'
	| 'removeWhitespace'
	| 'replaceComments'
	| 'replaceNulls'
	| 'sha1'
	| 'sqlHexDecode'
	| 'trim'
	| 'trimLeft'
	| 'trimRight'
	| 'uppercase'
	| 'urlEncode'
	| 'urlDecode'
	| 'urlDecodeUni'
	| 'utf8toUnicode'
	;

COLLECTION_NAME_ENUM:
	('ARGS'
	| 'ARGS_GET'
	| 'ARGS_GET_NAMES'
	| 'ARGS_NAMES'
	| 'ARGS_POST_NAMES'
	| 'ARGS_POST'
	| 'ENV'
	| 'FILES'
	| 'GEO'
	| 'GLOBAL'
	| 'IP'
	| 'MATCHED_VARS_NAMES'
	| 'MATCHED_VARS'
	| 'MULTIPART_PART_HEADERS'
	| 'PERF_RULES'
	| 'REQUEST_COOKIES_NAMES'
	| 'REQUEST_COOKIES'
	| 'REQUEST_HEADERS_NAMES'
	| 'REQUEST_HEADERS'
	| 'RESPONSE_HEADERS_NAMES'
	| 'RESPONSE_HEADERS'
	| 'RULE'
	| 'SESSION'
	| 'TX') -> pushMode (COLLECTION_FOUND)
	;

VARIABLE_NAME_ENUM:
    ('ARGS_COMBINED_SIZE'
	| 'AUTH_TYPE'
	| 'DURATION'
	| 'FILES_COMBINED_SIZE'
	| 'FILES_NAMES'
	| 'FILES_SIZES'
	| 'FILES_TMP_CONTENT'
	| 'FILES_TMPNAMES'
	| 'FULL_REQUEST'
	| 'FULL_REQUEST_LENGTH'
	| 'GEO'
	| 'HIGHEST_SEVERITY'
	| 'INBOUND_DATA_ERROR'
	| 'MATCHED_VAR'
	| 'MATCHED_VAR_NAME'
	| 'MODSEC_BUILD'
	| 'MSC_PCRE_LIMITS_EXCEEDED'
	| 'MULTIPART_CRLF_LF_LINES'
	| 'MULTIPART_FILENAME'
	| 'MULTIPART_NAME'
	| 'MULTIPART_STRICT_ERROR'
	| 'MULTIPART_UNMATCHED_BOUNDARY'
	| 'OUTBOUND_DATA_ERROR'
	| 'PATH_INFO'
	| 'PERF_ALL'
	| 'PERF_COMBINED'
	| 'PERF_GC'
	| 'PERF_LOGGING'
	| 'PERF_PHASE1'
	| 'PERF_PHASE2'
	| 'PERF_PHASE3'
	| 'PERF_PHASE4'
	| 'PERF_PHASE5'
	| 'PERF_SREAD'
	| 'PERF_SWRITE'
	| 'QUERY_STRING'
	| 'REMOTE_ADDR'
	| 'REMOTE_HOST'
	| 'REMOTE_PORT'
	| 'REMOTE_USER'
	| 'REQBODY_ERROR'
	| 'REQBODY_ERROR_MSG'
	| 'REQBODY_PROCESSOR'
	| 'REQUEST_BASENAME'
	| 'REQUEST_BODY'
	| 'REQUEST_BODY_LENGTH'
	| 'REQUEST_FILENAME'
	| 'REQUEST_LINE'
	| 'REQUEST_METHOD'
	| 'REQUEST_PROTOCOL'
	| 'REQUEST_URI'
	| 'REQUEST_URI_RAW'
	| 'RESPONSE_BODY'
	| 'RESPONSE_CONTENT_LENGTH'
	| 'RESPONSE_CONTENT_TYPE'
	| 'RESPONSE_PROTOCOL'
	| 'RESPONSE_STATUS'
	| 'RESOURCE'
	| 'SCRIPT_BASENAME'
	| 'SCRIPT_FILENAME'
	| 'SCRIPT_GID'
	| 'SCRIPT_GROUPNAME'
	| 'SCRIPT_MODE'
	| 'SCRIPT_UID'
	| 'SCRIPT_USERNAME'
	| 'SDBM_DELETE_ERROR'
	| 'SERVER_ADDR'
	| 'SERVER_NAME'
	| 'SERVER_PORT'
	| 'SESSIONID'
	| 'STATUS_LINE'
	| 'STREAM_INPUT_BODY'
	| 'STREAM_OUTPUT_BODY'
	| 'TIME'
	| 'TIME_DAY'
	| 'TIME_EPOCH'
	| 'TIME_HOUR'
	| 'TIME_MIN'
	| 'TIME_MON'
	| 'TIME_SEC'
	| 'TIME_WDAY'
	| 'TIME_YEAR'
	| 'UNIQUE_ID'
	| 'URLENCODED_ERROR'
	| 'USER'
	| 'USERAGENT_IP'
	| 'USERID'
	| 'WEBAPPID'
	| 'WEBSERVER_ERROR_LOG') -> pushMode(VARIABLE_FOUND)
	;

UNKNOWN_VARIABLES:
	('MSC_PCRE_ERROR'
	| 'MULTIPART_BOUNDARY_QUOTED'
	| 'MULTIPART_BOUNDARY_WHITESPACE'
	| 'MULTIPART_DATA_AFTER'
	| 'MULTIPART_DATA_BEFORE'
	| 'MULTIPART_FILE_LIMIT_EXCEEDED'
	| 'MULTIPART_HEADER_FOLDING'
	| 'MULTIPART_INVALID_HEADER_FOLDING'
	| 'MULTIPART_INVALID_PART'
	| 'MULTIPART_INVALID_QUOTING'
	| 'MULTIPART_LF_LINE'
	| 'MULTIPART_MISSING_SEMICOLON'
	| 'MULTIPART_SEMICOLON_MISSING'
	| 'REQBODY_PROCESSOR_ERROR'
	| 'REQBODY_PROCESSOR_ERROR_MSG'
	| 'STATUS') -> pushMode(VARIABLE_FOUND)
	;

RUN_TIME_VAR_XML
	: 'XML' -> pushMode(COLLECTION_FOUND)
	;

VAR_COUNT
	: '&'
	;

OPERATOR_BEGINS_WITH
	: 'beginsWith' -> pushMode(STRING_VALUE)
	;

OPERATOR_CONTAINS
	: 'contains'  -> pushMode(STRING_VALUE)
	;

OPERATOR_CONTAINS_WORD
	: 'containsWord'  -> pushMode(STRING_VALUE)
	;

OPERATOR_DETECT_SQLI
	: 'detectSQLi'
	;

OPERATOR_DETECT_XSS
	: 'detectXSS'
	;

OPERATOR_ENDS_WITH
	: 'endsWith'  -> pushMode(STRING_VALUE)
	;

OPERATOR_EQ
	: 'eq'  -> pushMode(STRING_VALUE)
	;

OPERATOR_FUZZY_HASH
	: 'fuzzyHash' -> pushMode(STRING_VALUE)
	;

OPERATOR_GE
	: 'ge'  -> pushMode(STRING_VALUE)
	;

OPERATOR_GEOLOOKUP
	: 'geoLookup'
	;

OPERATOR_GSB_LOOKUP
	: 'gsbLookup'
	;

OPERATOR_GT
	: 'gt'  -> pushMode(STRING_VALUE)
	;

OPERATOR_INSPECT_FILE
	: 'inspectFile'  -> pushMode(STRING_VALUE)
	;

OPERATOR_IP_MATCH_FROM_FILE
	: ('ipMatchF'|'ipMatchFromFile')  -> pushMode(STRING_VALUE)
	;

OPERATOR_IP_MATCH
	: 'ipMatch'  -> pushMode(STRING_VALUE)
	;

OPERATOR_LE
	: 'le'  -> pushMode(STRING_VALUE)
	;

OPERATOR_LT
	: 'lt'  -> pushMode(STRING_VALUE)
	;

OPERATOR_PM_FROM_FILE
	: ('pmf'|'pmFromFile')  -> pushMode(STRING_VALUE)
	;

OPERATOR_PM
	: 'pm'  -> pushMode(STRING_VALUE)
	;

OPERATOR_RBL
	: 'rbl'  -> pushMode(STRING_VALUE)
	;

OPERATOR_RSUB
	: 'rsub'  -> pushMode(STRING_VALUE)
	;

OPERATOR_RX
	: 'rx'  -> pushMode(STRING_VALUE)
	;

OPERATOR_RX_GLOBAL
	: 'rxGlobal'  -> pushMode(STRING_VALUE)
	;

OPERATOR_STR_EQ
	: 'streq'  -> pushMode(STRING_VALUE)
	;

OPERATOR_STR_MATCH
	: 'strmatch'  -> pushMode(STRING_VALUE)
	;

OPERATOR_UNCONDITIONAL_MATCH
	: 'unconditionalMatch'
	;

OPERATOR_VALIDATE_BYTE_RANGE
	: 'validateByteRange'
	;

OPERATOR_VALIDATE_DTD
	: 'validateDTD'
	;

OPERATOR_VALIDATE_HASH
	: 'validateHash'
	;

OPERATOR_VALIDATE_SCHEMA
	: 'validateSchema'
	;

OPERATOR_VALIDATE_URL_ENCODING
	: 'validateUrlEncoding'
	;

OPERATOR_VALIDATE_UTF8_ENCODING
	: 'validateUtf8Encoding'
	;

OPERATOR_VERIFY_CC
	: 'verifyCC'
	;

OPERATOR_VERIFY_CPF
	: 'verifyCPF'
	;

OPERATOR_VERIFY_SSN
	: 'verifySSN'
	;

OPERATOR_VERIFY_SVNR
	: 'verifySVNR'
	;

OPERATOR_WITHIN
	: 'within' -> pushMode(STRING_VALUE)
	;

AUDIT_PARTS
	: [ABCDEFGHJKIZ]+
	;

CONFIG_COMPONENT_SIG
	: 'SecComponentSignature' -> pushMode(STRING_VALUE)
	;

CONFIG_SEC_SERVER_SIG
	: 'SecServerSignature' -> pushMode(STRING_VALUE)
	;

CONFIG_SEC_WEB_APP_ID
	: 'SecWebAppId'
	;

CONFIG_SEC_CACHE_TRANSFORMATIONS
	: 'SecCacheTransformations'
	;

CONFIG_SEC_CHROOT_DIR
	: 'SecChrootDir' -> pushMode(FILE_PATH)
	;

CONFIG_CONN_ENGINE
	: 'SecConnEngine'
	;

CONFIG_SEC_HASH_ENGINE
	: 'SecHashEngine'
	;

CONFIG_SEC_HASH_KEY
	: 'SecHashKey'
	;

CONFIG_SEC_HASH_PARAM
	: 'SecHashParam'
	;

CONFIG_SEC_HASH_METHOD_RX
	: 'SecHashMethodRx'
	;

CONFIG_SEC_HASH_METHOD_PM
	: 'SecHashMethodPm'
	;

CONFIG_CONTENT_INJECTION
	: 'SecContentInjection'
	;

CONFIG_SEC_ARGUMENT_SEPARATOR
	: 'SecArgumentSeparator'
	;

CONFIG_DIR_AUDIT_DIR
	: 'SecAuditLogStorageDir' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_AUDIT_DIR_MOD
	: 'SecAuditLogDirMode'
	;

CONFIG_DIR_AUDIT_ENG
	: 'SecAuditEngine'
	;

CONFIG_DIR_AUDIT_FILE_MODE
	: 'SecAuditLogFileMode'
	;

CONFIG_DIR_AUDIT_LOG2
	: 'SecAuditLog2' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_AUDIT_LOG
	: 'SecAuditLog' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_AUDIT_LOG_FMT
	: 'SecAuditLogFormat'
	;

CONFIG_DIR_AUDIT_LOG_P
	: 'SecAuditLogParts'
	;

CONFIG_DIR_AUDIT_STS
	: 'SecAuditLogRelevantStatus'
	;

CONFIG_DIR_AUDIT_TYPE
	: 'SecAuditLogType'
	;

CONFIG_DIR_DEBUG_LOG
	: 'SecDebugLog' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_DEBUG_LVL
	: 'SecDebugLogLevel'
	;

CONFIG_DIR_GEO_DB
	: 'SecGeoLookupDb' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_GSB_DB
	: 'SecGsbLookupDb' -> pushMode(FILE_PATH)
	;

CONFIG_SEC_GUARDIAN_LOG
	: 'SecGuardianLog' -> pushMode(FILE_PATH)
	;

CONFIG_SEC_INTERCEPT_ON_ERROR
	: 'SecInterceptOnError'
	;

CONFIG_SEC_CONN_R_STATE_LIMIT
	: 'SecConnReadStateLimit'
	;

CONFIG_SEC_CONN_W_STATE_LIMIT
	: 'SecConnWriteStateLimit'
	;

CONFIG_SEC_SENSOR_ID
	: 'SecSensorId'
	;

CONFIG_SEC_RULE_INHERITANCE
	: 'SecRuleInheritance'
	;

CONFIG_SEC_RULE_PERF_TIME
	: 'SecRulePerfTime'
	;

CONFIG_SEC_STREAM_IN_BODY_INSPECTION
	: 'SecStreamInBodyInspection'
	;

CONFIG_SEC_STREAM_OUT_BODY_INSPECTION
	: 'SecStreamOutBodyInspection'
	;

CONFIG_DIR_PCRE_MATCH_LIMIT
	: 'SecPcreMatchLimit'
	;

CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION
	: 'SecPcreMatchLimitRecursion'
	;

CONFIG_DIR_ARGS_LIMIT
	: 'SecArgumentsLimit'
	;

CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT
	: 'SecRequestBodyJsonDepthLimit'
	;

CONFIG_DIR_REQ_BODY
	: 'SecRequestBodyAccess'
	;

CONFIG_DIR_REQ_BODY_IN_MEMORY_LIMIT
	: 'SecRequestBodyInMemoryLimit'
	;

CONFIG_DIR_REQ_BODY_LIMIT
	: 'SecRequestBodyLimit'
	;

CONFIG_DIR_REQ_BODY_LIMIT_ACTION
	: 'SecRequestBodyLimitAction'
	;

CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT
	: 'SecRequestBodyNoFilesLimit'
	;

CONFIG_DIR_RES_BODY
	: 'SecResponseBodyAccess'
	;

CONFIG_DIR_RES_BODY_LIMIT
	: 'SecResponseBodyLimit'
	;

CONFIG_DIR_RES_BODY_LIMIT_ACTION
	: 'SecResponseBodyLimitAction'
	;

CONFIG_DIR_RULE_ENG
	: 'SecRuleEngine'
	;

CONFIG_DIR_SEC_ACTION
	: 'SecAction'
	;

CONFIG_DIR_SEC_DEFAULT_ACTION
	: 'SecDefaultAction'
	;

CONFIG_SEC_DISABLE_BACKEND_COMPRESS
	: 'SecDisableBackendCompression'
	;

CONFIG_DIR_SEC_MARKER
	: 'SecMarker' -> pushMode(STRING_VALUE)
	;

CONFIG_DIR_UNICODE_MAP_FILE
	: 'SecUnicodeMapFile' -> pushMode(FILE_PATH)
	;

CONFIG_INCLUDE
	: 'Include'
	;

CONFIG_SEC_COLLECTION_TIMEOUT
	: 'SecCollectionTimeout'
	;

CONFIG_SEC_HTTP_BLKEY
	: 'SecHttpBlKey'
	;

CONFIG_SEC_REMOTE_RULES
	: 'SecRemoteRules'
	;

CONFIG_SEC_REMOTE_RULES_FAIL_ACTION
	: 'SecRemoteRulesFailAction'
	;

CONFIG_SEC_RULE_REMOVE_BY_ID
	: 'SecRuleRemoveById' | 'SecRuleRemoveByID'
	;

CONFIG_SEC_RULE_REMOVE_BY_MSG
	: 'SecRuleRemoveByMsg'
	;

CONFIG_SEC_RULE_REMOVE_BY_TAG
	: 'SecRuleRemoveByTag'
	;

CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG
	: 'SecRuleUpdateTargetByTag' -> pushMode(STRING_VALUE)
	;

CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG
	: 'SecRuleUpdateTargetByMsg' -> pushMode(STRING_VALUE)
	;

CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID
	: 'SecRuleUpdateTargetById'
	;

CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID
	: 'SecRuleUpdateActionById'
	;

CONFIG_UPLOAD_KEEP_FILES
	: 'SecUploadKeepFiles'
	;

CONFIG_UPLOAD_SAVE_TMP_FILES
	: 'SecTmpSaveUploadedFiles'
	;

CONFIG_UPLOAD_DIR
	: 'SecUploadDir' -> pushMode(FILE_PATH)
	;

CONFIG_UPLOAD_FILE_LIMIT
	: 'SecUploadFileLimit'
	;

CONFIG_UPLOAD_FILE_MODE
	: 'SecUploadFileMode'
	;

CONFIG_VALUE_ABORT
	: 'Abort'
	;

CONFIG_VALUE_DETC
	: 'DetectionOnly'
	;

CONFIG_VALUE_HTTPS
	: 'https'
	;

CONFIG_VALUE_OFF
	: 'Off'
	;

CONFIG_VALUE_ON
	: 'On'
	;

CONFIG_VALUE_PARALLEL
	: 'Parallel'
	| 'Concurrent'
	;

CONFIG_VALUE_PROCESS_PARTIAL
	: 'ProcessPartial'
	;

CONFIG_VALUE_REJECT
	: 'Reject'
	;

CONFIG_VALUE_RELEVANT_ONLY
	: 'RelevantOnly'
	;

CONFIG_VALUE_SERIAL
	: 'Serial'
	;

CONFIG_VALUE_WARN
	: 'Warn'
	;

CONFIG_XML_EXTERNAL_ENTITY
	: 'SecXmlExternalEntity'
	;

CONFIG_DIR_RESPONSE_BODY_MP
	: 'SecResponseBodyMimeType'
	;

CONFIG_DIR_RESPONSE_BODY_MP_CLEAR
	: 'SecResponseBodyMimeTypesClear'
	;

CONFIG_DIR_SEC_COOKIE_FORMAT
	: 'SecCookieFormat'
	;

CONFIG_SEC_COOKIEV0_SEPARATOR
	: 'SecCookieV0Separator'
	;

CONFIG_DIR_SEC_DATA_DIR
	: 'SecDataDir' -> pushMode(FILE_PATH)
	;

CONFIG_DIR_SEC_STATUS_ENGINE
	: 'SecStatusEngine'
	;

CONFIG_DIR_SEC_TMP_DIR
	: 'SecTmpDir' -> pushMode(FILE_PATH)
	;

DIRECTIVE
	: 'SecRule'
	;

DIRECTIVE_SECRULESCRIPT
	: 'SecRuleScript' -> pushMode(FILE_PATH)
	;

OPTION_NAME
	: 'incremental'
	| 'maxitems'
	| 'minlen'
	| 'maxlen'
	;

SINGLE_QUOTE_BUT_SCAPED
	: '\\' '\''
	;

DOUBLE_SINGLE_QUOTE_BUT_SCAPED
	: '\\' '"'
	;

COMMA_BUT_SCAPED
	: '\\' ','
	;

//MACRO_VARIABLE
//	: '%{' VARIABLE_NAME '}'
//	;

//START_MACRO_VARIABLE
//	: '%{' -> pushMode(MACRO)
//	;

NATIVE
	: 'NATIVE'
	;

NEWLINE
	: '\r' '\n'
	;

SINGLE_QUOTE_DEFAULT
    : '\'' -> type(SINGLE_QUOTE), pushMode(SINGLE_QUOTE_STRING_MODE)
    ;

QUOTE_DEFAULT
    : '"' -> type(QUOTE)
    ;

VARIABLE_NAME:
    LETTER (LETTER | DIGIT | '_' | '.' | '-')*
    ;

IDENT
   : ('A' .. 'Z') ('A' .. 'Z' | DIGIT | '_')*
   ;

INT
   : DIGIT+
   ;

INT_RANGE
   : INT MINUS INT
   ;

DIGIT:
    '0' .. '9'
    ;

LETTER:
    'a' .. 'z' | 'A' .. 'Z'
    ;

DICT_ELEMENT_REGEXP
    : SLASH ~[ |\t\r\n/]+ SLASH?
    ;

mode OPERATOR_VALUES;

FREE_TEXT_QUOTE_MACRO_EXPANSION
    : ~([\\"] )+ -> popMode
    ;

mode STRING_VALUE;

QUOTE_STRING_MODE
    : '"' -> type(QUOTE)
    ;

WS_STRING_MODE
	: WS -> skip
	;

STRING
    : (('\\"') | ~([" ])) (('\\"')|~('"'))* -> popMode
    ;

mode MACRO;

MACRO_EXPANSION
    : VARIABLE_NAME '}' -> popMode
	;

mode SETVAR;

SINGLE_QUOTE_SETVAR
    : '\'' -> type(SINGLE_QUOTE)
    ;

COLLECTION_ELEMENT
    : ('t'|'T') ('x'|'X') '.' (LETTER) (LETTER | DIGIT | '_' | '-')* -> popMode
    ;

COLLECTION_WITH_MACRO
    : 'tx.' IDENT '{%' -> mode(MACRO)
    ;

VAR_ASSIGNMENT
	: ~('\''|' ')+ -> popMode
	;

EQUAL_SETVAR
	: '=' -> type(EQUAL)
	;

EQUALS_PLUS_SETVAR
	: EQUAL_SETVAR '+' -> type(EQUALS_PLUS)
	;

EQUALS_MINUS_SETVAR
	: EQUAL_SETVAR '-' -> type(EQUALS_MINUS)
	;


mode COMMA_SEPARATED_STRING_MODE;

COLON_COMMA_STRING
	: COLON_DEFAULT -> type(COLON)
	;


COMMA_SEPARATED_STRING
    : ~([:,"])+ -> popMode
    ;

mode FILE_PATH;

WS_FILE_PATH_MODE
	: WS -> skip
	;

FILE_PATH_QUOTE
	: '"' -> type(QUOTE), pushMode(QUOTED_FILE_PATH)
	;

CONFIG_VALUE_PATH_DEFAULT
	: ('/' | LETTER | DIGIT | '.' | '_' | '~' | '|' | '\\' | ':' | '-')+ -> type(CONFIG_VALUE_PATH), popMode
	;

mode QUOTED_FILE_PATH;

CONFIG_VALUE_PATH_DEFAULT_QUOTED
	: CONFIG_VALUE_PATH_DEFAULT -> type(CONFIG_VALUE_PATH)
	;

FILE_PATH_CLOSE_QUOTE
	: '"' -> type(QUOTE), pushMode(DEFAULT_MODE)
	;

mode XPATH;

COLON_XPATH
	: ':' -> type(COLON)
	;

XPATH_EXPRESSION
	: ~[ :|\n\t",] ~[ |\n\t,"]* -> popMode
	;

XPATH_MODE_POP_CHARS
	: [ \n\t] -> popMode
	;

mode BODY_PROCESSOR_MODE;

EQUAL_BODY_PROCESSOR
	: '=' -> type(EQUAL)
	;

ACTION_CTL_BODY_PROCESSOR_TYPE
    : ('JSON' | 'URLENCODED' | 'XML') -> popMode
	;

mode SINGLE_QUOTE_STRING_MODE;

STRING_LITERAL
   : ('\\\'' | ~ ('\''))+
   ;

SINGLE_QUOTE_SINGLE_QUOTE_STRING_MODE
	: '\'' -> type(SINGLE_QUOTE), popMode
	;

mode COLLECTION_FOUND;

COLON_COLLECTION
	: ':' -> type(COLON), pushMode(COLLECTION_ELEMENT_MODE)
	;

SPACE_COL
	: ' ' -> skip, pushMode(OPERATOR_START_MODE)
	;

COMMA_COL 
	: ',' -> type(COMMA), popMode
	;

QUOTE_COL 
	: '"' -> type(QUOTE), popMode
	;

PIPE_COL
	: '|' -> type(PIPE), popMode
	;

mode VARIABLE_FOUND;

SPACE_VAR
	: ' ' -> skip, pushMode(OPERATOR_START_MODE)
	;

COMMA_VAR 
	: ',' -> type(COMMA), popMode
	;

QUOTE_VAR 
	: '"' -> type(QUOTE), popMode
	;

PIPE_VAR
	: '|' -> type(PIPE), popMode
	;

mode COLLECTION_ELEMENT_MODE;

COLLECTION_ELEMENT_VALUE
	: ~[ |",\n] ~[ |",\n]*
	;

SPACE_COL_ELEM
	: ' ' -> skip, pushMode(OPERATOR_START_MODE)
	;

NEWLINE_COL_ELEM
	: '\n' -> skip, pushMode(DEFAULT_MODE)
	;

COMMA_COL_ELEM
	: ',' -> type(COMMA), pushMode(DEFAULT_MODE)
	;

QUOTE_COL_ELEM
	: '"' -> type(QUOTE), pushMode(DEFAULT_MODE)
	;

PIPE_COL_ELEM
	: '|' -> type(PIPE), pushMode(DEFAULT_MODE)
	;

mode OPERATOR_START_MODE;

SKIP_CHARS
   : [\\\t\r\n ]+  -> skip 
   ;

QUOTE_OP 
	: '"' -> type(QUOTE), pushMode(OPERATOR_WITH_QUOTES)
	;

OPERATOR_UNQUOTED_STRING
    : (('\\"') | ~([" ])) (('\\"')|~[" ])* -> pushMode(DEFAULT_MODE)
    ;

mode OPERATOR_WITH_QUOTES;

AT
   : '@' -> pushMode(DEFAULT_MODE)
   ;

OPERATOR_QUOTED_STRING
    : (('\\"') | ~([" @])) (('\\"')|~('"'))* -> pushMode(DEFAULT_MODE)
    ;

