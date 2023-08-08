/*
BSD License
Copyright (c) 2023 Felipe Zipitria
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of Tom Everett nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
Adapted from pascal.g by  Hakki Dogusan, Piet Schoutteten and Marton Papp
*/
lexer grammar SecLangLexer;

//options { superClass = SecLangLexerBase; }

WS
   : [ \t\r\n]+ -> skip
   ;

COMMENT
   : '#' .*? '\r'? '\n' {}
   ;

SPACE
    : ' '
    ;

PIPE
    : '|'
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

COMMA
   : ',' -> skip
   ;

SEMI
   : ';'
   ;

COLON
   : ':' -> skip
   ;

EQUAL
   : '='
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

AT
   : '@'
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

ACTION_CTL_AUDIT_ENGINE
	: 'ctl:auditEngine'
	;

ACTION_CTL_AUDIT_LOG_PARTS
	: 'ctl:auditLogParts'
	;

ACTION_CTL_BDY_JSON
	: 'ctl:requestBodyProcessor=JSON'
	;

ACTION_CTL_BDY_XML
	: 'ctl:requestBodyProcessor=XML'
	;

ACTION_CTL_BDY_URLENCODED
	: 'ctl:requestBodyProcessor=URLENCODED'
	;

ACTION_CTL_FORCE_REQ_BODY_VAR
	: 'ctl:forceRequestBodyVariable'
	;

ACTION_CTL_REQUEST_BODY_ACCESS
	: 'ctl:requestBodyAccess'
	;

ACTION_CTL_RULE_ENGINE
	: 'ctl:ruleEngine'
	;

ACTION_CTL_RULE_REMOVE_BY_TAG
	: 'ctl:ruleRemoveByTag'
	;

ACTION_CTL_RULE_REMOVE_BY_ID
	: 'ctl:ruleRemoveById'
	;

ACTION_CTL_RULE_REMOVE_TARGET_BY_ID
	: 'ctl:ruleRemoveTargetById'
	;

ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG
	: 'ctl:ruleRemoveTargetByTag'
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
	: 'id:' QUOTE_BUT_SCAPED? INT+ QUOTE_BUT_SCAPED?
	;

ACTION_INITCOL
	: 'initcol'
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
	: 'phase' //'(REQUEST|RESPONSE|LOGGING|[0-9]+)')
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
	: 'setvar' -> pushMode(VARS)
	;

ACTION_SEVERITY
	: 'severity'
	;

ACTION_SEVERITY_VALUE
	: '(EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG)|[0-9]+'
	;

ACTION_SKIP_AFTER
	: 'skipAfter'
	;

ACTION_SKIP
	: 'skip'
	;

ACTION_STATUS
	: 'status:[0-9]+'
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

ACTION_TRANSFORMATION_BASE_64_DECODE
	: 't:base64Decode'
	;

ACTION_TRANSFORMATION_BASE_64_DECODE_EXT
	: 't:base64DecodeExt'
	;

ACTION_TRANSFORMATION_BASE_64_ENCODE
	: 't:base64Encode'
	;

ACTION_TRANSFORMATION_CMD_LINE
	: 't:cmdLine'
	;

ACTION_TRANSFORMATION_COMPRESS_WHITESPACE
	: 't:compressWhitespace'
	;

ACTION_TRANSFORMATION_ESCAPE_SEQ_DECODE
	: 't:escapeSeqDecode'
	;

ACTION_TRANSFORMATION_CSS_DECODE
	: 't:cssDecode'
	;

ACTION_TRANSFORMATION_HEX_ENCODE
	: 't:hexEncode'
	;

ACTION_TRANSFORMATION_HEX_DECODE
	: 't:hexDecode'
	;

ACTION_TRANSFORMATION_HTML_ENTITY_DECODE
	: 't:htmlEntityDecode'
	;

ACTION_TRANSFORMATION_JS_DECODE
	: 't:jsDecode'
	;

ACTION_TRANSFORMATION_LENGTH
	: 't:length'
	;

ACTION_TRANSFORMATION_LOWERCASE
	: 't:lowercase'
	;

ACTION_TRANSFORMATION_MD5
	: 't:md5'
	;

ACTION_TRANSFORMATION_NONE
	: 't:none'
	;

ACTION_TRANSFORMATION_NORMALISE_PATH
	: 't:(normalisePath|normalizePath)'
	;

ACTION_TRANSFORMATION_NORMALISE_PATH_WIN
	: 't:(normalisePathWin|normalizePathWin)'
	;

ACTION_TRANSFORMATION_PARITY_EVEN_7_BIT
	: 't:parityEven7bit'
	;

ACTION_TRANSFORMATION_PARITY_ODD_7_BIT
	: 't:parityOdd7bit'
	;

ACTION_TRANSFORMATION_PARITY_ZERO_7_BIT
	: 't:parityZero7bit'
	;

ACTION_TRANSFORMATION_REMOVE_COMMENTS
	: 't:removeComments'
	;

ACTION_TRANSFORMATION_REMOVE_COMMENTS_CHAR
	: 't:removeCommentsChar'
	;

ACTION_TRANSFORMATION_REMOVE_NULLS
	: 't:removeNulls'
	;

ACTION_TRANSFORMATION_REMOVE_WHITESPACE
	: 't:removeWhitespace'
	;

ACTION_TRANSFORMATION_REPLACE_COMMENTS
	: 't:replaceComments'
	;

ACTION_TRANSFORMATION_REPLACE_NULLS
	: 't:replaceNulls'
	;

ACTION_TRANSFORMATION_SHA1
	: 't:sha1'
	;

ACTION_TRANSFORMATION_SQL_HEX_DECODE
	: 't:sqlHexDecode'
	;

ACTION_TRANSFORMATION_TRIM
	: 't:trim'
	;

ACTION_TRANSFORMATION_TRIM_LEFT
	: 't:trimLeft'
	;

ACTION_TRANSFORMATION_TRIM_RIGHT
	: 't:trimRight'
	;

ACTION_TRANSFORMATION_UPPERCASE
	: 't:uppercase'
	;

ACTION_TRANSFORMATION_URL_ENCODE
	: 't:urlEncode'
	;

ACTION_TRANSFORMATION_URL_DECODE
	: 't:urlDecode'
	;

ACTION_TRANSFORMATION_URL_DECODE_UNI
	: 't:urlDecodeUni'
	;

ACTION_TRANSFORMATION_UTF8_TO_UNICODE
	: 't:utf8toUnicode'
	;

VARIABLE_ARGS_COMBINED_SIZE
	: 'ARGS_COMBINED_SIZE'
	;

VARIABLE_ARGS_GET_NAMES
	: 'ARGS_GET_NAMES'
	;

VARIABLE_ARGS_NAMES
	: 'ARGS_NAMES'
	;

VARIABLE_ARGS_POST_NAMES
	: 'ARGS_POST_NAMES'
	;

VARIABLE_AUTH_TYPE
	: 'AUTH_TYPE'
	;

VARIABLE_FILES_COMBINED_SIZE
	: 'FILES_COMBINED_SIZE'
	;

VARIABLE_FILES_TMP_NAMES
	: 'FILES_TMPNAMES'
	;

VARIABLE_FULL_REQUEST
	: 'FULL_REQUEST'
	;

VARIABLE_FULL_REQUEST_LENGTH
	: 'FULL_REQUEST_LENGTH'
	;

VARIABLE_GLOBAL
	: 'GLOBAL'
	;

VARIABLE_INBOUND_DATA_ERROR
	: 'INBOUND_DATA_ERROR'
	;

VARIABLE_MATCHED_VAR
	: 'MATCHED_VAR'
	;

VARIABLE_MATCHED_VAR_NAME
	: 'MATCHED_VAR_NAME'
	;

VARIABLE_MSC_PCRE_ERROR
	: 'MSC_PCRE_ERROR'
	;

VARIABLE_MSC_PCRE_LIMITS_EXCEEDED
	: 'MSC_PCRE_LIMITS_EXCEEDED'
	;

VARIABLE_MULTIPART_BOUNDARY_QUOTED
	: 'MULTIPART_BOUNDARY_QUOTED'
	;

VARIABLE_MULTIPART_BOUNDARY_WHITESPACE
	: 'MULTIPART_BOUNDARY_WHITESPACE'
	;

VARIABLE_MULTIPART_CRLF_LF_LINES
	: 'MULTIPART_CRLF_LF_LINES'
	;

VARIABLE_MULTIPART_DATA_AFTER
	: 'MULTIPART_DATA_AFTER'
	;

VARIABLE_MULTIPART_DATA_BEFORE
	: 'MULTIPART_DATA_BEFORE'
	;

VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED
	: 'MULTIPART_FILE_LIMIT_EXCEEDED'
	;

VARIABLE_MULTIPART_FILENAME
	: 'MULTIPART_FILENAME'
	;

VARIABLE_MULTIPART_HEADER_FOLDING
	: 'MULTIPART_HEADER_FOLDING'
	;

VARIABLE_MULTIPART_INVALID_HEADER_FOLDING
	: 'MULTIPART_INVALID_HEADER_FOLDING'
	;

VARIABLE_MULTIPART_INVALID_PART
	: 'MULTIPART_INVALID_PART'
	;

VARIABLE_MULTIPART_INVALID_QUOTING
	: 'MULTIPART_INVALID_QUOTING'
	;

VARIABLE_MULTIPART_LF_LINE
	: 'MULTIPART_LF_LINE'
	;

VARIABLE_MULTIPART_MISSING_SEMICOLON
	: 'MULTIPART_MISSING_SEMICOLON'
	;

VARIABLE_MULTIPART_SEMICOLON_MISSING
	: 'MULTIPART_SEMICOLON_MISSING'
	;

VARIABLE_MULTIPART_NAME
	: 'MULTIPART_NAME'
	;

VARIABLE_MULTIPART_STRICT_ERROR
	: 'MULTIPART_STRICT_ERROR'
	;

VARIABLE_MULTIPART_UNMATCHED_BOUNDARY
	: 'MULTIPART_UNMATCHED_BOUNDARY'
	;

VARIABLE_OUTBOUND_DATA_ERROR
	: 'OUTBOUND_DATA_ERROR'
	;

VARIABLE_PATH_INFO
	: 'PATH_INFO'
	;

VARIABLE_QUERY_STRING
	: 'QUERY_STRING'
	;

VARIABLE_REMOTE_ADDR
	: 'REMOTE_ADDR'
	;

VARIABLE_REMOTE_HOST
	: 'REMOTE_HOST'
	;

VARIABLE_REMOTE_PORT
	: 'REMOTE_PORT'
	;

VARIABLE_REQBODY_ERROR
	: 'REQBODY_ERROR'
	;

VARIABLE_REQBODY_ERROR_MSG
	: 'REQBODY_ERROR_MSG'
	;

VARIABLE_REQBODY_PROCESSOR_ERROR
	: 'REQBODY_PROCESSOR_ERROR'
	;

VARIABLE_REQBODY_PROCESSOR_ERROR_MSG
	: 'REQBODY_PROCESSOR_ERROR_MSG'
	;

VARIABLE_REQBODY_PROCESSOR
	: 'REQBODY_PROCESSOR'
	;

VARIABLE_REQUEST_BASENAME
	: 'REQUEST_BASENAME'
	;

VARIABLE_REQUEST_BODY
	: 'REQUEST_BODY'
	;

VARIABLE_REQUEST_BODY_LENGTH
	: 'REQUEST_BODY_LENGTH'
	;

VARIABLE_REQUEST_FILE_NAME
	: 'REQUEST_FILENAME'
	;

VARIABLE_REQUEST_HEADERS_NAMES
	: 'REQUEST_HEADERS_NAMES'
	;

VARIABLE_REQUEST_LINE
	: 'REQUEST_LINE'
	;

VARIABLE_REQUEST_METHOD
	: 'REQUEST_METHOD'
	;

VARIABLE_REQUEST_PROTOCOL
	: 'REQUEST_PROTOCOL'
	;

VARIABLE_REQUEST_URI
	: 'REQUEST_URI'
	;

VARIABLE_REQUEST_URI_RAW
	: 'REQUEST_URI_RAW'
	;

VARIABLE_RESOURCE
	: 'RESOURCE'
	;

VARIABLE_RESPONSE_BODY
	: 'RESPONSE_BODY'
	;

VARIABLE_RESPONSE_CONTENT_LENGTH
	: 'RESPONSE_CONTENT_LENGTH'
	;

VARIABLE_RESPONSE_CONTENT_TYPE
	: 'RESPONSE_CONTENT_TYPE'
	;

VARIABLE_RESPONSE_HEADERS_NAMES
	: 'RESPONSE_HEADERS_NAMES'
	;

VARIABLE_RESPONSE_PROTOCOL
	: 'RESPONSE_PROTOCOL'
	;

VARIABLE_RESPONSE_STATUS
	: 'RESPONSE_STATUS'
	;

VARIABLE_SERVER_ADDR
	: 'SERVER_ADDR'
	;

VARIABLE_SERVER_NAME
	: 'SERVER_NAME'
	;

VARIABLE_SERVER_PORT
	: 'SERVER_PORT'
	;

VARIABLE_SESSION_ID
	: 'SESSIONID'
	;

VARIABLE_UNIQUE_ID
	: 'UNIQUE_ID'
	;

VARIABLE_URL_ENCODED_ERROR
	: 'URLENCODED_ERROR'
	;

VARIABLE_USER_ID
	: 'USERID'
	;

VARIABLE_WEBSERVER_ERROR_LOG
	: 'WEBSERVER_ERROR_LOG'
	;

VARIABLE_ARGS
	: 'ARGS'
	;

VARIABLE_ARGS_POST
	: 'ARGS_POST'
	;

VARIABLE_ARGS_GET
	: 'ARGS_GET'
	;

VARIABLE_FILES_SIZES
	: 'FILES_SIZES'
	;

VARIABLE_FILES_NAMES
	: 'FILES_NAMES'
	;

VARIABLE_FILES_TMP_CONTENT
	: 'FILES_TMP_CONTENT'
	;

VARIABLE_MATCHED_VARS_NAMES
	: 'MATCHED_VARS_NAMES'
	;

VARIABLE_MATCHED_VARS
	: 'MATCHED_VARS'
	;

VARIABLE_FILES
	: 'FILES'
	;

VARIABLE_REQUEST_COOKIES
	: 'REQUEST_COOKIES'
	;

VARIABLE_REQUEST_HEADERS
	: 'REQUEST_HEADERS'
	;

VARIABLE_RESPONSE_HEADERS
	: 'RESPONSE_HEADERS'
	;

VARIABLE_GEO
	: 'GEO'
	;

VARIABLE_REQUEST_COOKIES_NAMES
	: 'REQUEST_COOKIES_NAMES'
	;

VARIABLE_MULTIPART_PART_HEADERS
	: 'MULTIPART_PART_HEADERS'
	;

VARIABLE_RULE
	: 'RULE'
	;

VARIABLE_SESSION
	: '(SESSION)'
	;

VARIABLE_IP
	: '(IP)'
	;

VARIABLE_USER
	: '(USER)'
	;

VARIABLE_STATUS
	: '(STATUS)'
	;

VARIABLE_STATUS_LINE
	: '(STATUS_LINE)'
	;

VARIABLE_TX
	: 'TX'
	;

VARIABLE_WEB_APP_ID
	: 'WEBAPPID'
	;

RUN_TIME_VAR_BLD
	: 'MODSEC_BUILD'
	;

RUN_TIME_VAR_DUR
	: 'DURATION'
	;

RUN_TIME_VAR_ENV
	: 'ENV'
	;

RUN_TIME_VAR_HSV
	: 'HIGHEST_SEVERITY'
	;

RUN_TIME_VAR_REMOTE_USER
	: 'REMOTE_USER'
	;

RUN_TIME_VAR_TIME
	: 'TIME'
	;

RUN_TIME_VAR_TIME_DAY
	: 'TIME_DAY'
	;

RUN_TIME_VAR_TIME_EPOCH
	: 'TIME_EPOCH'
	;

RUN_TIME_VAR_TIME_HOUR
	: 'TIME_HOUR'
	;

RUN_TIME_VAR_TIME_MIN
	: 'TIME_MIN'
	;

RUN_TIME_VAR_TIME_MON
	: 'TIME_MON'
	;

RUN_TIME_VAR_TIME_SEC
	: 'TIME_SEC'
	;

RUN_TIME_VAR_TIME_WDAY
	: 'TIME_WDAY'
	;

RUN_TIME_VAR_TIME_YEAR
	: 'TIME_YEAR'
	;

RUN_TIME_VAR_XML
	: 'XML'
	;

VAR_COUNT
	: '&'
	;

OPERATOR_BEGINS_WITH
	: '@beginsWith'
	;

OPERATOR_CONTAINS
	: '@contains'
	;

OPERATOR_CONTAINS_WORD
	: '@containsWord'
	;

OPERATOR_DETECT_SQLI
	: '@detectSQLi'
	;

OPERATOR_DETECT_XSS
	: '@detectXSS'
	;

OPERATOR_ENDS_WITH
	: '@endsWith'
	;

OPERATOR_EQ
	: '@eq'
	;

OPERATOR_FUZZY_HASH
	: '@fuzzyHash'
	;

OPERATOR_GE
	: '@ge'
	;

OPERATOR_GEOLOOKUP
	: '@geoLookup'
	;

OPERATOR_GSB_LOOKUP
	: '@gsbLookup'
	;

OPERATOR_GT
	: '@gt'
	;

OPERATOR_INSPECT_FILE
	: '@inspectFile'
	;

OPERATOR_IP_MATCH_FROM_FILE
	: '(@ipMatchF|@ipMatchFromFile)'
	;

OPERATOR_IP_MATCH
	: '@ipMatch'
	;

OPERATOR_LE
	: '@le'
	;

OPERATOR_LT
	: '@lt'
	;

OPERATOR_PM_FROM_FILE
	: '(@pmf|@pmFromFile)'
	;

OPERATOR_PM
	: '@pm'
	;

OPERATOR_RBL
	: '@rbl'
	;

OPERATOR_RSUB
	: '@rsub'
	;

OPERATOR_RX
	: '@rx'
	;

OPERATOR_RX_GLOBAL
	: '@rxGlobal'
	;

OPERATOR_STR_EQ
	: '@streq'
	;

OPERATOR_STR_MATCH
	: '@strmatch'
	;

OPERATOR_UNCONDITIONAL_MATCH
	: '@unconditionalMatch'
	;

OPERATOR_VALIDATE_BYTE_RANGE
	: '@validateByteRange'
	;

OPERATOR_VALIDATE_DTD
	: '@validateDTD'
	;

OPERATOR_VALIDATE_HASH
	: '@validateHash'
	;

OPERATOR_VALIDATE_SCHEMA
	: '@validateSchema'
	;

OPERATOR_VALIDATE_URL_ENCODING
	: '@validateUrlEncoding'
	;

OPERATOR_VALIDATE_UTF8_ENCODING
	: '@validateUtf8Encoding'
	;

OPERATOR_VERIFY_CC
	: '@verifyCC'
	;

OPERATOR_VERIFY_CPF
	: '@verifyCPF'
	;

OPERATOR_VERIFY_SSN
	: '@verifySSN'
	;

OPERATOR_VERIFY_SVNR
	: '@verifySVNR'
	;

OPERATOR_WITHIN
	: '@within'
	;

AUDIT_PARTS
	: [ABCDEFGHJKIZ]+
	;

//COL_FREE_TEXT_SPACE_COMMA
//	: ([^,"])+
//	;

//COL_NAME
//	: [A-Za-z]+
//	;

CONFIG_COMPONENT_SIG
	: 'SecComponentSignature'
	;

CONFIG_SEC_SERVER_SIG
	: 'SecServerSignature'
	;

CONFIG_SEC_WEB_APP_ID
	: 'SecWebAppId'
	;

CONFIG_SEC_CACHE_TRANSFORMATIONS
	: 'SecCacheTransformations'
	;

CONFIG_SEC_CHROOT_DIR
	: 'SecChrootDir'
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
	: 'SecAuditLogStorageDir'
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
	: 'SecAuditLog2'
	;

CONFIG_DIR_AUDIT_LOG
	: 'SecAuditLog'
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
	: 'SecDebugLog'
	;

CONFIG_DIR_DEBUG_LVL
	: 'SecDebugLogLevel'
	;

CONFIG_DIR_GEO_DB
	: 'SecGeoLookupDb'
	;

CONFIG_DIR_GSB_DB
	: 'SecGsbLookupDb'
	;

CONFIG_SEC_GUARDIAN_LOG
	: 'SecGuardianLog'
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
	: 'SecMarker'
	;

CONFIG_DIR_UNICODE_MAP_FILE
	: 'SecUnicodeMapFile'
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
	: 'SecRuleRemoveById'
	;

CONFIG_SEC_RULE_REMOVE_BY_MSG
	: 'SecRuleRemoveByMsg'
	;

CONFIG_SEC_RULE_REMOVE_BY_TAG
	: 'SecRuleRemoveByTag'
	;

CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG
	: 'SecRuleUpdateTargetByTag'
	;

CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG
	: 'SecRuleUpdateTargetByMsg'
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
	: 'SecUploadDir'
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

//CONFIG_VALUE_NUMBER
//	: [0-9]+
//	;

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

CONFIG_VALUE_PATH
	: [-0-9A-Za-z_/.*:]+
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
	: 'SecDataDir'
	;

CONFIG_DIR_SEC_STATUS_ENGINE
	: 'SecStatusEngine'
	;

CONFIG_DIR_SEC_TMP_DIR
	: 'SecTmpDir'
	;

DIRECTIVE
	: 'SecRule'
	;

DIRECTIVE_SECRULESCRIPT
	: 'SecRuleScript'
	;

//FREE_TEXT_NEW_LINE
//	: ~ ["|\n]+
//	;

//FREE_TEXT_QUOTE
//	: (~['] | (~[\\]) )+
//	;

//ESC : '\\"' | '\\\\' ;

QUOTE_BUT_SCAPED
	: '\\' '\''
	;

DOUBLE_QUOTE_BUT_SCAPED
	: '\\' '"'
	;

COMMA_BUT_SCAPED
	: '\\' ','
	;

START_MACRO_VARIABLE
	: '%{' -> pushMode(MACRO)
	;

//FREE_TEXT_QUOTE_COMMA
//	: ~ [,']+
//	;

//FREE_TEXT_SPACE
//    : ~ [ \t]+
//	;

//FREE_TEXT_SPACE_COMMA
//    : ~ [, \t]+
//	;

//FREE_TEXT_SPACE_COMMA_QUOTE
//    : ~ [", \t\n\r]+
//	;

//FREE_TEXT_COMMA_QUOTE
//	: ~ [",\n\r]+
//	;

//NEW_LINE_FREE_TEXT
//    : ~ [", \t\n\r]+
//	;

//FREE_TEXT
//    : '"' ( DOUBLE_QUOTE_BUT_SCAPED | ~'"' )* '"'
//    ;

JSON
	: 'JSON'
	;

NATIVE
	: 'NATIVE'
	;

NEWLINE
	: [\n\r]+
	;

EQUALS_PLUS
	: EQUAL '+'
	;

EQUALS_MINUS
	: EQUAL '-'
	;

QUOTE
    : '\''
    ;

QUOTATION_MARK
    : '"' -> skip
    ;

IDENT
   : ('A' .. 'Z') ('A' .. 'Z' | DIGIT | '_')*
   ;

STRING_LITERAL
   : '\'' ('\'\'' | ~ ('\''))* '\''
   ;

INT
   : DIGIT+
   ;

DIGIT:
    '0' .. '9'
    ;

LETTER:
    'a' .. 'z' | 'A' .. 'Z'
    ;

mode VARS;

VAR_FREE_TEXT_SPACE_COMMA
    : (~ (',' | ' ' | '\t' | '"' ))+ -> popMode
	;

REGEXP
    : QUOTE? SLASH (~ [\\] SLASH | SLASH SLASH)* SLASH QUOTE? -> popMode
    ;

DICT_ELEMENT
	: (~["|,\n \t}=]|(~[\\]'"'))+
	;

DICT_ELEMENT_WITH_PIPE
    : [^ =\t"]+
	;

DICT_ELEMENT_NO_PIPE
    : [^ =|\t"]+
	;

DICT_ELEMENT_NO_MACRO
    : (~ ["|,%{\n \t}=]| (~["]))+
	;

DICT_ELEMENT_WITH_EQUALS
    : (~ ["|,\n \t}] | (~ ["]))+
	;

DICT_ELEMENT_REGEXP
    : SLASH DICT_ELEMENT_NO_PIPE SLASH (SPACE | PIPE)
    | QUOTE SLASH DICT_ELEMENT_WITH_PIPE SLASH QUOTE PIPE
    ;

mode MACRO;

FREE_TEXT_QUOTE_MACRO_EXPANSION
    : (~ ['] | ( ~ [\\] QUOTE ) )+ '%}' -> popMode
	;


