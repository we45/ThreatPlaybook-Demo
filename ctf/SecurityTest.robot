*** Settings ***
Library  threat_playbook.ThreatPlaybook  cut_the_funds
Library  Collections
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  RoboSslyze
Library  RoboGit
Library  RoboNodeJSScan
Library  REST  http://localhost:3000  proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
Library  RoboNpmAudit

*** Variables ***
# Git URL
${GIT_URL}  https://github.com/we45/Cut-The-Funds-NodeJS
${TO_PATH}  /Users/abhaybhargav/Documents/Code/Python/ctf_blackhat/ctf/git_source

${TARGET_NAME}  Cut the Funds Expenser Application
${TARGET_URI}  localhost:3000
${SSL_TARGET}  207.148.70.86
#CONFIG
${RESULTS_PATH}  /Users/abhaybhargav/Documents/Code/Python/ctf_blackhat/ctf/results

#Sslyze
${SSLYZE_JSON}  /Users/abhaybhargav/Documents/Code/Python/ctf_blackhat/ctf/results/sslyze.json

#ZAP
${ZAP_PATH}  /Applications/OWASP_ZAP.app/Contents/Java/
${APPNAME}  Cut the Funds NodeJS API
${CONTEXT}  Cut_The_Funds_API
${REPORT_TITLE}  Cut the Funds NodeJS API Test Report - ZAP
${REPORT_FORMAT}  json
${ZAP_REPORT_FILE}  ctf.json
${REPORT_AUTHOR}  Abhay Bhargav
${SCANPOLICY}  Light

*** Test Cases ***
Load Entities
    load entity file

Create Entities
    find or create entities

Connect Entities
    find or connect entities

generate threat models
    find or load cases from directory

Create Targets
    find or create target  ${TARGET_NAME}  ${TARGET_URI}

Clone repo from Github
    clone repository from url  ${GIT_URL}  ${TO_PATH}

Run NodeJSScanner
    run nodejsscan against source  ${TO_PATH}  ${RESULTS_PATH}
    parse nodejsscan result  ${RESULTS_PATH}/nodejsscan.json  ${TARGET_NAME}

Run NPM Audit against packageJSON
    run npmaudit against source  ${TO_PATH}  ${RESULTS_PATH}
    parse npmaudit scan result  ${RESULTS_PATH}/npm_audit.json  ${TARGET_NAME}

Test for SSL
    test ssl basic  ${SSL_TARGET}
    test ssl server headers  ${SSL_TARGET}
    write results to json file  json_file=${SSLYZE_JSON}
    create and link recon  sslyze  ${TARGET_NAME}  file_name=${RESULTS_PATH}/sslyze.json

Initialize ZAP
    [Tags]  zap_init
    start gui zap  ${ZAP_PATH}
    sleep  10
    zap open url  http://${TARGET_URI}

Authenticate to Cut the Funds as Admin
    [Tags]  walk_web_service
    &{res}=  POST  /users/login  {"email": "andy.roberts@widget.co", "password": "spiderman"}
    Integer  response status  200
    Boolean  response body auth  true
    set suite variable  ${TOKEN}  ${res.body["token"]}
    log  ${TOKEN}

Search the Currency Lookup Service
    [Tags]  walk_web_service
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /projects/search_expense_db  { "search": "Chile" }
    Integer  response status  200
    String  $[0].country  Chile

ZAP Contextualize
    [Tags]  zap_context
    ${contextid}=  zap define context  ${CONTEXT}  http://${TARGET_URI}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Active Scan
    [Tags]  zap_scan
    ${scan_id}=  zap start ascan      ${CONTEXT_ID}  http://${TARGET_URI}  ${SCANPOLICY}
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    [Tags]  zap_generate_report
    zap export report  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

Write ZAP Results to DB
    parse zap json  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${TARGET_NAME}  ${TARGET_URI}

Auth Custom Exploit
    [Tags]  custom_exploit
    Authenticate to web service as a regular user

Create Expense for Custom Exploit
    [Tags]  custom_exploit
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    Create a Regular Expense
    Update Expense with Approved Tag

ZAP Die
    [Tags]  zap_kill
    zap shutdown
    sleep  3
    clear contents from directory  ${TO_PATH}

Write Final Report
    write markdown report  gen_diagram=True  gen_threat_model=True

Generate Threat Maps for all Models
    generate threat maps

*** Keywords ***
Authenticate to web service as a regular user
    &{res}=  POST  /users/login  {"email": "maya.williams@widget.co", "password": "superman123"}
    Integer  response status  200
    Boolean  response body auth  true
    set suite variable  ${TOKEN}  ${res.body["token"]}
    log  ${TOKEN}

Create a Regular Expense
    &{res}=  POST  /expenses/create_expense  {"name": "Dinner at TGIF", "projectId": "5ace0e85b10d64111c00adb2", "merchant": "TGIF", "reason": "Food Expenses at Conference", "amount": 80}
    Integer  response status  201
    set suite variable  ${EXPENSE_ID}  ${res.body["expense"]}
    log  ${EXPENSE_ID}

Update Expense with Approved Tag
    &{res}=  POST  /expenses/update_expense/${EXPENSE_ID}  {"isApproved": true}
    Integer  response status  200
    ${vul_name}=  convert to string  Insecure Direct Object Reference - Mass Assignment
    ${tool}=  convert to string  Custom Exploit Script
    ${cwe}=  convert to integer  285
    ${description}=  convert to string  The update expense function is vulnerable to a Mass-Assignment style Insecure Direct Object Reference, where the attacker can guess the name of the named parameters and bypass authorization"
    ${severity}=  convert to integer  3
    &{vul_dict}=  Create Dictionary  name=${vul_name}  tool=${tool}  cwe=${cwe}  description=${description}  severity=${severity}  target_name=${TARGET_NAME}
    run keyword if  ${res.body["isApproved"]}==True  create vulnerability  ${vul_dict}