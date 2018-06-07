coreo_aws_rule "s3-allusers-full-control" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-full-control.html"
  display_name "All users can do anything with the affected bucket"
  description "Bucket has permissions (ACL) which let all users do anything with the bucket and/or it's contents."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to have full control."
  level "High"
  meta_nist_171_id "3.1.22, 3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bfull_control\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bwrite\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-world-open-policy-all" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-all.html"
  display_name "Bucket policy gives the world permission to do anything in the bucket"
  description "Bucket policy gives the world permission to do anything in the bucket"
  category "Dataloss"
  suggested_action "Modify the principle to remove the * notation which signifies any person or remove the * from allowed actions which signifies allowing any possible action on the bucket or its contents."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_policy"]
  call_modifiers [{}, {:bucket => "buckets.name"}]
  audit_objects ["", "object.policy"]
  formulas      ["", "jmespath.Statement[?Effect == 'Allow' && Action == 's3:*' && Principal == '*' && !Condition]"]
  operators     ["", "=~"]
  raise_when    ["", /[^\[\]\{\}]/]
  id_map "modifiers.bucket"
end

coreo_aws_rule_runner "advise-s3" do
  service :s3
  action :run
  regions ["PLAN::region"]
  rules ${AUDIT_AWS_S3_ALERT_LIST}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_variables "s3-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.report' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.number_violations'},

            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-s3" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta65"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-s3.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_S3_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_S3_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_S3_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_S3_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

const alertListArray = ${AUDIT_AWS_S3_ALERT_LIST};
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');
function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end



coreo_uni_util_variables "s3-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-s3.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.table'}
            ])
end



coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}



let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-s3-to-tag-values" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
end


coreo_uni_util_notify "advise-s3-rollup" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_S3_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_S3_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
cloud account name: PLAN::cloud_account_name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-s3.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_aws_s3_policy "cloudcoreo-audit-aws-s3-policy" do
  action((("${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::bucket-${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::bucket-${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "bucket-${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-s3-policy"]
end

coreo_uni_util_notify "cloudcoreo-audit-aws-s3-s3" do
  action((("${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.report'
  endpoint ({
      object_name: 'aws-s3-json',
      bucket_name: 'bucket-${AUDIT_AWS_S3_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 's3/PLAN::name',
      properties: {}
  })
end
