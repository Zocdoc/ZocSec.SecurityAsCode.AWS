# S3 Auto Encrypt Bucket

*Part of the Zocdoc's Zocsec.SecurityAsCode initiative*

This script will encrypt any S3 bucket that was created without encryption or modified to disable the encryption.  The script may optionally send alert the owner of the bucket and/or your security team if an issue is detected, through SNS or SES.  This notification can be thought of a learning exercise for the teams to properly create buckets in the future.

# Set Up

Script has some configuration options at the top of the file, for setting different behaviors, email addresses, and more.  The options are:

* **send_sns**   - Select "True" or "False" to enable or disable SNS.
* **send_ses**   - Select "True" or "False" to enable or disable SES.
* **ses_sender** - The email address which SES uses as Sender.
* **ses_bcc**    - Blind carbon copy of email address/es for SES.
* **ses_owner_recipient_suffix** - Email domain suffix for business owner, e.g., "@yourcompany.com".  If an "owner" tag contains this email suffix, then SES will send to this recipient.
* **bucket_whitelist** - List of buckets where encryption settings are not checked.
* **pause_time** - How long to wait between the lambda being triggered and checking a bucket's encryption settings; we found we can eliminate unnecessary operations by waiting a moment.
* **log.setLevel()** - Set the logging level to one of the standard python levels.
* **lambda_role_arn_override** - By default, the IAM role is `'arn:aws:iam::' + Account ID + ':role/ZocsecS3BucketRole'` unless you override it via this variable.
* **SNS_TopicARN_override** - By default, the SNS Topic is `'arn:aws:sns:' Region + ':' + Account ID + ':' + 'unEncryptedS3BucketCreated'` unless you override it via this variable.

In addition to the above, there are two environment variables which can be set:

* **ZOCSEC_ROLE_ARN** - The IAM Role.  The "override" above has precedence.  
* **ZOCSEC_SNS_TOPIC_ARN** - The SNS Topic.  The "override" above has precedence.

# Deployment & Configuration

The directions below are for manual configuration through the AWS GUI.  You can also write your own Cloud Formation and Ansible scripts as you please.  We will release an automated configuration script at a point in the future.

## IAM Permissions

To begin, create a new IAM group so that we can have the right permissions.  Your Lambda will need access to perform S3 calls and also to write information into logs (for auditing and debugging).

* Name: ZocsecS3BucketRole
* Description: Zocsec Role to allow various security lambdas to interact with s3 and CloudWatchEvents. For questions, e-mail the Information Security team
* Attached Policies:
    - AmazonS3FullAccess
    - CloudWatchLogsFullAccess
    - AmazonSNSFullAccess
    - AmazonSESFullAccess
    - IAMReadOnlyAccess
    - CloudWatchEventsFullAccess
* Trust Relationship: 'lambda'; or just use this json:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## GuardDuty

Be sure to activate GuardDuty for your account.  Make sure it has the right permissions to run.  That's about it.  Mine was already set properly.

## SNS

As part of the optional warning infrastructure, the script sends message via an SNS topic.  Thus, we need to create that.

* Topic Name: ZocsecS3AutoEncryptBucket
* Display Name:  (leave blank)
* Add the appropriate email subscribers:
    - {list of emails for your infosec team}

After saving,

1. Confirm the email subscription from the link in the inbox.

The Topic ARN is needed for the Lambda, but the value is computed from the environment, thus `arn:aws:sns:{region}:{accountID}:ZocsecS3AutoEncryptBucket` is generated from the parameters passed to the lamdba.

## SES

SES sends email notification to the bucket creator regarding the misconfiguration they have just committed. Each time a bucket is created without encryption, SES will kicks off a warming email to the bucket creator. Below are the prerequisite for S3 bucket:

Bucket Tags: {key} ```owner```   {value} ```user@emailDomain.com``` 

In order for SES to successfully deliver an email via SES, verify whether your AWS account is under SES Sandbox mode or production mode.

When your account is in the Sandbox, the following restrictions apply to your account:
* You can only send mail to verified email addresses and domains, or to the Amazon SES mailbox simulator.
* You can only send mail from verified email addresses and domains.
* You can send a maximum of 200 messages per 24-hour period.
* You can send a maximum of 1 message per second.

For more information on Amazon SES sandbox, Please see [Amazon's Guide](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html)

To be able to send to non-verified email addresses, you will have to request to be moved out of the Sandbox. 
Here is the [SES Extended Access Request link](https://aws.amazon.com/ses/extendedaccessrequest/)

## Lambdas

Now, code it up!  Create a new Lambda and configure the events for it.

1. Go to Lambda
1. Create a new function:
    1. we called ours `ZocsecS3AutoEncryptBucket`
    1. this is python 3.6
    1. The role is ZocsecS3BucketRole
1. Add the code from the  [file s3-bucket-encrypt-lambda.py](s3-bucket-encrypt-lambda.py).
1. In the configuration, change the throttling to Reserve Concurrency of 1.
1. Add these tags:
    - Owner = Infosec Team
    - Project = SecurityAsCode
    - Subproject = ZocsecS3AutoEncryptBucket
    - Auto-Delete = never
    - zocsec:vcn = 2018-10-26
    - Creator / aws:cf:etc = {your CF script ID and stuff}
1. Memory = minimum (128MB) & timeout = 10sec.
1. Add a test event, which we called `Test1` loaded [from this file](test-event-1-bucket-not-found.json).
1. Click Test to see if it runs.  Please not that you will get an "Instance not found" error message or "Account not allowed" error.  You'll have to edit the event for your AWS Acount ID.
1. You can also copy an event from the logs and create your own test events.


## CloudWatch Events

First off, did the Lambda properly send its audit logs to CloudWatch?  If you see /aws/lambda/ZocsecS3AutoEncryptBucket in your Log stream, then your permission to write to the logs is correct.

Now, to configure the rule which scans Guard Duty and they fires the Lambda when needed.  So, in CloudWatch:

* Name: ZocsecS3AutoEncryptBucket
* Description: "Zocsec rule executes S3 Auto Encrypt Lambda when detecting S3 bucket without encryption, owner=Infosec Team"
* Custom Pattern in file [s3-cloudwatch-config.json](s3-cloudwatch-config.json)
* Target: Lambda Function ZocsecS3AutoEncryptBucket

After the log group appears, set the retention policy for /aws/lambda/ZocsecS3AutoEncryptBucket to 90 days.  Or, create the group and then set the policy.

# Test It!

To test,

1. Create a new s3 bucket with no encryption.
1. Wait a few seconds.
1. Load up that s3 bucket's properties and view the updated encryption settings.
1. For optional fun, please review CloudWatch Events and CloudTrail too.


# Error Reporting

CRITICAL: system does not have permissions and rights to perform s3:PutEncryptionConfiguration on ${name_of_bucket} - please see CloudWatch Logs on this event ID for more information.

# About

This project was released to the public as part of the Zocdoc's ZocSec.SecurityAsCode initiative.

Copyright © 2018 Zocdoc Inc.  www.zocdoc.com


<!-- vim: spell expandtab sw=4 sts=4 ts=4
-->
