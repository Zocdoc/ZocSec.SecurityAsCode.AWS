# EC2 Malware Automated Termination

*Part of the Zocdoc's ZocSec.SecurityAsCode initiative*

This auto-termination script kills off an EC2 instance if GuardDuty detects that malware has infested a server.  To install, follow these simple directions.

# IAM Permissions

First off, create a new IAM group so that we can the right permissions.  Your Lambda will need access to perform EC2 calls and also to write information into logs (for auditing and debugging).  

1. Go to IAM
1. Create a new role
1. Choose the trust entity, AWS Service, with Lambda use case.
1. Attach a policy for EC2, such as *AmazonEC2FullAccess* (or other as appropriate for your environment)
1. Attach a policy for logging, such as *CloudWatchLogsFullAccess* (again, customize to your setup)
1. Give it a name, we called ours `Backdoor_Shutdown_Role`
1. And a description: "Role used by Infosec functions which will shut down of EC2 during security event. This is a high privileged role."


# GuardDuty

Be sure to active GuardDuty for your account.  Make sure it has the right permissions.  That's about it.  Mine was already set properly.

# Lambdas

Now, code it up!  Create a new Lambda and configure the events for it.  

1. Go to Lambda
2. Create a new function:
    a. we called ours `Backdoor_Shutdown_Lambda`
    b. this is python 3.6
    c. The role is Backdoor_Shutdown_Role
3. Add the code from the  [file Backdoor_Shutdown_Lambda.py](Backdoor_Shutdown_Lambda.py).  
4. Add a test event, which we called `BackdoorDNSTrigger` loaded [from this file](test-event-1-positive.json).
5. Click Test to see if it works {hint: you'll get "Instance not found" error message}.


# Cloud Watch Events

First off, did the Lambda properly send its audit logs to CloudWatch?  If you see /aws/lambda/Backdoor_Shutdown_Lambda in your Log stream, then your permission to write to the logs is correct.

Now, to configure out rule which scans Guard Duty and they fires the Lambda when needed.

1. Go to CloudWatch
1. Click on Events &rarr; Rules
1. Create a new rule
1. Do an Event Pattern and choose "Build custom event pattern"
1. Edit the Pattern use the information found in the file [gd-cloudwatch-rules.json](gd-cloudwatch-rules.json).

Now, add the target 

1. Choose Lambda Function
1. Pick the Backdoor_Shutdown_Lambda that we created earlier
1. Go to the next screen with "Configure Details"
1. Give it a name, we called ours `GuardDuty_Backdoor_Alerts_Force_EC2_Shudown` 
1. Add a Description, such as: "Infosec rule executes EC2 shutdown Lambda when GuardDuty detects Backdoor on instance."

# Test It!

To test, `ssh` into the machine.  Then, run the test canary:

```
dig guarddutyc2activityb.com any
```

This triggers CloudWatch to call the Lambda to shut down the server.  Please note that GuardDuty and CloudWatch can have lag between the running of the test and when the machine is shutdown, please see the documentation on both for further information.

/* vim: spell expandtab
*/
