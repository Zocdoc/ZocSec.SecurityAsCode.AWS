# s3-bucket-encrypt-lambda.py || part of ZocSec.SecurityAsCode.AWS
#
# An AWS Lambda for adding encryption to a bucket which had its encryption removed.
#
# Owner:	Copyright 2018 Zocdoc Inc.  www.zocdoc.com
# Authors:	Jay Ball @veggiespam
#

import os
import boto3
import json
from time import sleep
import logging
from botocore.exceptions import ClientError

zocsec_vcn = '2018-10-26'
send_sns = False	# enable/disable Simple Notification Service
send_ses = False	# enable/disable Simple Email Service

# Configuration of SES
# Specify the sender of message, a list of BCC, and the email suffix to scan for in
# the "owner" tag as the recipient of alerts. See docs for more info.
ses_sender = "<SENDER>"
ses_bcc = [  ]
ses_owner_recipient_suffix = "<EMAIL DOMAIN>"

# List of buckets where encryption is not required.
bucket_whitelist = [   ]

# How long to wait after script invocation before we check the encryption.
pause_time = 1.00 # seconds  (e.g., 1.25 / 2.0 / 0.05 / 0.0 / etc)

FORMAT='[%(levelname)s] %(message)s'
log = logging.getLogger()
for h in log.handlers:
	h.setFormatter(logging.Formatter(FORMAT))
log.setLevel(logging.WARNING)

# lambda_role_arn_override = 'TBD'	; # IAM role for this lambda & S3 bucket operations, overrides defaults
# SNS_TopicARN_override = 'TBD' 	; # SNS Topic to send messages, overrides defaults

def sendMail(owner,subject,body):
	"""
	:param owner: This represents the owner of the bucket. It is also use for recipient for SES.
	:param subject: Subject line of the SES email
	:param body: The body content of the SES email
	:return: In the event SES fail to send, return the error message
	"""
	if send_ses:
		ses = boto3.client('ses')
		try:
			response = ses.send_email(
				Source=ses_sender,
			  	Destination={
			      	'ToAddresses': [ owner ],
			      	'BccAddresses': ses_bcc,
			  	},
			  	Message={
			      	'Subject': { 'Data': subject, 'Charset': 'utf-8' },
			      	'Body': {
				          	'Text': { 'Data': body,  'Charset': 'utf-8' },
			      	}
			  	}
			)
			log.debug("SES SENT response=" + response)
		except ClientError as e:
			msg = e.response['Error']['Message']
			if "Illegal address" or "MessageRejected" in msg:
				log.error('Error sending SES: ' + msg)
				return msg
			else:
				log.error('Strange error sending SES: ' + msg)
				return msg


# Main()
def lambda_handler(event, context):
	log.info("Event is: %s",  json.dumps(event))
	lambda_role_arn = os.getenv('ZOCSEC_ROLE_ARN',
								'arn:aws:iam::' + event['account'] + ':role/ZocsecS3BucketRole')
	if 'lambda_role_arn_override' in globals():
		lambda_role_arn = lambda_role_arn_override
	log.info("lambda_role_arn: %s",  lambda_role_arn)

	SNS_TopicARN = os.getenv('ZOCSEC_SNS_TOPIC_ARN',
							 'arn:aws:sns:' + event['region'] + ':' + event['account'] + ':' + 'unEncryptedS3BucketCreated')
	if 'SNS_TopicARN_override' in globals():
		SNS_TopicARN = SNS_TopicARN_override
	log.info('SNS_TopicARN= %s', SNS_TopicARN)

	source = event['source']
	if source != "aws.s3":
		# wrong caller, just silently return
		log.debug("Wrong Filter on CW Events, source=%s", source)
		return

	detail_type = event['detail-type']
	if detail_type != 'AWS API Call via CloudTrail':
		# wrong caller, just silently return
		log.debug("Wrong Filter on CW Events, source=%s / detail_type=%s", source, detail_type)
		return

	allowed_event_list =  [
		"CreateBucket",
		"PutBucketAcl",
		"PutBucketPolicy",
		"PutBucketEncryption",
		"DeleteBucketEncryption"
	]

	event_name = event['detail']['eventName']

	if not(event_name in allowed_event_list):
		# wrong event, just silently return
		log.debug("Wrong Filter on CW Events, source=%s / event_name=%s", source, event_name)
		return

	#get bucket Name from event
	bucket_name = event['detail']['requestParameters']['bucketName']

	if bucket_name in bucket_whitelist:
		# whitelisted bucket, just silently return
		log.info("Bucket on whitelist, encryption not performed: %s", bucket_name)
		return

	#get bucket Creator Name
	bucket_creator = event['detail']['userIdentity']['principalId']
	bucket_user = bucket_creator.split(":",1)

	s3 = boto3.client('s3')

	# Confirm our permissions.  We need the ability to perform some actions
	# on the buckets, like GetBuckEncryption and PutBucketEncryption.  Since
	# this script can be re-triggered on calls to PutBucketEncryption, check
	# our permissions here - otherwise we will get into an infinite loop.

	actions = ['s3:PutEncryptionConfiguration', 's3:GetEncryptionConfiguration']
	bucket_arn = 'arn:aws:s3:::' + bucket_name + '/*'
	log.info("bucket_arn = " + bucket_arn)

	iam = boto3.client("iam")
	response = iam.simulate_principal_policy(PolicySourceArn=lambda_role_arn, ActionNames=actions, ResourceArns=[ bucket_arn ])
	results = response['EvaluationResults']

	critical_sub = False
	do_encrypt = True
	for actions in results:
		eval_decision = actions['EvalDecision']
		if(eval_decision != 'allowed'):
			action_name = actions['EvalActionName']
			log.critical("Cannot perform " + action_name + " on " + bucket_arn + " because of " + eval_decision)
			if action_name == 's3:PutEncryptionConfiguration':
				do_encrypt = False
				critical_sub = True

	encryption_activation_message = ''

	# Before we go further - sleep.  We have found that CloudWatch Events get triggered on
	# CreateBucket and then the process / user performs the encryption afterwards,
	# but this lambda process was already triggered, so confusion reigns.  So, give them a moment to finish
	# thier encryption before we force the issue.
	sleep(pause_time)

	# Get the bucket current encryption, check for Exception with
	# ServerSideEncryptionConfigurationNotFoundError.
	try:
		# Note: even if we don't have s3:GetEncryptionConfiguration abilities, call
		# this anyway.  We will get access denied error and it will be properly
		# logged and report on.

		currEncrypt = s3.get_bucket_encryption (Bucket=bucket_name)

		# If this returns without an exception, then some type of encryption is
		# in place.  A future enhancement would be to check for AWS-KMS versus
		# AES-256 versus some-future-alg.  Then, decide if the encryption is
		# good enough or if some types of buckets require keys-only.  Etc.

	except ClientError as e:
		# Otherwise, there is no encryption (or other error):
		bucket_tags = '(no tags)'
		owner_email = ''

		# IMPORTANT: Check each exception's code.  If we don't do this correctly,
		# we might get into an infinite loop.
		if e.response['Error']['Code'] == 'NoSuchBucket':
			encryption_activation_message = "Bucket was deleted before encryption could be applied, error: " + str(e)

		elif e.response['Error']['Code'] == 'AccessDenied':
			encryption_activation_message = "We do not have permission to read the Bucket, error: " + str(e)

		elif e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
			# No encryption found, so encrypt it.

			if not(do_encrypt):
				# Remember, we tested for ability to call put_bucket_encryption() earlier
				encryption_activation_message = 'CRITICAL: system does not have permissions and rights to perform s3:PutEncryptionConfiguration on ' + bucket_name + ' - please see CloudWatch Logs on this event ID for more information.'

			else:
				# Finally, we try to encrypt the bucket
				try:
					toEncrypt = s3.put_bucket_encryption (Bucket=bucket_name,ServerSideEncryptionConfiguration={'Rules':[{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
					encryption_activation_message = 'AES-256 has been applied as the default operation when writing files.'
					log.info(encryption_activation_message)

				except ClientError as ee:
					if ee.response['Error']['Code'] == 'NoSuchBucket':
						# it may seem strange to check this again a few lines later, but yes, it happens
						encryption_activation_message = "Bucket was deleted before encryption could be applied, error: " + str(ee)

					elif ee.response['Error']['Code'] == 'AccessDenied':
						# technically, we should never get here since we check this permission earlier.
						encryption_activation_message = "Critical - We do not have permission to put encryption on the Bucket, error: " + str(ee)
						log.critical(encryption_activation_message)
						log.critical("Event is: %s",  json.dumps(event))
						critical_sub = True

					else:
						encryption_activation_message = "Critical - loop warning - Could not encrypt bucket during put_bucket_encryption(): " + str(ee)
						log.critical(encryption_activation_message)
						log.critical("Event is: %s",  json.dumps(event))
						critical_sub = True

			try:
				bucket_tags_dict = s3.get_bucket_tagging(Bucket=bucket_name)
				bucket_tags = ''
				for tag in bucket_tags_dict["TagSet"]:
					bucket_tags = bucket_tags + "\n\t\t\t" + tag["Key"] + " : " + tag["Value"]
					if tag["Key"].lower() == "owner":
						owner_email = tag["Value"]
						log.info('found an owner tag with value: ' + owner_email)
			except:
				pass
		else:
			encryption_activation_message = "Strange or unknown error when calling get_bucket_encryption() on " + bucket_name + ", ignoring this bucket : " + str(e)
			log.critical (encryption_activation_message)
			critical_sub = True

		sub = ''
		if True == critical_sub:
			sub = "CRITICAL "

		sub = sub + '[Zocsec][S3AutoEncryptBucket] s3 bucket not encrypted: ' + bucket_name
		sub = sub[0:99]   ; # SNS subject has a 100 char limit per AWS specification
		message = """{status_message}

Bucket Information:
	Operation:\t{op}
	Event ID:\t{id}
	Bucket:\t\t{bucket}
	User:\t\t{user}
	Account:\t{region} / {account}
	BucketTags:\t{tagset}""".format(
			status_message=encryption_activation_message, id=event['id'],
			op=event_name, bucket=bucket_name,
			user=bucket_user[1],
			region=event['region'], account=event['account'],
			tagset=bucket_tags)

		ses_result = ''
		if send_ses:
			if owner_email.endswith(ses_owner_recipient_suffix):
				result = sendMail(owner_email,sub,message)
				if result:
					ses_result = 'Unable to send email to the bucket owner via SES.  Response is: ' + result
					log.error(ses_result)
			else:
				ses_result = 'Owner tag of "' + owner_email + '" is not an email or is not destined for ' + ses_owner_recipient_suffix
				log.warning(ses_result)

		if ses_result:
			message = message + "\n\n\tSES Email Error:\t" + ses_result

		if send_sns:
			sns = boto3.client('sns')
			response = sns.publish(TopicArn = SNS_TopicARN, Message = message, Subject = sub)
			log.info('SNS response' + response)

	else:
		# Since data is already being written to CloudTrail no matter what we do, just say
		# everything was fine and provide current encryption settings on bucket.
		log.info('During operation %s, bucket %s was already encrypted, JSON_Dump=%s',
				event_name, bucket_name, json.dumps(currEncrypt)  )

# vim noexpandtab:ts=4:sw=4:sts=4
