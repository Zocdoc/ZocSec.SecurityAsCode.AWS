# s3-bucket-encrypt-lambda.py || part of ZocSec.SecurityAsCode.AWS 
#
# An AWS Lambda for adding encryption to a bucket which had its encryption removed.
#
# Owner:	Copyright 2018 Zocdoc Inc.  www.zocdoc.com 
# Authors:	Suved Adkar, Jay Ball @veggiespam
#
from __future__ import print_function
import boto3
import json
import logging
from botocore.exceptions import ClientError


#initialize the s3 client
s3 = boto3.client('s3')  

#initialize the SNS client
sns = boto3.client('sns')

#define Lambda Fucntion. The event variable will pass the full CloudWatch event to this function
def lambda_handler(event, context):
	#get bucket Name from event
	bucket_name = (event['detail']['requestParameters']['bucketName'])
	
	#get bucket Creators Name
	bucket_creator = (event['detail']['userIdentity']['principalId'])
	bucket_user = bucket_creator.split(":",1)
	


#Get the buckets current encryption, if it errors, there is no Default Encryption on the bucket and we set the encryption wiith Put Bucket encryption, else do nothing! 
	try:
		currEncrypt = s3.get_bucket_encryption (Bucket=bucket_name)
	except ClientError as e:
		toEncrypt = s3.put_bucket_encryption (Bucket=bucket_name,ServerSideEncryptionConfiguration={'Rules':[{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
		message = 'An Unencrypted Bucketed was created by ' + bucket_user[1] + '.' + ' Default AES-256 encryption has been applied to the bucket';
		response = sns.publish(TopicArn='arn:aws:sns:us-east-1:000123456:unEncryptedS3BucketCreated', Message = message)
	else:
		return currEncrypt

