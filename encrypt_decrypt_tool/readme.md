# AWS Encrypt/Decrypt Tool

The purpose of this tool is to make it easy to quickly encrypt and decrypt values 
with KMS Encryption Keys. This was written with python3. To use, just make sure 
you have the aws cli installed and you have an IAM key and secret configured 
properly for boto3 to use (should be in ~/.aws/credentials on a mac or 
%UserProfile%\.aws on pc).

You can also import the file in your projects and use the encrypt_value and 
decrypt_value functions directly.