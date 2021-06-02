![Red-Bucket](https://github.com/lightspin-tech/red-bucket/blob/main/red-bucket.png)



# Red-Bucket
## Lightspin S3 Bucket Scanner


### Description
Scan your S3 Buckets for public access and cross-account attack discovered by Lightspin's Security Research Team.

The tool analyzes the following:
- Bucket's block public access settings
- Bucket policy and ACL
- Object ACL

### Our Research
[Link to the full security research blog - part 1](https://blog.lightspin.io/how-to-access-aws-s3-buckets)

[Link to the full security research blog - part 2](https://blog.lightspin.io/risks-of-misconfigured-s3-buckets-and-what-to-do)

### Requirements
Red-Bucket is built with Python 3 and Boto3.

The tool requires:
- IAM User with Access Key
- [Sufficient permissions for the IAM User to run the scanner](red-bucket-policy.json)
- Python 3 and pip3 installed

### Installation
```bash
sudo git clone https://github.com/lightspin-tech/red-bucket.git
cd red-bucket
pip3 install -r requirements.txt
```

### Usage
```bash
python3 main.py [output-csv-path] [AWS-Access-Key-id] [AWS-Aecret-Access-Key]
```
### Notes
- In buckets with more that 1000 objects, the  value of "objects amount" will be 1000+. 
- The tool does not drill down to the object level in buckets that have more than 100 objects.
  if you want to change it you can edit the get_doc_objects function in the code locally to the desired number (999 max)
  
### Contact Us
This research was held by Lightspin's Security Research Team.
For more information, contact us at support@lightspin.io.

### License
This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-bucket/blob/main/LICENSE).
