import boto3, csv, sys, jsons

CSV_PATH = r'{path}'.format(path=str(sys.argv[1]))
AWS_ACCESS_KEY_ID = str(sys.argv[2])
AWS_SECRET_ACCESS_KEY = str(sys.argv[3])
#BUCKET_DOC = {'bucket_name': {}, 'bucket_policy': {}, 'bucket_policy_status': {}, 'bucket_acl': {}, 'bucket_block_public_access': {}, 'object_count': {}, 'lightspin_status': {}, 'objects': {}, 'bucket_access':{}, 'access_scope':{}}

def create_session(aws_access_key_id, aws_secret_access_key, service='s3'):
    """parameters:
        aws_access_key_id : str/None
        aws_secret_access_key : str/None
        service : str (default is 'S3')
       description:
        This function returns an s3 connection and a list_buckets() response."""
    if aws_access_key_id == None and aws_secret_access_key == None:
        client_session = boto3.session.Session()
    else:
        client_session = boto3.session.Session(aws_access_key_id, aws_secret_access_key)
    client = client_session.client(service)
    response = client.list_buckets()
    return [client, response]

def create_bucket_object(aws_access_key_id, aws_secret_access_key, bucket_name, service='s3'):
    """parameters:
        aws_access_key_id : str/None
        aws_secret_access_key : str/None
        bucket_name : str
        service : str (default is 'S3')
       description:
        This function returns the bucket object of the bucket with the specified name."""
    s3 = boto3.resource(service)
    bucket = s3.Bucket(bucket_name)
    return bucket

def get_bucket_names(response):
    """parameters:
        response : object
       description:
        This function returns a list of all the bucket names in the account."""
    bucket_names = []
    s3_buckets = response['Buckets']
    for bucket in s3_buckets:
        bucket_names.append(bucket['Name'])
    return bucket_names

def get_bucket_doc(client, bucket_name):
    """parameters:
        client : object
        bucket_name : str
       description:
        This function creates and returns a dictionary with the bucket access properties - policy, acl, and blocking configurations."""
    bucket_doc = {'bucket_name': {}, 'bucket_policy': {}, 'bucket_policy_status': {}, 'bucket_acl': {}, 'bucket_block_public_access': {}}
    bucket_doc['bucket_name'] = bucket_name
    try:
        bucket_policy = client.get_bucket_policy(Bucket=bucket_name)
        del bucket_policy['ResponseMetadata']
        bucket_doc['bucket_policy'] = bucket_policy
    except Exception:
        pass
    try:
        bucket_policy_status = client.get_bucket_policy_status(Bucket=bucket_name)
        del bucket_policy_status['ResponseMetadata']
        bucket_doc['bucket_policy_status'] = bucket_policy_status
    except Exception:
        pass
    try:
        bucket_acl = client.get_bucket_acl(Bucket=bucket_name)
        del bucket_acl['ResponseMetadata']
        bucket_doc['bucket_acl'] = bucket_acl
    except Exception:
        pass
    try:
        bucket_block_public_access = client.get_public_access_block(Bucket=bucket_name)
        del bucket_block_public_access['ResponseMetadata']
        bucket_doc['bucket_block_public_access'] = bucket_block_public_access
    except Exception:
        pass
    return bucket_doc

def get_bucket_status(bucket_doc):
    """parameters:
        bucket_doc : dict
       description:
        This function gets a bucket doc and returns its aws status - public, Bucket and objects not public, etc."""
    bucket_status = None
    if bucket_doc['bucket_policy'] != {} and bucket_doc['bucket_policy_status']['PolicyStatus']['IsPublic'] == True:
        if bucket_doc['bucket_block_public_access'] != {}:
            if bucket_doc['bucket_block_public_access']['PublicAccessBlockConfiguration']['RestrictPublicBuckets'] == True:
                bucket_status = 'Only authorized users of this account'
            else:
                bucket_status = 'Public'
        else:
            bucket_status = 'Public'
    elif bucket_doc['bucket_acl'] != {} and len(bucket_doc['bucket_acl']['Grants']) > 1:
        if bucket_doc['bucket_block_public_access'] != {}:
            if bucket_doc['bucket_block_public_access']['PublicAccessBlockConfiguration']['IgnorePublicAcls'] == True:
                bucket_status = 'Bucket and objects not public'
            else:
                bucket_status = 'Public'
        else:
            bucket_status = 'Public'
    else:
        if bucket_doc['bucket_block_public_access'] != {}:
            if bucket_doc['bucket_block_public_access']['PublicAccessBlockConfiguration']['IgnorePublicAcls'] == True:
                bucket_status = 'Bucket and objects not public'
            else:
                bucket_status = 'Objects can be public'
        else:
            bucket_status = 'Objects can be public'
    bucket_doc['status'] = bucket_status
    return bucket_doc

def get_objects_num(client, bucket_doc):
    objects_doc = {}
    objects_amount = 0
    try:
        bucket_name = bucket_doc['bucket_name']
        bucket_objects = client.list_objects(Bucket=bucket_name)
        del bucket_objects['ResponseMetadata']
        objects_doc = bucket_objects
    except Exception:
        pass
    if 'Contents' in list(objects_doc.keys()):
        objects_amount = len(objects_doc['Contents'])
    if objects_amount == 1000:
        bucket_doc['objects_count'] = '1000+'
    else:
        bucket_doc['objects_count'] = objects_amount
    return bucket_doc

def policy_analyzer(bucket_doc):
    """parameters:
        bucket_doc : dict
       description:
        This function pareses the bucket policy. It returns a list of every policy statement (each one cotains the action, principal, resource and effect)."""
    bucket_policy = bucket_doc['bucket_policy']['Policy']
    policy_dict = None
    if type(bucket_policy)==str:
        policy_dict = jsons.loads(bucket_policy)
    elif type(bucket_policy)==dict:
        policy_dict = bucket_policy
    if policy_dict!={}:
        actions = [[statement['Action'], statement['Principal'], statement['Effect'], statement['Resource']] for statement in policy_dict['Statement']]
        return actions

def policy_access_analyzer(policy_actions):
    """parameters:
        policy_actions : list
       description:
        This function analyzes the bucket policy statements, and determines the access scope (read, write, full aceess, etc).
        It return a string of the access scope."""
    access_actions = []
    bucket_access = None
    for action in policy_actions:
        if action[0].find('Get') != -1 or action[0].find('List') != -1:
            if action[2] == 'Allow':
                access_actions.append('read access')
        if action[0].find('Put') != -1:
            if action[2] == 'Allow':
                access_actions.append('write access')
        if action[0].find('Delete') != -1:
            if action[2] == 'Allow':
                access_actions.append('delete access')
        if action[0].find('*') != -1:
            if action[2] == 'Allow':
                access_actions.append('full access')
    if 'full access' in access_actions:
        bucket_access = 'full access'
    elif 'read access' in access_actions:
        if 'write access' in access_actions:
            if 'delete access' in access_actions:
                bucket_access = 'read, write, delete access'
            else:
                bucket_access = 'read and write access'
        else:
            bucket_access = 'read access'
    elif 'write access' in access_actions:
        if 'read access' not in access_actions:
            if 'delete access' in access_actions:
                bucket_access = 'write and delete access'
            else:
                bucket_access = 'write access'
        else:
            bucket_access = 'unknown'
    return bucket_access

def bucket_acl_analyzer(bucket_doc):
    """parameters:
        bucket_doc : dict
       description:
        This function pareses the bucket acl. It returns a list of every acl grant (each one contains the grantee and permission)."""
    bucket_acl = bucket_doc['bucket_acl']
    bucket_owner = bucket_acl['Owner']
    actions = []
    for grant in bucket_acl['Grants']:
        if grant['Grantee']['Type'] == 'CanonicalUser':
            action = [grant['Grantee']['ID'], grant['Permission']]
            actions.append(action)
        elif grant['Grantee']['Type'] == 'Group':
            action = [grant['Grantee']['URI'], grant['Permission']]
            actions.append(action)
    return actions

def acl_bucket_access_analyzer(acl_actions):
    """parameters:
        acl_actions : list
       description:
        This function analyzes the bucket acl grants, and determines the access scope (read, write, etc).
        It return a string of the access scope."""
    access_actions = []
    bucket_access = None
    for action in acl_actions:
        if action[1].find('ACP') != -1:
            access_actions.append('read acp access')
        else:
            access_actions.append('read access')
    if 'read acp access' in access_actions:
        if 'read access' in access_actions:
            bucket_access = 'read and read acp access'
        else:
            bucket_access = 'read acp access'
    elif 'read access' in access_actions:
        if 'read acp access' not in access_actions:
            bucket_access = 'read access'
    return bucket_access

def get_bucket_objects(client, bucket_name):
    """parameters:
        client :
        bucket_name : str
       description:
        This function creates a list of all the files in the bucket (if the bucket is not a aws service bucket like cloudtrail, config, etc),
        It returns a list of the object names."""
    object_names = []
    if bucket_name.find('cloudtrail')==-1 and bucket_name.find('aws')==-1 and bucket_name.find('kops')==-1 and bucket_name.find('elastic')==-1:
        objects = client.list_objects(Bucket=bucket_name)
        del objects['ResponseMetadata']
        object_names = [obj['Key'] for obj in objects['Contents']]
    return object_names

def object_acl_analayzer(bucket_name, object_name, client):
    """parameters:
        bucket_name : str
        object_name : str
        client :
       description:
        This function pareses the object acl. It returns a list of every acl grant (each one contains the grantee and permission)."""
    object_acl = client.get_object_acl(Bucket=bucket_name, Key=object_name)
    del object_acl['ResponseMetadata']
    object_owner = object_acl['Owner']['ID']
    actions = []
    for grant in object_acl['Grants']:
        action = []
        if grant['Grantee']['Type'] == 'CanonicalUser':
            action = [grant['Grantee']['ID'], grant['Permission']]
        elif grant['Grantee']['Type'] == 'Group':
            action = [grant['Grantee']['URI'], grant['Permission']]
        actions.append(action)
    return actions

def acl_object_access_analyzer(object_actions):
    """parameters:
        object_actions : list
       description:
        This function analyzes the object acl grants, and determines if the object is public or not.
        It return a string of the object status."""
    object_access = None
    if ['http://acs.amazonaws.com/groups/global/AllUsers', 'READ'] in object_actions or ['http://acs.amazonaws.com/groups/global/AuthenticatedUsers', 'READ'] in object_actions:
        object_access = 'Public'
    elif ['http://acs.amazonaws.com/groups/global/AllUsers', 'READ_ACP'] in object_actions or ['http://acs.amazonaws.com/groups/global/AuthenticatedUsers', 'READ_ACP'] in object_actions:
        object_access = 'ACP is public'
    else:
        object_access = 'Not public'
    return object_access

def get_doc_objects(client, bucket_doc):
    """parameters:
        client :
        bucket_doc : dict
       description:
        This function creates a dictionary where every key is an object, and its value is its aceess.
        It adds this dictionary to the bucket doc and returns the new doc."""
    objects_access = {}
    if bucket_doc['objects_count'] != '1000+' and 0 < bucket_doc['objects_count'] < 100:
        object_list = get_bucket_objects(client, bucket_doc['bucket_name'])
        for obj in object_list:
            object_actions = object_acl_analayzer(bucket_doc['bucket_name'], obj, client)
            object_access = acl_object_access_analyzer(object_actions)
            objects_access[obj] = object_access
    bucket_doc['objects'] = objects_access
    return bucket_doc

def get_lightspin_status(client, bucket_doc):
    """parameters:
        client :
        bucket_doc : dict
       description:
        This function returns our evaluation of whether a bucket is public or not.
        It adds the status to the bucket doc and returns the doc """
    aws_status = bucket_doc['status']
    lightspin_status = None
    if aws_status == 'Public':
        lightspin_status = 'Public'
    elif aws_status == 'Bucket and objects not public':
        lightspin_status = 'Not public'
    elif aws_status == 'Only authorized users of this account':
        lightspin_status = 'Not public'
    elif aws_status == 'Objects can be public':
        if bucket_doc['objects_count'] == 0:
            lightspin_status = 'Not public'
        elif bucket_doc['objects_count'] == '1000+':
            lightspin_status = 'Objects can be public'
        else:
            object_list = get_bucket_objects(client, bucket_doc['bucket_name'])
            objects_access = []
            for obj in object_list:
                object_actions = object_acl_analayzer(bucket_doc['bucket_name'], obj, client)
                object_access = acl_object_access_analyzer(object_actions)
                objects_access.append(object_access)
                if 'Public' in objects_access or 'ACP is public' in objects_access:
                    lightspin_status = 'Public'
                else:
                    lightspin_status = 'Not public'
    else:
        lightspin_status = 'Objects can be public'
    bucket_doc['lightspin_status'] = lightspin_status
    return bucket_doc

def get_access_scope(bucket_doc):
    """parameters:
        bucket_doc : dict
       description:
        For public buckets.
        This function determines the access scope of a public bucket based on the policy and the acl access scopes.
        It adds the access scope to the bucket doc and returns the new doc."""
    access_scope = None
    policy_access = None
    acl_access = None
    if bucket_doc['bucket_policy'] != {} and bucket_doc['bucket_policy_status']['PolicyStatus']['IsPublic']==True: #and type(bucket_doc['bucket_policy'])==str:
        policy_actions = policy_analyzer(bucket_doc)
        policy_access = policy_access_analyzer(policy_actions)
    if bucket_doc['bucket_acl'] != {} and len(bucket_doc['bucket_acl']['Grants']) > 1:
        acl_action = bucket_acl_analyzer(bucket_doc)
        acl_access = acl_bucket_access_analyzer(acl_action)
    if policy_access != None and acl_access == None:
        access_scope = policy_access
    elif policy_access == None and acl_access != None:
        access_scope = acl_access
    else:
        if policy_access == 'full access':
            access_scope = policy_access
        elif policy_access == 'unknown':
            access_scope = acl_access
        elif policy_access == 'read and write access':
            access_scope = policy_access
        else: #policy_access='write access'
            if acl_access != None:
                access_scope = 'read and write access'
            else:
                access_scope = policy_access
    bucket_doc['access_scope'] = access_scope
    return bucket_doc

def check_cross_account_access(bucket_doc):
    bucket_policy = {}
    bucket_doc['cross_account_attack'] = False
    path_a = "arn:aws:s3:::{bucket}/*".format(bucket=bucket_doc['bucket_name'])
    path_b = "arn:aws:s3:::{bucket}/AWSLogs/*".format(bucket=bucket_doc['bucket_name'])
    path_c = "arn:aws:s3:::{bucket}/AWSLogs/*/Config/*".format(bucket=bucket_doc['bucket_name'])
    path_d = "arn:aws:s3:::{bucket}/AWSLogs/*/CloudTrail/*".format(bucket=bucket_doc['bucket_name'])
    if bucket_doc['bucket_policy'] != {}:
        bucket_policy = bucket_doc['bucket_policy']['Policy']
    policy_dict = None
    if type(bucket_policy) == str:
        policy_dict = jsons.loads(bucket_policy)
    elif type(bucket_policy) == dict:
        policy_dict = bucket_policy
    if policy_dict != {}:
        for statement in policy_dict['Statement']:
            if statement['Principal']=='*':
                if statement['Action'] == "s3:PutObject":
                    if statement['Resource'] in [path_a, path_b, path_c, path_d]:
                        bucket_doc['cross_account_attack'] = True
            elif 'Service' in statement['Principal'].keys():
                if statement['Principal']['Service'] == "config.amazonaws.com" or statement['Principal']['Service'] == "cloudtrail.amazonaws.com":
                    if statement['Action'] == "s3:PutObject":
                        if statement['Resource'] in [path_a, path_b, path_c, path_d]:
                            bucket_doc['cross_account_attack'] = True
    return bucket_doc

def complete_doc(client, bucket_name):
    """parameters:
        client :
        bucket_name : str
       description:
        This function creates the complete bucket doc, with all the relevant conclusions."""
    bucket_doc = get_bucket_doc(client, bucket_name)
    bucket_obj = create_bucket_object(AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID, bucket_name=bucket_name)
    bucket_with_status = get_bucket_status(bucket_doc)
    #bucket_with_object_num = get_objects_num(bucket_obj, bucket_with_status)
    bucket_with_object_num = get_objects_num(client, bucket_with_status)
    bucket_with_lightspin_status = get_lightspin_status(client, bucket_with_object_num)
    if bucket_with_lightspin_status['lightspin_status'] == 'Public':
        bucket_with_access_scope = get_access_scope(bucket_with_lightspin_status)
    elif bucket_with_lightspin_status['lightspin_status'] == 'Objects can be public':
        bucket_with_lightspin_status['access_scope'] = 'No Public Bucket Access'
        bucket_with_access_scope = bucket_with_lightspin_status
    else:
        bucket_with_lightspin_status['access_scope'] = 'No Public Access'
        bucket_with_access_scope = bucket_with_lightspin_status
    bucket_doc_with_objects = get_doc_objects(client, bucket_with_access_scope)
    bucket_doc_cross_account = check_cross_account_access(bucket_doc_with_objects)
    return bucket_doc_cross_account

def get_bucket_for_csv(bucket_doc):
    """parameters:
        bucket_doc : dict
       description:
        This function creates and returns a list of the bucket doc fields that will be written to the output csv file."""
    bucket_list = []
    if bucket_doc['objects'] == {}:
        bucket_list = [bucket_doc['bucket_name'], bucket_doc['objects_count'], bucket_doc['status'], bucket_doc['lightspin_status'], bucket_doc['access_scope'], bucket_doc['cross_account_attack']]
    else:
        bucket_list.append([bucket_doc['bucket_name'], bucket_doc['objects_count'], bucket_doc['status'], bucket_doc['lightspin_status'], bucket_doc['access_scope'], bucket_doc['cross_account_attack']])
        for key in list(bucket_doc['objects'].keys()):
            if bucket_doc['objects'][key] != 'Not public':
                object_list = [None, None, None, None, None, None, key]
                bucket_list.append(object_list)
    return bucket_list


def csv_export(buckets_doc_list, dest_path):
    """parameters:
        buckets_doc_list : list
        dest_path : str
       description:
        This function exports the data into a csv file"""
    with open(dest_path, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(["bucket", "objects amount", "aws status", "lightspin status", "bucket access scope", "cross_account_attack", "public objects"])
        for bucket in buckets_doc_list:
            if type(bucket[0]) != list:
                writer.writerow(bucket)
            else:
                for obj in bucket:
                    writer.writerow(obj)

def main():
    session = create_session(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    client = session[0]
    response = session[1]
    bucket_names = get_bucket_names(response)
    bucket_doc_list = []
    for name in bucket_names:
        bucket_doc = complete_doc(client, name)
        bucket_csv = get_bucket_for_csv(bucket_doc)
        bucket_doc_list.append(bucket_csv)
    csv_export(bucket_doc_list, CSV_PATH)

if __name__ == '__main__':
    main()
