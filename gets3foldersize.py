import boto3

def getdirsizesummary(bucketname):
    dirsizedict = {}
    dirsizedict['.'] = 0
    s3 = boto3.resource('s3')
    s3client = boto3.client('s3')
    try:
        response = s3client.head_bucket(Bucket=bucketname)
    except:
        print('Bucket ' + bucketname + ' does not exist or is unavailable. - Exiting')
        quit()
    paginator = s3client.get_paginator('list_objects')
    pageresponse = paginator.paginate(Bucket=bucketname)
    for pageobject in pageresponse:
        if 'Contents' in pageobject.keys():
            for file in pageobject['Contents']:
                itemtocheck = s3.ObjectSummary(bucketname, file['Key'])
                keylist = file['Key'].split('/')
                if len(keylist) == 1:
                    dirsizedict['.'] += itemtocheck.size
                else:
                    if keylist[0] in dirsizedict:
                        dirsizedict[keylist[0]] += itemtocheck.size
                    else:
                        dirsizedict[keylist[0]] = itemtocheck.size

    return dirsizedict

if __name__ == "__main__":
    print (getdirsizesummary('AAA'))

### Assuming we can authenticte directly
### Assuming there are only 1000 items in the bucket as that is the current limit
### if there is no direct authentication we need to get iam access key and id to authenticate
