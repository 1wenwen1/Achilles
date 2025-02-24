import json
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.request import CommonRequest

# Read the configuration file
with open("/root/Achilles/deployment/config.json", "r") as f:
    config = json.load(f)

region_id = config["region_id"]
access_key_id = config["access_key_id"]
access_key_secret = config["access_key_secret"]
instance_type = config["instance_type"]
instance_count = config["instance_count"]
image_id = config["image_id"]
security_group_id = config["security_group_id"]
instance_name_prefix = config["instance_name_prefix"]
key_pair_name = config["key_pair_name"]
vpc_id = config["vpc_id"]
vswitch_id = config["vswitch_id"]

# Create an ECS instance function
def create_ecs_instances():
    client = AcsClient(access_key_id, access_key_secret, region_id)

    request = CommonRequest()
    request.set_accept_format('json')
    request.set_domain('ecs.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_version('2014-05-26')
    request.set_action_name('RunInstances')

    request.add_query_param('InstanceType', instance_type)
    request.add_query_param('ImageId', image_id)
    request.add_query_param('RegionId', region_id)
    request.add_query_param('SecurityGroupId', security_group_id)
    request.add_query_param('InstanceName', instance_name_prefix)
    request.add_query_param('InternetMaxBandwidthOut', '100')  # Pay as you use
    request.add_query_param('SystemDisk.Category', 'cloud_essd')
    request.add_query_param('VpcId', vpc_id)
    request.add_query_param('VSwitchId', vswitch_id)
    request.add_query_param('InstanceChargeType', 'PostPaid')  # Pay by volume
    request.add_query_param('KeyPairName', key_pair_name)  # Set the key pair
    request.add_query_param('SecurityOptions.TrustedSystemMode', 'vTPM')
    request.add_query_param('UniqueSuffix', 'true')  # Set an orderly instance name
    # request.add_query_param('AutoReleaseTime', '2024-06-01T12:00:00Z')  # Automatic release time
    request.add_query_param('Amount', instance_count)  #  the number of instances

    try:
        response = client.do_action_with_exception(request)
        print("Instances created successfully.")
        instance_ids = json.loads(response.decode('utf-8'))["InstanceIdSets"]["InstanceIdSet"]
        # Save the instance ID to the file
        with open("/root/Achilles/deployment/instances.txt", "a") as f:
            for instance_id in instance_ids:
                f.write(f"{instance_id}\n")
    except ServerException as e:
        print(f"Error creating instances: {e}")

# Create an instance
create_ecs_instances()

