#!/usr/bin/env python
"""Usage: awsler.py [ -i --instance <instance_id> ]

Run live response-style incident response scripts against a set of AWS
instances, or a single AWS instance.

Arguments:
    <instance_id>   AWS 8- or 17-digit instance ID, e.g. 'i-25e7d81490b27176b'

Options:
    -h --help       Show this help message and exit
    --version       Show version and exit
    -v --verbose    Verbose mode

"""
import boto3
import logging
import time
from docopt import docopt
from pprint import pprint

logging.basicConfig()
logger = logging.getLogger('awsler')
logger.setLevel(logging.DEBUG)

INCIDENT = 'SECURITY-123-testing'
INSTANCE = 'i-02e94b2c82d81d2ab'
OUTFILE = '/tmp/{incident}-{instance}-{timestamp!s}.txt'.format(
    incident=INCIDENT,
    instance=INSTANCE,
    timestamp=time.time(),
)
S3DEST = 's3://aws_bucket_name/liveresponse/'\
         '{incident}/{instance}/'.format(
            incident=INCIDENT,
            instance=INSTANCE,
         )
S3COPY = '/usr/bin/aws '\
         's3 cp --region=us-east-2 --acl=bucket-owner-full-control --'


def assume_role():
    arn = 'arn:aws:iam::012345678912:role/IRrole'
    role_session_name = 'username-' + 'live-response-' + INCIDENT

    logger.debug("Attempting assume role to ARN \'{0}\'.".format(arn))
    stsclient = boto3.client('sts')
    role = stsclient.assume_role(RoleArn=arn,
                                 RoleSessionName=role_session_name)
    return role


def get_client(role):
    region = 'us-east-1'

    logger.debug("Building the client.")
    client = boto3.client(
        'ssm',
        region_name=region,
        aws_access_key_id=role['Credentials']['AccessKeyId'],
        aws_secret_access_key=role['Credentials']['SecretAccessKey'],
        aws_session_token=role['Credentials']['SessionToken'],
    )
    return client


def locate_instance(instance):
    pass


def send_command(client):
    logger.debug("Sending commands.")
    #  We can later exchange these for our trusted binaries.
    #  TODO: script fuser -v -n tcp <all listening>, xclip?
    #  Note that the xargs commands require piping from others; for example,
    #  "authkeys" must be fed from the "homedirs" command.
    commands = {
        "aptinstalled": "/usr/bin/apt list --installed",
        "arp": "/usr/sbin/arp -a",
        "authkeys": "/usr/bin/xargs -I HOMEDIR /bin/sh -c "
                    "/bin/echo \#################### /bin/cat "
                    "HOMEDIR/.authorized_keys; "
                    "/bin/cat HOMEDIR/bash_history;",
        "bashhistory": "/usr/bin/xargs -I HOMEDIR /bin/sh -c "
                       "'/bin/echo \#################### /bin/cat "
                       "HOMEDIR/.bash_history; /bin/cat HOMEDIR/bash_history;'",
        "cat": "/bin/cat",
        "cronfiles": "/usr/bin/find /etc/cron.* -type f | "
                     "xargs -I CRONFILE /bin/sh -c "
                     "'/bin/echo \#################### /bin/cat CRONFILE; "
                     "/bin/cat CRONFILE;'",
        "crontab": "/etc/crontab",
        "date": "/bin/date",
        "ec2metadata": "/usr/bin/ec2metadata",
        "echo": "/bin/echo",
        "fstab": "/etc/fstab",
        "homedirs": "/usr/bin/getent passwd | /usr/bin/cut -d : -f 6 | "
                    "/bin/egrep ^/home ",
        "hostname": "/bin/hostname --fqdn",
        "hosts": "/etc/hosts",
        "ifconfig": "/sbin/ifconfig -a",
        "kversion": "/proc/version",
        "last": "/usr/bin/last",
        "lastlog": "/usr/bin/lastlog",
        "lsmod": "/sbin/lsmod",
        "lsof": "/usr/sbin/lsof",
        "meminfo": "/proc/meminfo",
        "mount": "/bin/mount",
        "netstat": "/bin/netstat -anp",  # Use sudo
        "passwd": "/etc/passwd",
        "pidstat": "/usr/bin/pidstat -p ALL",
        "printenv": "/usr/bin/printenv",
        "ps": "/bin/ps -auxfw",
        "pstree": "/usr/bin/pstree -cplZ",
        "resolv": "/etc/resolv.conf",
        "route": "/sbin/route -n",
        "sar": "/usr/bin/sar -A",
        "shadow": "/etc/shadow",
        "service": "/usr/sbin/service --status-all",
        "sudo": "/usr/bin/sudo",
        "top": "/usr/bin/top -n 1 -b",
        "uid": "/usr/bin/id",
        "uname": "/bin/uname -a",
        "uptime": "/usr/bin/uptime",
        "whoami": "/usr/bin/whoami",
        "w": "/usr/bin/w --ip-addr",
        }
    response = client.send_command(
        InstanceIds=[
            INSTANCE,
        ],
        DocumentName='AWS-RunShellScript',
        Comment=INCIDENT,
        Parameters={
            #  TODO: Allow instances to download a script, and trusted
            #  binaries, to take these actions, instead of executing untrusted
            #  binaries on the host.
            'commands': [
                #  start date / time
                '{date} >> {outfile};' \
                #  aptinstalled
                '{echo} {sep} {aptinstalled} >> {outfile};' \
                '{aptinstalled} >> {outfile};' \
                #  arp
                '{echo} {sep} {arp} >> {outfile};' \
                '{arp} >> {outfile};' \
                #  authkeys
                '{echo} {sep} cat /home/*/.authorized_keys >> {outfile};' \
                '{homedirs} {authkeys} >> {outfile};' \
                #  bashhistory
                '{echo} {sep} cat /home/*/.bash_history >> {outfile};' \
                '{homedirs} {bashhistory} >> {outfile};' \
                #  cronfiles
                '{echo} {sep} cronfiles >> {outfile};' \
                '{cronfiles} >> {outfile};' \
                #  crontab
                '{echo} {sep} {crontab} >> {outfile};' \
                '{cat} {crontab} >> {outfile};' \
                #  ec2metadata
                '{echo} {sep} {ec2metadata} >> {outfile};' \
                '{ec2metadata} >> {outfile};' \
                #  fstab
                '{echo} {sep} {fstab} >> {outfile};' \
                '{cat} {fstab} >> {outfile};' \
                #  hostname
                '{echo} {sep} {hostname} >> {outfile};' \
                '{hostname} >> {outfile};' \
                #  hosts
                '{echo} {sep} {cat} {hosts} >> {outfile};' \
                '{cat} {hosts} >> {outfile};' \
                #  ifconfig
                '{echo} {sep} {ifconfig} >> {outfile};' \
                '{ifconfig} >> {outfile};' \
                #  kversion
                '{echo} {sep} {cat} {kversion} >> {outfile};' \
                '{cat} {kversion} >> {outfile};' \
                #  last
                '{echo} {sep} {last} >> {outfile};' \
                '{last} >> {outfile};' \
                #  lastlog
                '{echo} {sep} {lastlog} >> {outfile};' \
                '{lastlog} >> {outfile};' \
                #  lsmod
                '{echo} {sep} {lsmod} >> {outfile};' \
                '{lsmod} >> {outfile};' \
                #  lsof
                '{echo} {sep} {lsof} >> {outfile};' \
                '{lsof} >> {outfile};' \
                #  meminfo
                '{echo} {sep} {cat} {meminfo} >> {outfile};' \
                '{cat} {meminfo} >> {outfile};' \
                #  mount
                '{echo} {sep} {mount} >> {outfile};' \
                '{mount} >> {outfile};' \
                #  netstat
                '{echo} {sep} {netstat} >> {outfile};' \
                '{netstat} >> {outfile};' \
                #  passwd
                '{echo} {sep} {cat} {passwd} >> {outfile};' \
                '{cat} {passwd} >> {outfile};' \
                #  pidstat
                '{echo} {sep} {pidstat} >> {outfile};' \
                '{pidstat} >> {outfile};' \
                #  printenv
                '{echo} {sep} {printenv} >> {outfile};' \
                '{printenv} >> {outfile};' \
                #  ps
                '{echo} {sep} {ps} >> {outfile};' \
                '{ps} >> {outfile};' \
                #  pstree
                '{echo} {sep} {pstree} >> {outfile};' \
                '{pstree} >> {outfile};' \
                #  resolv
                '{echo} {sep} {resolv} >> {outfile};' \
                '{cat} {resolv} >> {outfile};' \
                #  route
                '{echo} {sep} {route} >> {outfile};' \
                '{route} >> {outfile};' \
                #  sar
                '{echo} {sep} {sar} >> {outfile};' \
                '{sar} >> {outfile};' \
                #  service
                '{echo} {sep} {service} >> {outfile};' \
                '{service} >> {outfile};' \
                #  shadow
                '{echo} {sep} {cat} {shadow} >> {outfile};' \
                '{cat} {shadow} >> {outfile};' \
                #  top
                '{echo} {sep} {top} >> {outfile};' \
                '{top} >> {outfile};' \
                #  uid
                '{echo} {sep} {uid} >> {outfile};' \
                '{uid} >> {outfile};' \
                #  uname
                '{echo} {sep} {uname} >> {outfile};' \
                '{uname} >> {outfile};' \
                #  uptime
                '{echo} {sep} {uptime} >> {outfile};' \
                '{uptime} >> {outfile};' \
                #  whoami
                '{echo} {sep} {whoami} >> {outfile};' \
                '{whoami} >> {outfile};' \
                #  w
                '{echo} {sep} {w} >> {outfile};' \
                '{w} >> {outfile};' \
                #  end date / time
                '{date} >> {outfile};'.format(
                    aptinstalled=commands['aptinstalled'],
                    arp=commands['arp'],
                    authkeys=commands['authkeys'],
                    bashhistory=commands['bashhistory'],
                    cat=commands['cat'],
                    cronfiles=commands['cronfiles'],
                    crontab=commands['crontab'],
                    date=commands['date'],
                    ec2metadata=commands['ec2metadata'],
                    echo=commands['echo'],
                    fstab=commands['fstab'],
                    homedirs=commands['homedirs'],
                    hostname=commands['hostname'],
                    hosts=commands['hosts'],
                    uid=commands['uid'],
                    ifconfig=commands['ifconfig'],
                    kversion=commands['kversion'],
                    last=commands['last'],
                    lastlog=commands['lastlog'],
                    lsmod=commands['lsmod'],
                    lsof=commands['lsof'],
                    meminfo=commands['meminfo'],
                    mount=commands['mount'],
                    netstat=commands['netstat'],
                    outfile=OUTFILE,
                    passwd=commands['passwd'],
                    pidstat=commands['pidstat'],
                    printenv=commands['printenv'],
                    ps=commands['ps'],
                    pstree=commands['pstree'],
                    resolv=commands['resolv'],
                    route=commands['route'],
                    sar=commands['sar'],
                    sep='\##############################',
                    shadow=commands['shadow'],
                    service=commands['service'],
                    sudo=commands['sudo'],
                    top=commands['top'],
                    uname=commands['uname'],
                    uptime=commands['uptime'],
                    whoami=commands['whoami'],
                    w=commands['w'],
                 ),
                '{s3copy} {outfile} {s3dest}'.format(
                    s3copy=S3COPY,
                    outfile=OUTFILE,
                    s3dest=S3DEST,
                )
            ]
        }
    )
    command_id = response['Command']['CommandId']
    logger.debug("Full response was:\n" + str(response))
    logger.debug("Returning command_id")
    return command_id


def get_command_status(client, command_id, instance_id):
    logger.debug("Getting command status for " + command_id +
                 " run on instance " + instance_id)
    return client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id,
    )['Status']


def get_command_result(client, command_id, instance_id):
    logger.debug("Getting command result for " + command_id +
                 " run on instance " + instance_id)

    #  TODO: Handle possible botocore.errorfactory.InvocationDoesNotExist
    logger.debug("Waiting for invocation to exist...")
    time.sleep(2)

    return client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id,
    )


def main():
    role = assume_role()
    client = get_client(role)
    command_id = send_command(client)
    waiting = 0
    while waiting < 8:
        result = get_command_result(client, command_id, INSTANCE)
        if result['StatusDetails'] != 'Success':
            logger.debug("StatusDetails is \"" + result['StatusDetails'] +
                         ",\" sleeping 2...")
            waiting += 1
            time.sleep(2)
        else:
            logger.debug("StatusDetails \"Success\" returned:")
            pprint(result)
            break
    else:
        logger.debug("Done trying, ended with result: ")
        logger.debug(pprint(result))

if __name__ == "__main__":
    arguments = docopt(__doc__, version='awsler.py 0.3')
    print(arguments)
    main()
