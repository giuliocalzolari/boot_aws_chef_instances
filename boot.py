#!/usr/bin/env python
#


import argparse
import logging
import time
import glob
import json
import os, sys
import yaml
import re
import boto
import boto.ec2.elb
import boto.utils
import boto.ec2
import boto.vpc
import boto.s3.connection
from cli.log import LoggingApp
from boto.exception import EC2ResponseError

__author__ = ['Giulio.Calzolari']

class BootEnv(LoggingApp):

    def connect_boto(self):
        region = boto.ec2.get_region(self.config["aws_region"], aws_access_key_id=self.config["aws_access_key_id"], aws_secret_access_key=self.config["aws_secret_access_key"])
        self.conn = boto.connect_ec2( aws_access_key_id=self.config["aws_access_key_id"], aws_secret_access_key=self.config["aws_secret_access_key"],region=region)


    def quote_argument(self,argument):
        return '%s' % (
            argument
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('$', '\\$')
            .replace('`', '\\`')
        )

    def is_ip_private(self,ip):
        priv_lo = re.compile("^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        priv_24 = re.compile("^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        priv_20 = re.compile("^192\.168\.\d{1,3}.\d{1,3}$")
        priv_16 = re.compile("^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")
        if priv_lo.match(ip) or priv_24.match(ip) or priv_20.match(ip) or priv_16.match(ip):
            return True
        else:
            return False

    def execute_cmd(self,cmd,argvs=None):
        if len(argvs) > 0:
            for argv in argvs:
                if argv in ["aws_ssh_argv"]:
                    continue
                cmd +=str(" --"+argv+' '+self.quote_argument(argvs[argv]))

        self.log.info(cmd)
        os.system(cmd)
        return



    def wait_for_state (self,instance, target_state):
        """
        Waits for instance to move to desired state
        """

        status = instance.update ()
        while status != target_state:
            self.log.info ('Waiting for instance %s to be in \'%s\' state' % (instance.id, target_state))
            time.sleep (5)
            status = instance.update ()

    def terminate_with_vols_instance (self,instance_id):
        """
        Terminates instance with all attached volumes
        """
        return self.terminate_instance ( instance_id, True)

    def terminate_instance (self, instance_id, delete_vols=False):
        """
        Gets a connection object and instance id
        Kills an instance, meaning terminating it and, if asked for, making sure all attached volumes
        are deleted
        """
        if delete_vols:
            self.log.info ('Killing instance %s and all its attached volumes' % instance_id)
        else:
            self.log.info ('Terminating instance %s' % instance_id)
        # gets instance
        try:
            instance = self.conn.get_all_instances (instance_ids=[instance_id])[0].instances[0]
        except EC2ResponseError, e:
            self.log.error ('Could not kill instance %s. Error: %s' % (instance_id, e.error_message))
            return False

        # find block devices
        if delete_vols:
            vols_to_delete = []
            for bd in instance.block_device_mapping.values():
                if bd.delete_on_termination == False:
                    vols_to_delete.append (bd.volume_id)

        # terminate instance
        try:
            self.conn.terminate_instances (instance_ids=[instance_id])
        except EC2ResponseError, e:
            self.log.error ('Could not kill instance %s. Error: %s' % (instance_id, e.error_message))
            return False

        self.wait_for_state (instance, u'terminated')

        # deletes extra volumes
        if delete_vols:
            first_vol_delete = True
            for vol in vols_to_delete:
                for try_num in 1,2:
                    self.log.info ('Deleting attached volume %s, try number %d' % (vol, try_num))
                    try:
                        self.conn.delete_volume (vol)
                        break
                    except EC2ResponseError, e:
                        self.log.error ('Could not delete attached volume %s. Error: %s' % (vol, e.error_message))
                        if try_num == 1:
                            time.sleep (10)


        if delete_vols:
            self.log.info ('Successfully terminated instance %s with all attached volumes' % instance_id)
        else:
            self.log.info ('Successfully terminated instance %s' % instance_id)
        return True


    def _ssh_instance(self):
        filters = {"tag:Name" : self.params.instance,"tag:Environment" : self.params.environment, 'instance-state-name' : 'running'}
        reservations = self.conn.get_all_instances(filters=filters)
        found = False
        for res in reservations:
            for inst in res.instances:
                if self.config["aws_ssh_connect_ip"] == "public":
                    condition = False
                    check_ip = inst.ip_address
                elif self.config["aws_ssh_connect_ip"] == "private":
                    condition = True
                    check_ip = inst.private_ip_address
                else:
                    self.log.error("invalid mapping of aws_ssh_connect_ip  allowed value are public or private")
                    exit(1)


                if "aws_ssh_argv" in self.config["environment"][self.params.environment][self.params.instance]:
                    aws_ssh_argv = self.config["environment"][self.params.environment][self.params.instance]["aws_ssh_argv"]
                else:
                    aws_ssh_argv = self.config["aws_ssh_argv"]


                if self.is_ip_private(check_ip) == condition:
                    self.log.info ("Connecting to "+self.config["aws_ssh_connect_ip"]+" IP: "+check_ip)
                    found = True
                    os.system("ssh "+aws_ssh_argv+" "+check_ip)
                    break


        if found == False:
            self.log.error("No instances found - searched name: "+self.params.instance)
            exit(1)
        # self.execute_cmd("knife ec2 server create --environment "+self.params.environment+"  --node-name "+self.params.instance+" ",self.config["environment"][self.params.environment][self.params.instance])


    def _bootstrap_instance(self):
        filters = {"tag:Name" : self.params.instance,"tag:Environment" : self.params.environment, 'instance-state-name' : 'running'}
        reservations = self.conn.get_all_instances(filters=filters)
        found = False
        for res in reservations:
            for inst in res.instances:
                if self.config["aws_ssh_connect_ip"] == "public":
                    condition = False
                    check_ip = inst.ip_address
                elif self.config["aws_ssh_connect_ip"] == "private":
                    condition = True
                    check_ip = inst.private_ip_address
                else:
                    self.log.error("invalid mapping of aws_ssh_connect_ip  allowed value are public or private")
                    exit(1)

                parms = self.config["environment"][self.params.environment][self.params.instance]

                if "aws_ssh_argv" in parms:
                    aws_ssh_argv = parms["aws_ssh_argv"]
                else:
                    aws_ssh_argv = self.config["aws_ssh_argv"]


                if self.is_ip_private(check_ip) == condition:
                    self.log.info ("bootstrap to "+self.config["aws_ssh_connect_ip"]+" IP: "+check_ip)
                    found = True

                    cmd = "knife bootstrap "+check_ip+" --environment "+self.params.environment+"  --node-name "+self.params.instance+" "
                    cmd += " --ssh-user "+ parms["ssh-user"]
                    self.log.info(cmd)
                    os.system(cmd)
                    break


        if found == False:
            self.log.error("No instances found - searched name: "+self.params.instance)
            exit(1)
        # self.execute_cmd("knife ec2 server create --environment "+self.params.environment+"  --node-name "+self.params.instance+" ",self.config["environment"][self.params.environment][self.params.instance])



    def _create_instance(self):
        tags = { "Environment":self.params.environment  }
        tags.update(self.config["global_config"]["tags"])
        tags.update(self.config["environment"][self.params.environment][self.params.instance]["tags"])

        self.config["environment"][self.params.environment][self.params.instance]["tags"] =  "Name="+self.params.instance+","+','.join('%s=%s' % o for o in tags.items())

        self.execute_cmd("knife ec2 server create --environment "+self.params.environment+"  --node-name "+self.params.instance+" ",self.config["environment"][self.params.environment][self.params.instance])

    def _runchefclient_instance(self):
        parms = self.config["environment"][self.params.environment][self.params.instance]
        cmd = "knife ssh 'name:"+self.params.instance+"' 'sudo chef-client'  --environment "+self.params.environment+"  "
        cmd += " --ssh-user "+ parms["ssh-user"]

        self.log.info(cmd)
        os.system(cmd)


    def _delete_instance(self):

        confirm = raw_input("Do you want to delete: %s ?"
            " (type 'yes'): "
            % (self.params.instance))
        if confirm != "yes":
            self.log.warning("Abort..")
            exit(0)
        else:
            instance_id = None
            filters = {"tag:Name" : self.params.instance,"tag:Environment" : self.params.environment, 'instance-state-name' : 'running'}
            reservations = self.conn.get_all_instances(filters=filters)
            for res in reservations:
                for inst in res.instances:
                    instance_id = inst.id
                    break

            if instance_id:
                self.terminate_with_vols_instance(instance_id)
            else:
                self.log.error( "instances not found")


        os.system("knife node delete "+self.params.instance+" ")
        os.system("knife client delete "+self.params.instance+" ")


    def lookupSG(self,Name):
        groups = self.conn.get_all_security_groups()
        for group in groups:
            if group.name == Name:
                return group.id

        self.log.error("Error cannot find the SG "+ Name)
        quit("")

    def lookupSubnet(self,Name):
        region = boto.ec2.get_region(self.config["aws_region"], aws_access_key_id=self.config["aws_access_key_id"], aws_secret_access_key=self.config["aws_secret_access_key"])
        conn = boto.vpc.VPCConnection(region=region,aws_access_key_id=self.config["aws_access_key_id"],aws_secret_access_key=self.config["aws_secret_access_key"])

        subnets = conn.get_all_subnets()
        for subnet in subnets:
            if "Name" in subnet.tags:
                if subnet.tags["Name"] == Name:
                    return subnet.id

        self.log.error("Error cannot find the subnet "+ Name)
        quit("")

    def get_allowed_method(self):
        m = []
        for mth in dir(self):
            valid = re.match( r'^_(.*)_instance$', mth, re.M|re.I)
            if valid and valid.group(1) != "name":
                m.append(valid.group(1))
        return m

    def get_allowed_env(self):
        return self.config["environment"].keys()


    def main(self):
        """
        Tool for auto build instances using knife ec2 plugin and yaml config.
        """

        start = time.time()
        self.log.setLevel(20)

        # Validate that action is something we know what to do with
        valid_actions = self.get_allowed_method()
        if self.params.action not in valid_actions:
            self.log.error ("Invalid action provided, must be one of: '%s'"  % (", ".join(valid_actions)))
            exit(1)





        # Make sure we can read the yaml file provided
        try:
            open(self.params.yamlfile, 'r')
        except IOError as exception:
            self.log.error ("Cannot read yaml file %s: %s" % (self.params.yamlfile, exception))
            exit(1)


        try:
            self.config = yaml.load(open(self.params.yamlfile))
        except IOError as e:
            self.log.error("No Configuration file found at " + self.params.config)
            exit(1)


        valid_env = self.get_allowed_env()
        if self.params.environment not in valid_env:
            self.log.error ("Invalid environment provided, must be one of: '%s'"  % (", ".join(valid_env)))
            exit(1)

        if not self.params.instance in self.config["environment"][self.params.environment]:
            self.log.error ("Invalid instance provided, must be one of: '%s'"  % (", ".join(self.config["environment"][self.params.environment].keys())))
            exit(1)


        os.environ["OPSORGNAME"] = self.config["profile"]
        os.environ["AWS_DEFAULT_PROFILE"] = self.config["profile"]

        self.connect_boto()


        if self.params.action == "create":
            matchSG = re.match( r'^lookupSG\((.*)\)$', self.config["environment"][self.params.environment][self.params.instance]["security-group-ids"], re.M|re.I)
            if matchSG:
                self.log.info("Lookup SG:"+matchSG.group(1))
                self.config["environment"][self.params.environment][self.params.instance]["security-group-ids"] =self.lookupSG(matchSG.group(1))

            matchSubnet = re.match( r'^lookupSubnet\((.*)\)$', self.config["environment"][self.params.environment][self.params.instance]["subnet"], re.M|re.I)
            if matchSubnet:
                self.log.info("Lookup Subnet:"+matchSubnet.group(1))
                self.config["environment"][self.params.environment][self.params.instance]["subnet"] =self.lookupSubnet(matchSubnet.group(1))


            self.log.debug( self.config["environment"][self.params.environment][self.params.instance])
        # locals()[self.params.action+'_instance']()
        # getattr(self, self.params.action+'_instance')()

        try:
            getattr(self, '_%s_instance' % self.params.action )()
        except KeyboardInterrupt:
            self.log.warn("Exit")
            exit(0)


        end = time.time()
        self.log.info("")
        if (end - start) > 100:
            self.log.info("Execution time: %s min", round( (end - start) / 60 ,2))
        else:
            self.log.info("Execution time: %s sec", round(end - start,2))



if __name__ == "__main__":
    b=BootEnv()
    b.add_param(
        "-a", "--action",
        dest="action", required=True,
        help="The action to preform: %s" % (", ".join(b.get_allowed_method())))
    b.add_param(
        "-i", "--instance",
        dest="instance", required=True,
        help="Name of instance to build")
    b.add_param(
        "-e", "--environment",default="development",
        dest="environment", required=False,
        help="environment to build")
    b.add_param(
        "-y", "--yamlfile", default=os.path.abspath(os.path.dirname(__file__))+"/config.yaml",
        dest="yamlfile", required=False,
        help="main config file default( ./config.yaml )")

    b.run()
