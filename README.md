# boot_aws_chef_instances

installation

      git clone https://github.com/giuliocalzolari/boot_aws_chef_instances.git
      pip install -r ./requirements.txt
      - crete your config.yaml
      chmod 755 boot.py
      ./boot.py -a create -i linux01

Example of config.yaml

      aws_access_key_id: "AAAAAAAAAAAAAAAA"
      aws_secret_access_key: "BBBBBBBBBBBBBBBBBBBBBBBBB"
      aws_region: eu-west-1
      profile: your_profile


      global_config: &default_value
        ssh-user: centos
        ssh-key: ~/.ssh/private.key
        iam-profile: iam_role_s3
        flavor: m4.2xlarge
        image: ami-12345
        ebs-size: "150"
        ebs-volume-type: gp2
        region: eu-west-1
        associate-public-ip: ""
        server-connect-attribute: public_ip_address



      environment:
        development:
          linux01:
            security-group-ids: sg-12345
            tags: Name=linux01,Role=Web,Platform=Test
            availability-zone: eu-west-1a
            subnet: subnet-123456
            run-list: 'role[web]'
            private-ip-address: 10.0.0.10
            <<: *default_value
          linux02:
            security-group-ids: lookupSG(DBSecurityGroup)
            tags: Name=linux02,Role=DB,Platform=Test
            availability-zone: eu-west-1b
            subnet: lookupSubnet(PrivateSubnet)
            run-list: 'role[db]'
            private-ip-address: 10.0.0.20
            <<: *default_value
