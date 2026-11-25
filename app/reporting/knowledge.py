# One written reason and fix per rule. A test checks every rule has an entry.
KNOWLEDGE = {
    "sg-admin-open": {
        "why": "Anyone on the internet can try to log in to this resource. Automated attackers look for open SSH and remote desktop ports all the time.",
        "fix": "Limit the rule to your office or VPN address range, or use a tool such as AWS Systems Manager Session Manager so no inbound admin port is needed.",
    },
    "sg-db-ports-open": {
        "why": "A database port reachable from the internet can be attacked directly, and one weak or leaked password becomes a breach.",
        "fix": "Allow the database port only from the application's own security group or private address range.",
    },
    "sg-all-traffic-open": {
        "why": "Every port on the resource is reachable from anywhere, including ports that were never meant to be public.",
        "fix": "Replace the rule with rules for only the ports the service needs, from only the sources that need them.",
    },
    "s3-no-public-access-block": {
        "why": "Without the public access block, one wrong bucket policy or permission setting can expose files to the internet.",
        "fix": "Turn on all four Block Public Access settings for the bucket, unless it is deliberately a public website.",
    },
    "rds-public": {
        "why": "The database is set to accept connections from outside your private network. Its security group may still limit who connects, but it adds a path in from the internet.",
        "fix": "Turn off public access and connect through your private network, a VPN or a bastion host.",
    },
    "rds-no-backups": {
        "why": "With no automatic backups, a deleted or damaged database cannot be restored to an earlier point in time.",
        "fix": "Set a backup retention period of at least several days. Many teams use seven or more.",
    },
    "rds-unencrypted": {
        "why": "The data on the database's disks, and its backups, is not encrypted at rest.",
        "fix": "Encryption cannot simply be switched on for an existing database. Create an encrypted copy from a snapshot and switch over in a planned window.",
    },
    "ec2-imdsv1": {
        "why": "The older metadata service can be tricked by some web application bugs into revealing the server's temporary credentials.",
        "fix": "Require the newer version (IMDSv2) after checking that the software on the server supports it.",
    },
    "ebs-unattached": {
        "why": "A disk that is not attached to a server still bills for its full size every month.",
        "fix": "Confirm nobody needs it, take a snapshot if the data might matter, then delete the volume.",
    },
    "ebs-gp2": {
        "why": "gp3 disks cost less per gigabyte than gp2 and include a free baseline of performance.",
        "fix": "Change the volume type to gp3, after checking that the disk's performance needs fit gp3's baseline.",
    },
    "snapshot-old": {
        "why": "Old snapshots keep billing for the data they hold and are rarely needed after a retention period.",
        "fix": "Set a retention policy, for example with Amazon Data Lifecycle Manager, and delete snapshots past it after checking they are not the only copy.",
    },
    "eip-unassociated": {
        "why": "AWS charges for every public IPv4 address, and an address that is attached to nothing is pure cost.",
        "fix": "Release the Elastic IP address if nothing needs it.",
    },
}