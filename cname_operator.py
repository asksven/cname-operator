from azure.mgmt.dns import DnsManagementClient
from azure.identity import DefaultAzureCredential
import os
import re
import kopf


# Create the DNSZone client
sub_id = os.getenv("AZURE_SUBSCRIPTION_ID")
dns_zone = os.getenv("AZURE_DNS_ZONE")
rg = os.getenv("AZURE_DNS_ZONE_RESOURCE_GROUP")
client = DnsManagementClient(credential=DefaultAzureCredential(), subscription_id=sub_id)

# Read constants
ttl = os.getenv("RECORD_TTL")
cname_domain=os.getenv("CNAME_DOMAIN")
host_domain=os.getenv("HOST_DOMAIN")

# this function normalizes the hostname to the DNSZone's domain
# e.g. hostname = foo.baz.bar
# and dns_zone = bar
# result is foo.baz
def normalize_hostname(hostname):
    ret = ''
    print("normalize_hostname called with {h} and dns zone {d}".format(h=hostname, d=dns_zone))
    if dns_zone in hostname:
        ret=hostname.replace("{}{}".format('.',dns_zone), '')
    else:
        ret=''  

    return ret       
    
def create_or_update_cname(logger, host, cname):
    normalized_hostname = normalize_hostname(host)
    logger.info("hostname to be updated : {h}".format(h=normalized_hostname))
    if normalized_hostname:
        record_set = client.record_sets.create_or_update(
            resource_group_name=rg,
            zone_name=dns_zone,
            relative_record_set_name=normalized_hostname,
            record_type='CNAME',
            parameters={
                    "cnamerecord": {"cname": cname},
                    "ttl": ttl
            }
        )
        logger.info("Created/updated CNAME for {r}".format(r=record_set.cname_record))
    else:
        logger.error("CNAME for {r} not updated since hostname {h} is not in {z}".format(r=record_set.cname_record, h=normalized_host, z=dns_zone))

def delete_cname(logger, host):
    normalized_host = normalize_hostname(host)
    record_set = client.record_sets.delete(
        resource_group_name=rg,
        zone_name=dns_zone,
        relative_record_set_name=normalized_host,
        record_type='CNAME'
    )
    logger.info("Deleted CNAME for host {r}".format(r=host))    

def get_hosts_from_ingress(ingress, logger):
    hosts = []
    for rule in ingress['spec']['rules']:
        if 'host' in rule:
            hostname=rule['host']
#            first_part = rule['host'].split(".")[0]
            logger.info("Found hostname {h}".format(h=hostname))
            hosts.append(hostname)
    return hosts

def get_hosts_from_spec(spec, logger):
    hosts = []
    for rule in spec['rules']:
        if 'host' in rule:
            hostname=rule['host']
#            first_part = rule['host'].split(".")[0]
            logger.info("Found hostname {h}".format(h=hostname))
            hosts.append(hostname)
    return hosts

def check_if_cname_valid(cname, logger):
    # todo: validate on *.impervadns.net
    pattern = '^[a-z0-9-]+\.{domain}$'.format(domain=cname_domain)
    result = bool(re.fullmatch(pattern, cname))
    logger.info(">>>Testing cname {c} against pattern {p} resulted in {r}".format(c=cname, p=pattern, r=result))

    return result

def check_if_host_valid(host, logger):
    # todo: validate against what we defined as the managed subdomain
    pattern = '^[a-z0-9-]+\.{domain}$'.format(domain=host_domain)
    result = bool(re.fullmatch(pattern, host))
    logger.info(">>>Testing host {h} against pattern {p} resulted in {r}".format(h=host, p=pattern, r=result))
    
    
    return result


####### Operator #######
@kopf.on.create(kind='Ingress',
                annotations={'cname': kopf.PRESENT})
async def create_with_annotations_present(logger, new, **kwargs):
    logger.info("Annotation is present, object is {v}".format(v=new))

    cname=new['metadata']['annotations']['cname']

    logger.info("Ingress was created with cname-annotation. Value is {v}".format(v=cname))
    if check_if_cname_valid(cname, logger):
        logger.info("Creating/updating cname")
        
        hosts = get_hosts_from_ingress(new, logger)
        # create all cnames fo valid hosts
        applied_hosts = []
        for entry in hosts:
            if check_if_host_valid(entry, logger):
                # update
                create_or_update_cname(logger=logger, host=entry, cname=cname)
                applied_hosts.append(entry)
            else:
                logger.error("Hostname {host} did not get applied because it did not match {r}".format(host=entry, r=host_domain))    
        return {'status': "Applied hosts: {hosts}".format(hosts=applied_hosts)}    
    else:
        logger.error("CNAME {c} did not get applied because it did not match {r}".format(c=new, r=cname_domain))    
        return {'status': "Name {n} invalid".format(n=new)}

@kopf.on.update(kind='Ingress', annotations={'cname': kopf.PRESENT})
async def update_with_annotations_present(logger, old, new, **kwargs):
    logger.info("Old: {v}".format(v=old))
    logger.info("New: {v}".format(v=new))

    cname_new=new['metadata']['annotations']['cname']
    hosts_old = []
    hosts = []
    if ( "metadata" in old) and ("annotations" in old['metadata']) and ("cname" in old['metadata']['annotations']):
        # old exists: remove the old CNAME
        cname_old=old['metadata']['annotations']['cname']
        logger.info("Ingress was updated with a new value of the cname annotation. old value is {o}, new value is {n}".format(
                o=cname_old,
                n=cname_new))
        hosts_old = get_hosts_from_ingress(old, logger)
        hosts = get_hosts_from_ingress(new, logger)

    else:
        # annotation was just added
        logger.info("Ingress was added the cname annotation: {n}".format(n=cname_new))
        hosts = get_hosts_from_ingress(new, logger)

    if check_if_cname_valid(cname_new, logger):
        # hosts may have changed: we need to diff them    
        # remove all cnames from hosts_old that are not in hosts, if any
        for entry in hosts_old:
            if entry not in hosts:
                # remove
                delete_cname(logger=logger, host=entry)
        
        # update all left cnames
        for entry in hosts:
            if check_if_host_valid(entry, logger):
                # update
                create_or_update_cname(logger=logger, host=entry, cname=cname_new)
    else:
        # set error
        logger.error("The cname {c} is invalid".format(c=cname_new))
         
        


@kopf.on.update(kind='Ingress', annotations={'cname': kopf.ABSENT})
async def update_with_annotations_removed(logger, old, new, **kwargs):
    logger.info("Annotation was removed from ingress.")
    logger.info("Old: {v}".format(v=old))
    hosts_old = get_hosts_from_ingress(old, logger)
    for entry in hosts_old: 
        # we don't need to remove what was not applied because invalid
        if check_if_host_valid(entry, logger):
            delete_cname(logger=logger, host=entry)
   



#    delete_cname(logger, host)

@kopf.on.delete(kind='Ingress', annotations={'cname': kopf.PRESENT})
async def delete_with_annotations_present(logger, spec, **kwargs):
    logger.info("Ingress was deleted.")
    logger.info("Old: {v}".format(v=spec))

    hosts_old = get_hosts_from_spec(spec, logger)
    for entry in hosts_old:
        # we don't need to remove what was not applied because invalid
        if check_if_host_valid(entry, logger):
            # delete
            delete_cname(logger=logger, host=entry)
 


