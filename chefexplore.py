# -*- coding: utf-8 -*-

DESCRIPTION = """
    Script file chefexplore

    Author: Alexey Kolyanov, 2015

"""

import os
import sys
import yaml
import logging
import json
import argparse

from chefwrapper import ChefWrapper
import device42
from nodefilter import node_filter


logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter('%(asctime)-15s\t%(levelname)s\t %(message)s'))
logger.addHandler(ch)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="chefexplore", epilog=DESCRIPTION)

parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - outputs only errors')
parser.add_argument('-c', '--config', help='Config file', default='settings.yaml')
parser.add_argument('-f', '--nodefile', help='Get node info from JSON file instead of Chef server')
parser.add_argument('-S', '--savenodes', help='Save nodes info from Chef server to json file')
parser.add_argument('-n', '--onlynode', action='append', help='Process only selected nodes (fqdn or hostname)')

debugmode = False

# We have to restrict FS to only known types to avoid incorrect disk size calculatons
# add more yourself
ALLOWED_FSTYPES = ['ntfs', 'ext2', 'ext3', 'ext4', 'ocfs2', 'xfs', 'zfs', 'jfs',
                   'vfat', 'msdos', 'reiser4', 'reiserfs']


def get_config(cfgpath):
    config = {}
    if not os.path.exists(cfgpath):
        if not os.path.exists(os.path.join(CUR_DIR, cfgpath)):
            raise ValueError("Config file %s is not found!" % cfgpath)
        cfgpath = os.path.join(CUR_DIR, cfgpath)
    with open(cfgpath, 'r') as cfgf:
        config = yaml.load(cfgf.read())
    return config


def d42_update(dev42, nodes, options, static_opt, chefhost=None):

    # get customer info
    customer_name = static_opt.get('customer')
    customer_id = str(static_opt.get('customer_id') or '') or None
    if (not customer_id and customer_name) or (customer_id and not customer_name):
        allcustomers = dev42._get('customers')['Customers']
        for cst in allcustomers:
            if customer_id and str(cst['id']) == customer_id:
                customer_name = cst['name']
                break
            if customer_name and cst['name'] == customer_name:
                customer_id = str(cst['id'])
                break
    logger.debug("Customer %s: '%s'" % (customer_id, customer_name))

    # processing all nodes
    for node in nodes:
        if 'hostname' not in node:
            logger.debug("Skip node: no name found")
            continue
        node_name = node['hostname']
        if options.get('as_node_name').upper() == 'FQDN':
            node_name = node.get('fqdn', node_name)

        # filtering by attributes
        if options.get('node_filter'):
            if not node_filter(node, options['node_filter']):
                logger.info("Skip node %s: filter not passed" % node_name)
                continue  # filter not passed
        try:
            # device = dev42.get_device_by_name(node_name)

            # detect memory
            totalmem = '0'
            if 'memory' in node:
                # linux
                totalmem = node['memory']['total']
                if totalmem.endswith('kB'):
                    totalmem = int(totalmem[:-2]) / 1024
                elif totalmem.endswith('mB'):
                    totalmem = int(totalmem[:-2])
                elif totalmem.endswith('gB'):
                    totalmem = int(totalmem[:-2]) * 1024
                else:
                    totalmem = int(totalmem)
            else:
                # win
                totalmem = node.get('kernel', {}).get('cs_info', {}).get('total_physical_memory') or '0'
                totalmem = int(totalmem) / (1024 * 1024)

            # detect HDD
            hddcount = 0
            hddsize = 0  # first in bytes, then should be converted to Gb
            for devname, dev in node['filesystem'].items():
                fstype = dev.get('fs_type') or dev.get('fstype')
                if fstype not in ALLOWED_FSTYPES:
                    continue
                hddcount += 1
                size = int(dev.get('kb_size', 0)) * 1024
                hddsize += size
            hddsize = hddsize >> 30  # convert to Gb ( hddsize/ 1024**3 )

            nodetype = None
            is_virtual = 'no'
            virtual_subtype = None
            if node.get('virtualization'):
                # node['virtualization']['system']
                is_virtual = 'yes'
                nodetype = 'virtual'
            if node.get('kernel', {}).get('os_info', {}).get('registered_user') == 'EC2':
                is_virtual = 'yes'
                virtual_subtype = 'ec2'
                nodetype = 'virtual'

            data = {
                'name': node_name,
                'type': nodetype,
                'is_it_virtual_host': is_virtual,
                'virtual_subtype': virtual_subtype,
                'os': node['platform'],
                'osver': node['platform_version'],

                'memory': totalmem,
                'cpucount': node['cpu']['total'],
                'cpucore': node['cpu']['0'].get('cores', 0),
                'cpupower': int(float(node['cpu']['0']['mhz'])),
                'hddcount': hddcount,
                'hddsize': hddsize,

                'macaddress': node['macaddress'],
                'customer': customer_name,
                'service_level': static_opt.get('service_level'),
            }
            logger.debug("Updating node %s" % node_name)
            updateinfo = dev42.update_device(**data)
            deviceid = updateinfo['msg'][1]
            logger.info("Device %s updated/created (id %s)" % (node_name, deviceid))

            if chefhost:
                cfdata = {
                    'name': node_name,
                    'key': 'Chef Node ID',
                    'value': node_name,
                    'notes': 'Chef Server %s' % chefhost
                }
                updateinfo = dev42._put('device/custom_field', cfdata)

            # Dealing with IPs
            device_ips = dev42._get("ips", data={'device': node_name})['ips']
            updated_ips = []

            for ifsname, ifs in node['network']['interfaces'].items():
                if ifsname == 'lo':
                    continue  # filter out local interface
                if [aip for aip, a in ifs['addresses'].items() if aip.startswith('127.0')]:
                    continue  # local loopbacks
                macs = [aip for aip, a in ifs['addresses'].items() if a['family'] == 'lladdr']
                macaddr = None
                if macs:
                    macaddr = macs[0]
                for nodeip, addr in ifs['addresses'].items():
                    if addr['family'] == 'lladdr':
                        continue  # filter out mac

                    # update IP
                    ipdata = {
                        'ipaddress': nodeip,
                        'tag': ifsname,
                        'device': node_name,
                        'macaddress': macaddr,
                    }
                    # logger.debug("IP data: %s" % ipdata)
                    updateinfo = dev42._post('ips', ipdata)
                    updated_ips.append(updateinfo['msg'][1])
                    logger.info("IP %s for device %s updated/created (id %s)" % (nodeip, node_name, deviceid))

            # Delete other IPs from the device
            for d_ip in device_ips:
                if d_ip['id'] not in updated_ips:
                    dev42._delete('ips/%s' % d_ip['id'])
                    logger.debug("Deleted IP %s (id %s) for device %s (id %s)" %
                                 (d_ip['ip'], d_ip['id'], node_name, deviceid))
        except Exception as eee:
            logger.exception("Error(%s) updating device %s" % (type(eee), node_name))


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime("%Y %m %d %H:%M:%S")
        return json.JSONEncoder.default(self, o)


def main():
    global debugmode
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        debugmode = True
    if args.quiet:
        logger.setLevel(logging.ERROR)
        debugmode = False
    onlynodes = []
    if args.onlynode:
        onlynodes = args.onlynode

    config = get_config(args.config)

    if not args.nodefile:
        chef = ChefWrapper(
            host=config['chef_server']['host'],
            user=config['chef_server']['user'],
            key=config['chef_server'].get('key'),
            key_file=config['chef_server'].get('key_file'),
            version=config['chef_server'].get('version'),
            organization=config['chef_server'].get('organization'),
            logger=logger,
            onlynodes=onlynodes,
        )
        chefnodes = chef.get_nodes()
        logger.debug("Got %s nodes from chef" % len(chefnodes))
    else:
        with open(args.nodefile, 'r') as nf:
            allchefnodes = json.loads(nf.read())
        if isinstance(allchefnodes, dict):
            allchefnodes = [allchefnodes]
        chefnodes = allchefnodes
        if onlynodes:
            chefnodes = []
            for node in allchefnodes:
                if not (node.get('hostname') in onlynodes or
                        node.get('fqdn') in onlynodes or
                        node.get('ipaddress') in onlynodes):
                    continue
                chefnodes.append(node)

    if args.savenodes:
        with open(args.savenodes, 'w') as wnf:
            wnf.write(json.dumps(chefnodes, cls=JSONEncoder, indent=4, sort_keys=True, ensure_ascii=False))

    dev42 = device42.Device42(
        endpoint=config['device42']['host'],
        user=config['device42']['user'],
        password=config['device42']['pass'],
        logger=logger,
        debug=debugmode,
    )
    d42_update(dev42, chefnodes, config['options'], config.get('static', {}), config['chef_server']['host'])

    return 0


if __name__ == "__main__":
    retval = main()
    sys.exit(retval)
