# -*- coding: utf-8 -*-

import chef  # pychef


class ChefWrapper(object):
    """ This class might be used to call Chef server API
        It can operate with different versions of Chef (11-12)
        and wraps calls of outdated 'pychef' library
    """

    def __init__(self, host, user, key=None, key_file=None, version=None, organization=None,
                 onlynodes=None, logger=None):
        self.host = host
        self.user = user
        self.key = key
        if not self.key:
            if not key_file:
                raise Exception("Either key or key_file should be passed!")
            with open(key_file, 'r') as kff:
                self.key = kff.read()
        self.version = str(version or "")
        self.organization = organization
        if self.version >= '12' and not organization:
            raise Exception("Parameter organization is required for Chef server version >= 12")
        self.logger = logger
        self.onlynodes = onlynodes or []

    def get_nodes(self):
        if self.version >= "12":
            chef_url = "https://%s/organizations/%s" % (self.host, self.organization)
        else:
            chef_url = "https://%s" % self.host
        # print(chef_url)
        all_nodes = []
        with chef.ChefAPI(chef_url, self.key, self.user, ssl_verify=False):
            nodes = chef.Node.list()
        for nname, node in nodes.items():
            node_data = node.attributes.to_dict()
            if node_data:  # if not empty
                if self.onlynodes:
                    if not (node_data.get('hostname') in self.onlynodes or
                            node_data.get('fqdn') in self.onlynodes or
                            node_data.get('ipaddress') in self.onlynodes):
                        continue
                all_nodes.append(node_data)
        return all_nodes
