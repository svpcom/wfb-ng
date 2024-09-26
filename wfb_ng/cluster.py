# -*- coding: utf-8 -*-

# Copyright (C) 2018-2024 Vasily Evseenko <svpcom@p2ptech.org>

#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; version 3.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import itertools
from jinja2 import Environment, StrictUndefined

from .common import search_attr
from .services import parse_services, hash_link_domain, bandwidth_map
from .conf import settings

def parse_cluster_services(profiles):
    if not settings.cluster.nodes:
        raise Exception('Cluster is empty!')

    udp_port_allocator = itertools.count(settings.cluster.base_port_server)
    services = list((profile, parse_services(profile, udp_port_allocator)) for profile in profiles)
    port_allocators = {}
    cluster_nodes = {}

    def update_node(node, profile, service_name, link_id, tx_port_base, wlans, srv_cfg):
        server_address = search_attr('server_address',
                                     settings.cluster.nodes[node],
                                     settings.cluster.__dict__)

        if not server_address:
            raise Exception('Server IP address is not set!')

        d = dict(wlans = wlans,
                 link_id = link_id,
                 bandwidth = srv_cfg.bandwidth,
                 stream_tx = srv_cfg.stream_tx,
                 stream_rx = srv_cfg.stream_rx,
                 tx_port_base = tx_port_base,
                 fwmark = srv_cfg.fwmark if srv_cfg.use_qdisc else None,
                 rx_fwd = (server_address, srv_cfg.udp_port_auto))

        if node not in cluster_nodes:
            cluster_nodes[node] = {}

        cluster_nodes[node]['%s_%s' % (profile, service_name)] = d


    def get_allocator(node):
        alloc = port_allocators.get(node)
        if alloc is not None:
            return alloc

        alloc = itertools.count(settings.cluster.base_port_node)
        port_allocators[node] = alloc

        return alloc

    for profile, service_list in services:
        link_id = hash_link_domain(getattr(settings, profile).link_domain)

        for service_name, service_type, srv_cfg in service_list:
            auto_peers = []
            # Sort cluster nodes for stable result
            for node, attrs in sorted(settings.cluster.nodes.items(), key=lambda x: x[0]):
                ports = list(next(get_allocator(node)) for wlan in attrs['wlans'])
                if not ports:
                    raise Exception('WiFi interface list is empty for node %s!' % (node,))

                auto_peers.append('%s:%s' % (node, ','.join(map(str, ports))))
                update_node(node, profile, service_name, link_id, min(ports), attrs['wlans'], srv_cfg)

            srv_cfg.udp_peers_auto = auto_peers

    return services, cluster_nodes



env = Environment(autoescape=False, undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
env.globals.update({'sorted': sorted, 'repr': repr, 'max': max,
                    'min': min, 'None': None, 'settings': settings})

script_template = '''\
#!/bin/bash
set -emb

export LC_ALL=C

_cleanup()
{
  plist=$(jobs -p)
  if [ -n "$plist" ]
  then
      kill -TERM $plist || true
  fi
  exit 1
}

trap _cleanup EXIT

{% if custom_init_script != None %}
{{ custom_init_script }}
{% endif %}

iw reg set {{ settings.common.wifi_region }}
{% for wlan in  wlans %}

# init {{ wlan }}
if which nmcli > /dev/null && ! nmcli device show {{ wlan }} | grep -q '(unmanaged)'
then
  nmcli device set {{ wlan }} managed no
  sleep 1
fi

ip link set {{ wlan }} down
iw dev {{ wlan }} set monitor otherbss
ip link set {{ wlan }} up
iw dev {{ wlan }} set channel {{ channel[wlan] }} {{ ht_mode }}
{% if txpower[wlan] not in (None, 'off') %}
iw dev {{ wlan }} set txpower fixed {{ txpower[wlan] }}
{% endif %}
{% endfor %}
{% for service, attrs in services.items() %}

# {{ service }}
{% if attrs['stream_rx'] != None %}
wfb_rx -f -c {{ attrs['rx_fwd'][0] }} -u {{ attrs['rx_fwd'][1] }} -p {{ attrs['stream_rx'] }} -i {{ attrs['link_id'] }} -R {{ settings.common.tx_rcv_buf_size }} {{ attrs['wlans']|join(' ') }} &
{% endif %}
{% if attrs['stream_tx'] != None %}
wfb_tx -I {{ attrs['tx_port_base'] }} -R {{ settings.common.tx_rcv_buf_size }} {{ '-Q -P %d' % (attrs['fwmark'],) if attrs['fwmark'] != None else '' }} {{ attrs['wlans']|join(' ') }} &
{% endif %}
{% endfor %}

{% if ssh_mode %}
# Will fail in case of connection loss
(sleep 1; exec cat > /dev/null) &
{% endif %}

echo "WFB-ng init done"
wait -n

'''

script_template = env.from_string(script_template)

def gen_cluster_scripts(cluster_nodes, ssh_mode=False):
    """
    cluster_nodes:  node_name -> service_map
    """

    res = {}

    for node, node_attrs in cluster_nodes.items():
        wlans = sorted(set().union(*[srv_attrs['wlans'] for srv_attrs in node_attrs.values()]))
        max_bw = max(srv_attrs['bandwidth'] for srv_attrs in node_attrs.values())

        channel = search_attr('wifi_channel',
                              settings.cluster.nodes[node],
                              settings.common.__dict__)

        if not isinstance(channel, dict):
            channel = dict((wlan, channel) for wlan in wlans)

        txpower = search_attr('wifi_txpower',
                              settings.cluster.nodes[node],
                              settings.common.__dict__)

        custom_init_script = search_attr('custom_init_script',
                                         settings.cluster.nodes[node],
                                         settings.cluster.__dict__)

        if not isinstance(txpower, dict):
            txpower = dict((wlan, txpower) for wlan in wlans)

        res[node] = script_template.render(wlans=wlans,
                                           ht_mode=bandwidth_map[max_bw],
                                           services=node_attrs,
                                           txpower=txpower,
                                           channel=channel,
                                           ssh_mode=ssh_mode,
                                           custom_init_script=custom_init_script)

    return res
