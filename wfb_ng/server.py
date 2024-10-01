#!/usr/bin/env python
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

import sys
import msgpack
import os
import time
import socket
import struct
import gzip
import argparse

from twisted.python import log, failure
from twisted.internet import reactor, defer

from . import _log_msg, ConsoleObserver, ErrorSafeLogFile, call_and_check_rc, ExecError, version_msg
from .common import abort_on_crash, exit_status, df_sleep, search_attr
from .protocols import StatsAndSelectorFactory, RFTempMeter, SSHClientProtocol
from .services import parse_services, init_udp_direct_tx, init_udp_direct_rx, init_mavlink, init_tunnel, init_udp_proxy, hash_link_domain, bandwidth_map
from .cluster import parse_cluster_services, gen_cluster_scripts
from .conf import settings, cfg_files


# Log format is gzipped sequence of int32 strings
# For every run new file will be open to avoid framing errors

def BinLogFile(self, fname, directory):
    filename = '%s.%s' % (fname, time.strftime('%Y%m%d-%H%M%S', time.localtime()))
    filename = os.path.join(directory, filename)
    reactor.callFromThread(log.msg, 'Open binary log %s' % (filename,))
    return gzip.GzipFile(filename, 'wb')


class BinLogger(ErrorSafeLogFile):
    binary = True
    twisted_logger = False
    flush_delay = 10
    log_cls = BinLogFile

    def send_stats(self, data):
        data = msgpack.packb(data, use_bin_type=True)
        self.write(b''.join((struct.pack('!I', len(data)), data)))


@defer.inlineCallbacks
def init_wlans(max_bw, wlans):
    ht_mode = bandwidth_map[max_bw]

    if not settings.common.primary:
        log.msg('Skip card init due to secondary role')
        return

    try:
        yield call_and_check_rc('iw', 'reg', 'set', settings.common.wifi_region)
        for wlan in wlans:
            if settings.common.set_nm_unmanaged and os.path.exists('/usr/bin/nmcli'):
                device_status = yield call_and_check_rc('nmcli', 'device', 'show', wlan, log_stdout=False)
                if not b'(unmanaged)' in device_status:
                    log.msg('Switch %s to unmanaged state' % (wlan,))
                    yield call_and_check_rc('nmcli', 'device', 'set', wlan, 'managed', 'no')
                    yield df_sleep(1)

            yield call_and_check_rc('ip', 'link', 'set', wlan, 'down')
            yield call_and_check_rc('iw', 'dev', wlan, 'set', 'monitor', 'otherbss')
            yield call_and_check_rc('ip', 'link', 'set', wlan, 'up')

            # You can set own frequency channel for each card
            if isinstance(settings.common.wifi_channel, dict):
                channel = settings.common.wifi_channel[wlan]
            else:
                channel = settings.common.wifi_channel

            yield call_and_check_rc('iw', 'dev', wlan, 'set', 'channel', str(channel), ht_mode)

            txpower = settings.common.wifi_txpower

            # You can set own tx power for each card
            if isinstance(txpower, dict):
                txpower = txpower[wlan]

            if txpower not in (None, 'off'):
                yield call_and_check_rc('iw', 'dev', wlan, 'set', 'txpower', 'fixed', str(txpower))

    except ExecError as v:
        if v.stdout:
            log.msg(v.stdout, isError=1)
        if v.stderr:
            log.msg(v.stderr, isError=1)
        raise


@defer.inlineCallbacks
def init(profiles, wlans, cluster_mode):
    type_map = dict(udp_direct_rx=init_udp_direct_rx,
                    udp_direct_tx=init_udp_direct_tx,
                    mavlink=init_mavlink,
                    tunnel=init_tunnel,
                    udp_proxy=init_udp_proxy)

    dl = []
    is_cluster = bool(cluster_mode)

    def _ssh_exited(x, node):
        raise Exception('Connection to %s closed, aborting' % (node,))

    rx_only_wlan_ids = set()

    if is_cluster:
        services, cluster_nodes = parse_cluster_services(profiles)
        for node in cluster_nodes:
            node_ipv4_addr = struct.unpack("!L", socket.inet_aton(node))[0]
            txpower = search_attr('wifi_txpower',
                                  settings.cluster.nodes[node],
                                  settings.common.__dict__)

            for idx, wlan in enumerate(settings.cluster.nodes[node]['wlans']):
                if (txpower[wlan] if isinstance(txpower, dict) else txpower) == 'off':
                    rx_only_wlan_ids.add((node_ipv4_addr << 24) | idx)


        if cluster_mode == 'ssh':
            for node, setup_script in gen_cluster_scripts(cluster_nodes, ssh_mode=True).items():
                ssh_user = search_attr('ssh_user',
                                       settings.cluster.nodes[node],
                                       settings.cluster.__dict__)

                ssh_port = search_attr('ssh_port',
                                       settings.cluster.nodes[node],
                                       settings.cluster.__dict__)

                ssh_key = search_attr('ssh_key',
                                      settings.cluster.nodes[node],
                                      settings.cluster.__dict__)

                if ssh_user and ssh_port:
                    dl.append(SSHClientProtocol(node,
                                                ssh_user,
                                                '/bin/bash',
                                                key=ssh_key,
                                                port=ssh_port,
                                                use_agent=ssh_key is None,
                                                stdin=setup_script).start()\
                              .addBoth(_ssh_exited, node))
    else:
        services = list((profile, parse_services(profile, None)) for profile in profiles)
        # Do cards init
        if not wlans:
            raise Exception('WiFi interface list is empty!')

        max_bw = max(cfg.bandwidth for _, tmp in services for _, _, cfg in tmp)
        yield init_wlans(max_bw, wlans)

        txpower = settings.common.wifi_txpower

        for idx, wlan in enumerate(wlans):
            if (txpower[wlan] if isinstance(txpower, dict) else txpower) == 'off':
                rx_only_wlan_ids.add(idx)


    sockets = []
    cleanup_l = []

    def _cleanup(x):
        for s in sockets:
            s.stopListening()

        for f in cleanup_l:
            f._cleanup()

        return x

    if not is_cluster:
        rf_temp_meter = RFTempMeter(wlans, settings.common.temp_measurement_interval)
        cleanup_l.append(rf_temp_meter)
    else:
        rf_temp_meter = None

    if rx_only_wlan_ids:
        log.msg('RX-only wlan ids: %s' % (', '.join(map(hex, rx_only_wlan_ids))))

    for profile, service_list in services:
        # Domain wide antenna selector
        profile_cfg = getattr(settings, profile)

        if settings.common.binary_log_file is not None:
            logger = BinLogger(settings.common.binary_log_file % (profile,),
                               settings.path.log_dir)

            logger.send_stats(dict(type='init',
                                   timestamp = time.time(),
                                   version=settings.common.version,
                                   profile=profile,
                                   wlans=None if is_cluster else wlans,
                                   link_domain=profile_cfg.link_domain))
        else:
            logger = None

        cli_title = 'WFB-ng_%s @%s %s [%s]' % (settings.common.version, profile,
                                               'cluster' if is_cluster else ', '.join(wlans),
                                               profile_cfg.link_domain)

        ant_sel_f = StatsAndSelectorFactory(logger, cli_title, rf_temp_meter, is_cluster, rx_only_wlan_ids)
        cleanup_l.append(ant_sel_f)

        link_id = hash_link_domain(profile_cfg.link_domain)

        if profile_cfg.stats_port:
            sockets.append(reactor.listenTCP(profile_cfg.stats_port, ant_sel_f))

        for service_name, service_type, srv_cfg in service_list:
            log.msg('Starting %s/%s@%s' % (profile, service_name, profile_cfg.link_domain))
            dl.append(defer.maybeDeferred(type_map[service_type], service_name, srv_cfg,
                                          srv_cfg.udp_peers_auto if is_cluster else wlans,
                                          link_id, ant_sel_f, is_cluster, rx_only_wlan_ids))

    yield defer.gatherResults(dl, consumeErrors=True).addBoth(_cleanup).addErrback(lambda f: f.trap(defer.FirstError) and f.value.subFailure)



def main():
    description = 'WFB-ng version %s-%s' % (settings.common.version, settings.common.commit[:8])

    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--version', action='version', version=version_msg % settings)
    parser.add_argument('--profiles', type=str, required=True, nargs='+', metavar='profile', help='Use service profile(s)')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cluster', type=str, choices=('ssh', 'manual'), help='Distributed mode')
    group.add_argument('--gen-init', type=str, metavar='node', help='Generate init script for cluster node')
    group.add_argument('--wlans', type=str, nargs='+', metavar='wlan', help='WiFi interfaces for local mode')

    args = parser.parse_args()
    profiles = sorted(args.profiles)

    if args.gen_init:
        _, cluster_nodes = parse_cluster_services(profiles)
        print(gen_cluster_scripts(cluster_nodes)[args.gen_init])
        return

    log.msg = _log_msg

    if settings.common.log_file:
        log.startLogging(ErrorSafeLogFile(settings.common.log_file,
                                          settings.path.log_dir,
                                          rotateLength=1024 * 1024,
                                          maxRotatedFiles=10))

    elif sys.stdout.isatty():
        log.startLogging(sys.stdout)

    else:
        obs = ConsoleObserver()
        log.theLogPublisher._startLogging(obs.emit, False)

    log.msg(description)

    uname = os.uname()

    if args.cluster:
        cluster_mode = args.cluster
        wlans = None
        log.msg('Run on %s/%s @%s, profile(s): %s, cluster mode' % (uname[4], uname[2], uname[1], profiles))
    else:
        cluster_mode = None
        wlans = args.wlans
        log.msg('Run on %s/%s @%s, profile(s): %s, using: %s' % (uname[4], uname[2], uname[1], profiles, wlans))

    log.msg('Using config files:\n%s' % ('\n'.join(cfg_files),))

    reactor.callWhenRunning(lambda: defer.maybeDeferred(init, profiles, wlans, cluster_mode)\
                            .addErrback(abort_on_crash))
    reactor.run()

    rc = exit_status()
    log.msg('Exiting with code %d' % rc)
    sys.exit(rc)


if __name__ == '__main__':
    main()
