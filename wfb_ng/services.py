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
import os
import re
import hashlib

from twisted.python import log, failure
from twisted.internet import reactor, defer, main as ti_main, threads
from twisted.internet.serialport import SerialPort

from .protocols import RXProtocol, TXProtocol
from .proxy import UDPProxyProtocol, MavlinkSerialProxyProtocol, MavlinkUDPProxyProtocol
from .mavlink_protocol import MavlinkARMProtocol, MavlinkTCPFactory, MavlinkLoggerProtocol
from .tuntap import TUNTAPProtocol, TUNTAPTransport
from .config_parser import Section
from .conf import settings

connect_re = re.compile(r'^connect://(?P<addr>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?P<port>[0-9]+)$', re.IGNORECASE)
listen_re = re.compile(r'^listen://(?P<addr>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?P<port>[0-9]+)$', re.IGNORECASE)
serial_re = re.compile(r'^serial:(?P<dev>[a-z0-9\-\_/]+):(?P<baud>[0-9]+)$', re.IGNORECASE)


bandwidth_map = {
    5: '5MHz',
    10: '10MHz',
    20: 'HT20',
    40: 'HT40+',
    80: '80MHz',
    160: '160MHz',
}

def hash_link_domain(link_domain):
    return int.from_bytes(hashlib.sha1(link_domain.encode('utf-8')).digest()[:3], 'big')


def parse_services(profile_name, udp_port_allocator):
    res = []
    for stream in getattr(settings, profile_name).streams:
        cfg = Section()
        stream = dict(stream)
        name = stream.pop('name')
        service_type = stream.pop('service_type')

        for profile in stream.pop('profiles'):
            cfg.__dict__.update(getattr(settings, profile).__dict__)

        cfg.__dict__.update(stream)

        # Allocate udp port for cluster aggregator and services
        if udp_port_allocator is not None:
            cfg.udp_port_auto = next(udp_port_allocator)

        res.append((name, service_type, cfg))

    return res


@defer.inlineCallbacks
def init_udp_direct_tx(service_name, cfg, wlans, link_id, ant_sel_f, is_cluster, rx_only_wlan_ids):
    # Direct udp doesn't support TX diversity - only first card will be used.
    # But if mirror mode is enabled it will use all cards.

    if not cfg.mirror and (len(wlans) > 1 or ',' in wlans[0] or rx_only_wlan_ids):
        raise Exception("udp_direct_tx doesn't supports diversity and/or rx-only wlans. Use udp_proxy for such case.")

    if not listen_re.match(cfg.peer):
        raise Exception('%s: unsupported peer address: %s' % (service_name, cfg.peer))

    m = listen_re.match(cfg.peer)
    listen = m.group('addr'), int(m.group('port'))
    log.msg('Listen for %s stream %d on %s:%d' % (service_name, cfg.stream_tx, listen[0], listen[1]))

    cmd = ('%(cmd)s%(cluster)s -f %(frame_type)s -p %(stream)d -u %(port)d -K %(key)s '\
           '-B %(bw)d -G %(gi)s -S %(stbc)d -L %(ldpc)d -M %(mcs)d'\
           '%(mirror)s%(force_vht)s%(qdisc)s '\
           '-k %(fec_k)d -n %(fec_n)d -T %(fec_timeout)d -F %(fec_delay)d -i %(link_id)d -R %(rcv_buf_size)d -l %(log_interval)d -C %(control_port)d' % \
           dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_tx'),
                cluster=' -d' if is_cluster else '',
                frame_type=cfg.frame_type,
                stream=cfg.stream_tx,
                port=listen[1],
                control_port = cfg.control_port,
                key=os.path.join(settings.path.conf_dir, cfg.keypair),
                bw=cfg.bandwidth,
                force_vht=' -V' if cfg.force_vht else '',
                qdisc=' -Q -P %d' % (cfg.fwmark,) if cfg.use_qdisc else '',
                gi="short" if cfg.short_gi else "long",
                stbc=cfg.stbc,
                ldpc=cfg.ldpc,
                mcs=cfg.mcs_index,
                mirror=' -m' if cfg.mirror else '',
                fec_k=cfg.fec_k,
                fec_n=cfg.fec_n,
                fec_timeout=cfg.fec_timeout,
                fec_delay=cfg.fec_delay,
                link_id=link_id,
                log_interval=settings.common.log_interval,
                rcv_buf_size=settings.common.tx_rcv_buf_size)
           ).split() + wlans

    control_port_df = defer.Deferred() if cfg.control_port == 0 else None
    df = TXProtocol(ant_sel_f, cmd, '%s tx' % (service_name,), control_port_df=control_port_df).start()
    log.msg('%s: %s' % (service_name, ' '.join(cmd),))

    control_port = cfg.control_port

    if control_port == 0:
        control_port = yield control_port_df

    log.msg('%s use wfb_tx control_port %d' % (service_name, control_port))

    yield df


def init_udp_direct_rx(service_name, cfg, wlans, link_id, ant_sel_f, is_cluster, rx_only_wlan_ids):
    if not connect_re.match(cfg.peer):
        raise Exception('%s: unsupported peer address: %s' % (service_name, cfg.peer))

    m = connect_re.match(cfg.peer)
    connect = m.group('addr'), int(m.group('port'))
    log.msg('Send %s stream %d to %s:%d' % (service_name, cfg.stream_rx, connect[0], connect[1]))

    cmd = ('%(cmd)s%(cluster)s -p %(stream)d -c %(ip_addr)s -u %(port)d -K %(key)s -R %(rcv_buf_size)d -l %(log_interval)d -i %(link_id)d' % \
           dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_rx'),
                cluster=' -a %d' % (cfg.udp_port_auto,) if is_cluster else '',
                stream=cfg.stream_rx,
                ip_addr=connect[0],
                port=connect[1],
                key=os.path.join(settings.path.conf_dir, cfg.keypair),
                rcv_buf_size=settings.common.tx_rcv_buf_size,
                log_interval=settings.common.log_interval,
                link_id=link_id)).split() + (wlans if not is_cluster else [])

    df = RXProtocol(ant_sel_f, cmd, '%s rx' % (service_name,)).start()

    log.msg('%s: %s' % (service_name, ' '.join(cmd),))
    return df


@defer.inlineCallbacks
def init_mavlink(service_name, cfg, wlans, link_id, ant_sel_f, is_cluster, rx_only_wlan_ids):
    listen = None
    connect = None
    serial = None
    osd_peer = None

    if connect_re.match(cfg.peer):
        m = connect_re.match(cfg.peer)
        connect = m.group('addr'), int(m.group('port'))
        log.msg('Connect %s stream %d(RX), %d(TX) to %s:%d' % (service_name, cfg.stream_rx, cfg.stream_tx, connect[0], connect[1]))

    elif listen_re.match(cfg.peer):
        m = listen_re.match(cfg.peer)
        listen = m.group('addr'), int(m.group('port'))
        log.msg('Listen for %s stream %d(RX), %d(TX) on %s:%d' % (service_name, cfg.stream_rx, cfg.stream_tx, listen[0], listen[1]))

    elif serial_re.match(cfg.peer):
        m = serial_re.match(cfg.peer)
        serial = m.group('dev'), int(m.group('baud'))
        log.msg('Open serial port %s on speed %d' % (serial[0], serial[1]))

    else:
        raise Exception('Unsupported peer address: %s' % (cfg.peer,))

    if cfg.osd is not None and connect_re.match(cfg.osd):
        m = connect_re.match(cfg.osd)
        osd_peer = m.group('addr'), int(m.group('port'))
        log.msg('Mirror %s stream to OSD at %s:%d' % (service_name, osd_peer[0], osd_peer[1]))

    rx_hooks = []
    tx_hooks = []

    if cfg.call_on_arm or cfg.call_on_disarm:
        arm_proto = MavlinkARMProtocol(cfg.call_on_arm, cfg.call_on_disarm)
        rx_hooks.append(arm_proto.dataReceived)
        tx_hooks.append(arm_proto.dataReceived)

    if cfg.log_messages and ant_sel_f.logger is not None:
        mav_log_proto = MavlinkLoggerProtocol(ant_sel_f.logger)
        rx_hooks.append(mav_log_proto.dataReceived)
        tx_hooks.append(mav_log_proto.dataReceived)

    if serial:
        p_in = MavlinkSerialProxyProtocol(agg_max_size=settings.common.radio_mtu,
                                          agg_timeout=settings.common.mavlink_agg_timeout,
                                          inject_rssi=cfg.inject_rssi,
                                          mavlink_sys_id=cfg.mavlink_sys_id,
                                          mavlink_comp_id=cfg.mavlink_comp_id,
                                          rx_hooks=rx_hooks, tx_hooks=tx_hooks)
    else:
        # The first argument is not None only if we initiate mavlink connection
        p_in = MavlinkUDPProxyProtocol(connect, agg_max_size=settings.common.radio_mtu,
                                       agg_timeout=settings.common.mavlink_agg_timeout,
                                       inject_rssi=cfg.inject_rssi,
                                       mirror=osd_peer,
                                       mavlink_sys_id=cfg.mavlink_sys_id,
                                       mavlink_comp_id=cfg.mavlink_comp_id,
                                       rx_hooks=rx_hooks, tx_hooks=tx_hooks)

    p_rx = UDPProxyProtocol()
    p_rx.peer = p_in

    rx_socket = reactor.listenUDP(0, p_rx)
    sockets = [rx_socket]

    cmd_rx = ('%(cmd)s%(cluster)s -p %(stream)d -u %(port)d -K %(key)s -R %(rcv_buf_size)d -l %(log_interval)d -i %(link_id)d' % \
              dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_rx'),
                   cluster=' -a %d' % (cfg.udp_port_auto,) if is_cluster else '',
                   stream=cfg.stream_rx,
                   port=rx_socket.getHost().port,
                   key=os.path.join(settings.path.conf_dir, cfg.keypair),
                   rcv_buf_size=settings.common.tx_rcv_buf_size,
                   log_interval=settings.common.log_interval,
                   link_id=link_id)).split() + (wlans if not is_cluster else [])

    cmd_tx = ('%(cmd)s%(cluster)s -f %(frame_type)s -p %(stream)d -u %(port)d -K %(key)s -B %(bw)d '\
              '-G %(gi)s -S %(stbc)d -L %(ldpc)d -M %(mcs)d'\
              '%(mirror)s%(force_vht)s%(qdisc)s '\
              '-k %(fec_k)d -n %(fec_n)d -T %(fec_timeout)d -F %(fec_delay)d -i %(link_id)d -R %(rcv_buf_size)d -l %(log_interval)d -C %(control_port)d' % \
              dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_tx'),
                   cluster=' -d' if is_cluster else '',
                   frame_type=cfg.frame_type,
                   stream=cfg.stream_tx,
                   port=0,
                   control_port=cfg.control_port,
                   key=os.path.join(settings.path.conf_dir, cfg.keypair),
                   bw=cfg.bandwidth,
                   force_vht=' -V' if cfg.force_vht else '',
                   qdisc=' -Q -P %d' % (cfg.fwmark,) if cfg.use_qdisc else '',
                   gi="short" if cfg.short_gi else "long",
                   stbc=cfg.stbc,
                   ldpc=cfg.ldpc,
                   mcs=cfg.mcs_index,
                   mirror=' -m' if cfg.mirror else '',
                   fec_k=cfg.fec_k,
                   fec_n=cfg.fec_n,
                   fec_timeout=cfg.fec_timeout,
                   fec_delay=cfg.fec_delay,
                   link_id=link_id,
                   log_interval=settings.common.log_interval,
                   rcv_buf_size=settings.common.tx_rcv_buf_size)).split() + wlans

    log.msg('%s RX: %s' % (service_name, ' '.join(cmd_rx)))
    log.msg('%s TX: %s' % (service_name, ' '.join(cmd_tx)))

    # Setup mavlink TCP proxy
    if cfg.mavlink_tcp_port:
        mav_tcp_f = MavlinkTCPFactory(p_in)
        p_in.rx_hooks.append(mav_tcp_f.write)
        reactor.listenTCP(cfg.mavlink_tcp_port, mav_tcp_f)

    tx_ports_df = defer.Deferred()
    control_port_df = defer.Deferred() if cfg.control_port == 0 else None

    dl = [TXProtocol(ant_sel_f, cmd_tx, '%s tx' % (service_name,), tx_ports_df, control_port_df).start()]

    # Wait while wfb_tx allocates ephemeral udp ports and reports them back
    tx_ports = yield tx_ports_df
    control_port = cfg.control_port

    if control_port == 0:
        control_port = yield control_port_df

    log.msg('%s use wfb_tx ports %s, control_port %d' % (service_name, tx_ports, control_port))

    p_tx_map = dict((wlan_id, UDPProxyProtocol(('127.0.0.1', port))) for wlan_id, port in tx_ports.items() if wlan_id not in rx_only_wlan_ids)

    if serial:
        serial_port = SerialPort(p_in, os.path.join('/dev', serial[0]), reactor, baudrate=serial[1])
        serial_port._serial.exclusive = True

    else:
        serial_port = None
        sockets += [ reactor.listenUDP(listen[1] if listen else 0, p_in) ]

    sockets += [ reactor.listenUDP(0, p_tx) for p_tx in p_tx_map.values() ]

    def ant_sel_cb(wlan_id):
        p_in.peer = p_tx_map[wlan_id] \
            if wlan_id is not None \
               else list(p_tx_map.values())[0]

    if p_tx_map:
        ant_sel_f.add_ant_sel_cb(ant_sel_cb)

    # Report RSSI to OSD
    ant_sel_f.add_rssi_cb(p_in.send_rssi)

    dl.append(RXProtocol(ant_sel_f, cmd_rx, '%s rx' % (service_name,)).start())

    def _cleanup(x):
        if serial_port is not None:
            serial_port.loseConnection()
            serial_port.connectionLost(failure.Failure(ti_main.CONNECTION_DONE))

        for s in sockets:
            s.stopListening()

        return x

    yield defer.gatherResults(dl, consumeErrors=True).addBoth(_cleanup)\
                                                     .addErrback(lambda f: f.trap(defer.FirstError) and f.value.subFailure)


@defer.inlineCallbacks
def init_tunnel(service_name, cfg, wlans, link_id, ant_sel_f, is_cluster, rx_only_wlan_ids):
    p_in = TUNTAPProtocol(mtu=settings.common.radio_mtu,
                          agg_timeout=settings.common.tunnel_agg_timeout)

    p_rx = UDPProxyProtocol()
    p_rx.peer = p_in

    rx_socket = reactor.listenUDP(0, p_rx)
    sockets = [rx_socket]

    cmd_rx = ('%(cmd)s%(cluster)s -p %(stream)d -u %(port)d -K %(key)s -R %(rcv_buf_size)d -l %(log_interval)d -i %(link_id)d' % \
              dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_rx'),
                   cluster=' -a %d' % (cfg.udp_port_auto,) if is_cluster else '',
                   stream=cfg.stream_rx,
                   port=rx_socket.getHost().port,
                   key=os.path.join(settings.path.conf_dir, cfg.keypair),
                   rcv_buf_size=settings.common.tx_rcv_buf_size,
                   log_interval=settings.common.log_interval,
                   link_id=link_id)).split() + (wlans if not is_cluster else [])

    cmd_tx = ('%(cmd)s%(cluster)s -f %(frame_type)s -p %(stream)d -u %(port)d -K %(key)s -B %(bw)d -G %(gi)s '\
              '-S %(stbc)d -L %(ldpc)d -M %(mcs)d'\
              '%(mirror)s%(force_vht)s%(qdisc)s '\
              '-k %(fec_k)d -n %(fec_n)d -T %(fec_timeout)d -F %(fec_delay)d -i %(link_id)d -R %(rcv_buf_size)d -l %(log_interval)d -C %(control_port)d' % \
              dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_tx'),
                   cluster=' -d' if is_cluster else '',
                   frame_type=cfg.frame_type,
                   stream=cfg.stream_tx,
                   port=0,
                   control_port=cfg.control_port,
                   key=os.path.join(settings.path.conf_dir, cfg.keypair),
                   bw=cfg.bandwidth,
                   force_vht=' -V' if cfg.force_vht else '',
                   qdisc=' -Q -P %d' % (cfg.fwmark,) if cfg.use_qdisc else '',
                   gi="short" if cfg.short_gi else "long",
                   stbc=cfg.stbc,
                   ldpc=cfg.ldpc,
                   mcs=cfg.mcs_index,
                   mirror=' -m' if cfg.mirror else '',
                   fec_k=cfg.fec_k,
                   fec_n=cfg.fec_n,
                   fec_timeout=cfg.fec_timeout,
                   fec_delay=cfg.fec_delay,
                   link_id=link_id,
                   log_interval=settings.common.log_interval,
                   rcv_buf_size=settings.common.tx_rcv_buf_size)).split() + wlans

    log.msg('%s RX: %s' % (service_name, ' '.join(cmd_rx)))
    log.msg('%s TX: %s' % (service_name, ' '.join(cmd_tx),))

    tx_ports_df = defer.Deferred()
    control_port_df = defer.Deferred() if cfg.control_port == 0 else None

    dl = [TXProtocol(ant_sel_f, cmd_tx, '%s tx' % (service_name,), tx_ports_df, control_port_df).start()]

    # Wait while wfb_tx allocates ephemeral udp ports and reports them back
    tx_ports = yield tx_ports_df
    control_port = cfg.control_port

    if control_port == 0:
        control_port = yield control_port_df

    log.msg('%s use wfb_tx ports %s, control_port %d' % (service_name, tx_ports, control_port))
    p_tx_map = dict((wlan_id, UDPProxyProtocol(('127.0.0.1', port))) for wlan_id, port in tx_ports.items() if wlan_id not in rx_only_wlan_ids)

    tun_ep = TUNTAPTransport(reactor, p_in, cfg.ifname, cfg.ifaddr, mtu=settings.common.radio_mtu, default_route=cfg.default_route)
    sockets += [ reactor.listenUDP(0, p_tx) for p_tx in p_tx_map.values() ]

    def ant_sel_cb(wlan_id):
        p_in.peer = p_tx_map[wlan_id] \
            if wlan_id is not None \
               else list(p_tx_map.values())[0]

    # Broadcast keepalive message to all cards, not to active one
    # This allow to use direct antennas on both ends and/or differenct frequencies.
    # But when mirroring enabled it will be done by wfb_tx itself

    if cfg.mirror:
        p_in.all_peers = list(p_tx_map.values())[0:1]
    else:
        p_in.all_peers = list(p_tx_map.values())

    if p_tx_map:
        ant_sel_f.add_ant_sel_cb(ant_sel_cb)

    dl.append(RXProtocol(ant_sel_f, cmd_rx, '%s rx' % (service_name,)).start())

    def _cleanup(x):
        tun_ep.loseConnection()
        for s in sockets:
            s.stopListening()
        return x

    yield defer.gatherResults(dl, consumeErrors=True).addBoth(_cleanup)\
                                                     .addErrback(lambda f: f.trap(defer.FirstError) and f.value.subFailure)


@defer.inlineCallbacks
def init_udp_proxy(service_name, cfg, wlans, link_id, ant_sel_f, is_cluster, rx_only_wlan_ids):
    listen = None
    connect = None

    if connect_re.match(cfg.peer):
        m = connect_re.match(cfg.peer)
        connect = m.group('addr'), int(m.group('port'))
        log.msg('Connect %s stream %s(RX), %s(TX) to %s:%d' % (service_name, cfg.stream_rx, cfg.stream_tx, connect[0], connect[1]))

    elif listen_re.match(cfg.peer):
        m = listen_re.match(cfg.peer)
        listen = m.group('addr'), int(m.group('port'))
        log.msg('Listen for %s stream %s(RX), %s(TX) on %s:%d' % (service_name, cfg.stream_rx, cfg.stream_tx, listen[0], listen[1]))

    else:
        raise Exception('Unsupported peer address: %s' % (cfg.peer,))

    # The first argument is not None only if we initiate mavlink connection
    p_in = UDPProxyProtocol(connect)
    sockets = [reactor.listenUDP(listen[1] if listen else 0, p_in)]
    dl = []

    if cfg.stream_rx is not None:
        p_rx = UDPProxyProtocol()
        p_rx.peer = p_in
        rx_socket = reactor.listenUDP(0, p_rx)
        sockets = [rx_socket]
        cmd_rx = ('%(cmd)s%(cluster)s -p %(stream)d -u %(port)d -K %(key)s -R %(rcv_buf_size)d -l %(log_interval)d -i %(link_id)d' % \
                  dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_rx'),
                       cluster=' -a %d' % (cfg.udp_port_auto,) if is_cluster else '',
                       stream=cfg.stream_rx,
                       port=rx_socket.getHost().port,
                       key=os.path.join(settings.path.conf_dir, cfg.keypair),
                       rcv_buf_size=settings.common.tx_rcv_buf_size,
                       log_interval=settings.common.log_interval,
                       link_id=link_id)).split() + (wlans if not is_cluster else [])

        log.msg('%s RX: %s' % (service_name, ' '.join(cmd_rx)))
        dl.append(RXProtocol(ant_sel_f, cmd_rx, '%s rx' % (service_name,)).start())

    if cfg.stream_tx is not None:
        cmd_tx = ('%(cmd)s%(cluster)s -f %(frame_type)s -p %(stream)d -u %(port)d -K %(key)s -B %(bw)d '\
                  '-G %(gi)s -S %(stbc)d -L %(ldpc)d -M %(mcs)d'\
                  '%(mirror)s%(force_vht)s%(qdisc)s '\
                  '-k %(fec_k)d -n %(fec_n)d -T %(fec_timeout)d -F %(fec_delay)d -i %(link_id)d -R %(rcv_buf_size)d -l %(log_interval)d -C %(control_port)d' % \
                  dict(cmd=os.path.join(settings.path.bin_dir, 'wfb_tx'),
                       cluster=' -d' if is_cluster else '',
                       frame_type=cfg.frame_type,
                       stream=cfg.stream_tx,
                       port=0,
                       control_port=cfg.control_port,
                       key=os.path.join(settings.path.conf_dir, cfg.keypair),
                       bw=cfg.bandwidth,
                       force_vht=' -V' if cfg.force_vht else '',
                       qdisc=' -Q -P %d' % (cfg.fwmark,) if cfg.use_qdisc else '',
                       gi="short" if cfg.short_gi else "long",
                       stbc=cfg.stbc,
                       ldpc=cfg.ldpc,
                       mcs=cfg.mcs_index,
                       mirror=' -m' if cfg.mirror else '',
                       fec_k=cfg.fec_k,
                       fec_n=cfg.fec_n,
                       fec_timeout=cfg.fec_timeout,
                       fec_delay=cfg.fec_delay,
                       link_id=link_id,
                       log_interval=settings.common.log_interval,
                       rcv_buf_size=settings.common.tx_rcv_buf_size)).split() + wlans
        log.msg('%s TX: %s' % (service_name, ' '.join(cmd_tx)))

        tx_ports_df = defer.Deferred()
        control_port_df = defer.Deferred() if cfg.control_port == 0 else None

        dl += [TXProtocol(ant_sel_f, cmd_tx, '%s tx' % (service_name,), tx_ports_df, control_port_df).start()]

        # Wait while wfb_tx allocates ephemeral udp ports and reports them back
        tx_ports = yield tx_ports_df
        control_port = cfg.control_port

        if control_port == 0:
            control_port = yield control_port_df

        log.msg('%s use wfb_tx ports %s, control_port %d' % (service_name, tx_ports, control_port))

        p_tx_map = dict((wlan_id, UDPProxyProtocol(('127.0.0.1', port))) for wlan_id, port in tx_ports.items() if wlan_id not in rx_only_wlan_ids)
        sockets += [ reactor.listenUDP(0, p_tx) for p_tx in p_tx_map.values() ]

        def ant_sel_cb(wlan_id):
            p_in.peer = p_tx_map[wlan_id] \
                if wlan_id is not None \
                   else list(p_tx_map.values())[0]

        if p_tx_map:
            ant_sel_f.add_ant_sel_cb(ant_sel_cb)

    def _cleanup(x):
        for s in sockets:
            s.stopListening()

        return x

    yield defer.gatherResults(dl, consumeErrors=True).addBoth(_cleanup)\
                                                     .addErrback(lambda f: f.trap(defer.FirstError) and f.value.subFailure)
