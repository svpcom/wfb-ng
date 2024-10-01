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

from itertools import groupby
from twisted.python import log, failure
from twisted.internet import reactor, defer, threads, task
from twisted.internet.protocol import ProcessProtocol, Factory
from twisted.protocols.basic import LineReceiver, Int32StringReceiver

from .conf import settings


class BadTelemetry(Exception):
    pass


class WFBFlags(object):
    LINK_LOST = 1
    LINK_JAMMED = 2


fec_types = {1: 'VDM_RS'}

class StatisticsProtocol(Int32StringReceiver):
    MAX_LENGTH = 1024 * 1024

    def connectionMade(self):
        # Push all config values for CLI into session
        # to allow CLI run without config file
        # (for example for access from remote host)

        self.sendString(msgpack.packb(dict(type='cli_title',
                                           cli_title=self.factory.cli_title or "",
                                           is_cluster=self.factory.is_cluster,
                                           log_interval=settings.common.log_interval,
                                           temp_overheat_warning=settings.common.temp_overheat_warning),
                                      use_bin_type=True))

        self.factory.ui_sessions.append(self)

    def stringReceived(self, string):
        pass

    def connectionLost(self, reason):
        self.factory.ui_sessions.remove(self)

    def send_stats(self, data):
        self.sendString(msgpack.packb(data, use_bin_type=True))


class RFTempMeter(object):
    def __init__(self, wlans, measurement_interval):
        # RF module temperature by rf_path
        self.wlans = tuple(wlans)
        self.rf_temperature = {}

        self.lc = task.LoopingCall(self.read_temperature)
        self.lc.start(measurement_interval, now=True)

    def _cleanup(self):
        self.lc.stop()

    def read_temperature(self):
        def _read_temperature():
            res = {}
            for idx, wlan in enumerate(self.wlans):
                fname = '/proc/net/rtl88x2eu/%s/thermal_state' % (wlan,)
                try:
                    with open(fname) as fd:
                        for line in fd:
                            line = line.strip()
                            if not line:
                                continue

                            d = {}
                            for f in line.split(','):
                                k, v = f.split(':', 1)
                                d[k.strip()] = int(v.strip())

                            ant_id = (idx << 8) + d['rf_path']
                            res[ant_id] = d['temperature']
                except FileNotFoundError:
                    pass
                except Exception as v:
                    reactor.callFromThread(log.err, v, 'Unable to parse %s:' % (fname,))
            return res

        def _got_temp(temp_d):
            self.rf_temperature = temp_d

        return threads.deferToThread(_read_temperature).addCallback(_got_temp)


class StatsAndSelectorFactory(Factory):
    noisy = False
    protocol = StatisticsProtocol

    """
    Aggregate RX stats and select TX antenna
    """

    def __init__(self, logger, cli_title=None, rf_temp_meter=None, is_cluster=False, rx_only_wlan_ids=None):
        self.is_cluster = is_cluster
        self.rx_only_wlan_ids = rx_only_wlan_ids or set()
        self.ant_sel_cb_list = []
        self.rssi_cb_l = []
        self.cur_stats = {}

        self.tx_sel = None
        self.tx_sel_rssi_delta = settings.common.tx_sel_rssi_delta
        self.tx_sel_counter_rel_delta = settings.common.tx_sel_counter_rel_delta
        self.tx_sel_counter_abs_delta = settings.common.tx_sel_counter_abs_delta

        # tcp sockets for UI
        self.ui_sessions = []

        # machine-readable logger
        self.logger = logger

        if logger is not None:
            self.ui_sessions.append(logger)

        self.cli_title = cli_title
        self.rf_temp_meter = rf_temp_meter

        self.lc = task.LoopingCall(self.aggregate_stats)
        self.lc.start(settings.common.log_interval / 1000.0, now=False)

    def _cleanup(self):
        self.lc.stop()

    def add_ant_sel_cb(self, ant_sel_cb):
        self.ant_sel_cb_list.append(ant_sel_cb)
        ant_sel_cb(self.tx_sel)

    def add_rssi_cb(self, rssi_cb):
        self.rssi_cb_l.append(rssi_cb)

    def _stats_agg_by_freq_and_rxid(self, ant_stats_by_rx):
        stats_agg = {}

        for ant_stats in ant_stats_by_rx.values():
            for (((freq, mcs_index, bandwidth), ant_id),
                 (pkt_s,
                  rssi_min, rssi_avg, rssi_max,
                  snr_min, snr_avg, snr_max)) in ant_stats.items():

                if ant_id not in stats_agg:
                    stats_agg[ant_id] = (pkt_s,
                                         rssi_min, rssi_avg * pkt_s, rssi_max,
                                         snr_min, snr_avg * pkt_s, snr_max)
                else:
                    tmp = stats_agg[ant_id]
                    stats_agg[ant_id] = (pkt_s + tmp[0],
                                        min(rssi_min, tmp[1]),
                                        rssi_avg * pkt_s + tmp[2],
                                        max(rssi_max, tmp[3]),
                                        min(snr_min, tmp[4]),
                                        snr_avg * pkt_s + tmp[5],
                                        max(snr_max, tmp[6]))

        return dict((ant_id, (pkt_s,
                              rssi_min, rssi_avg // pkt_s, rssi_max,
                              snr_min, snr_avg // pkt_s, snr_max)) \
                    for ant_id, (pkt_s,
                                 rssi_min, rssi_avg, rssi_max,
                                 snr_min, snr_avg, snr_max) in stats_agg.items())

    def select_tx_antenna(self, stats_agg):
        wlan_rssi_and_pkts = {}
        max_pkts = 0

        for wlan_id, grp in groupby(sorted(((ant_id >> 8), pkt_s, rssi_avg) \
                                           for ant_id, (pkt_s,
                                                        rssi_min, rssi_avg, rssi_max,
                                                        snr_min, snr_avg, snr_max) in stats_agg.items()),
                                    lambda x: x[0]):

            # Skip RX only cards in TX voting
            if wlan_id in self.rx_only_wlan_ids:
                continue

            grp = list(grp)
            # Use max average rssi [dBm] from all wlan's antennas
            # Use max packet counter per antenna from all wlan's antennas
            rssi = max(rssi for _, pkt_s, rssi in grp)
            pkts = max(pkt_s for _, pkt_s, rssi in grp)
            max_pkts = max(pkts, max_pkts)
            wlan_rssi_and_pkts[wlan_id] = (rssi, pkts)

        if not wlan_rssi_and_pkts:
            return

        # Select antennas with near-maximum RX packet counters only
        tx_sel_counter_thr = max_pkts - max(self.tx_sel_counter_abs_delta, max_pkts * self.tx_sel_counter_rel_delta)
        wlans_with_max_pkts = set(wlan_id for wlan_id, (rssi, pkt_s) in wlan_rssi_and_pkts.items() if pkt_s >= tx_sel_counter_thr)

        if not wlans_with_max_pkts:
            return

        new_max_rssi, new_tx_wlan = max((rssi, wlan_id) for wlan_id, (rssi, pkt_s) in wlan_rssi_and_pkts.items() if wlan_id in wlans_with_max_pkts)
        cur_max_rssi = wlan_rssi_and_pkts.get(self.tx_sel, (-1000, 0))[0]

        if new_tx_wlan == self.tx_sel:
            return

        if self.tx_sel in wlans_with_max_pkts and new_max_rssi - cur_max_rssi < self.tx_sel_rssi_delta:
            # Already selected antenna with near-maximum RX packets counter
            # and other antennas doesn't have significally large RSSI
            return

        log.msg('Switch TX wlan %x -> %x, RSSI %d -> %d[dB]' % (self.tx_sel if self.tx_sel is not None else -1,
                                                                new_tx_wlan, cur_max_rssi, new_max_rssi))

        for ant_sel_cb in self.ant_sel_cb_list:
            try:
                ant_sel_cb(new_tx_wlan)
            except Exception:
                log.err()

        self.tx_sel = new_tx_wlan

    def process_new_session(self, rx_id, session):
        if self.logger is not None:
            self.logger.send_stats(dict(type='new_session',
                                        timestamp = time.time(),
                                        id=rx_id,
                                        **session))

    def aggregate_stats(self):
        cur_stats, self.cur_stats = self.cur_stats, {}
        ant_stats_by_rx = dict((rx_id, ant_stats) for rx_id, (ant_stats, packet_stats) in cur_stats.items())
        packet_stats_by_rx = dict((rx_id, packet_stats) for rx_id, (ant_stats, packet_stats) in cur_stats.items())

        stats_agg = self._stats_agg_by_freq_and_rxid(ant_stats_by_rx)
        # (rssi,noise) tuples
        card_rssi_l = list((rssi_avg, rssi_avg - snr_avg)
                           for pkt_s,
                               rssi_min, rssi_avg, rssi_max,
                               snr_min, snr_avg, snr_max
                           in stats_agg.values())

        if stats_agg and self.ant_sel_cb_list:
            self.select_tx_antenna(stats_agg)

        if self.rssi_cb_l:
            _idx = 0 if settings.common.mavlink_err_rate else 1
            flags = 0

            bad_packets = sum(p['dec_err'][0] + p['bad'][0] for p in packet_stats_by_rx.values())

            if not card_rssi_l:
                flags |= WFBFlags.LINK_LOST
                mav_rssi, mav_noise = -128, -128

            else:
                if bad_packets > 0:
                    flags |= WFBFlags.LINK_JAMMED
                mav_rssi, mav_noise = max(card_rssi_l)

            rx_errors = sum(p['dec_err'][_idx] + p['bad'][_idx] + p['lost'][_idx] for p in packet_stats_by_rx.values())
            rx_fec = sum(p['fec_rec'][_idx] for p in packet_stats_by_rx.values())

            for rssi_cb in self.rssi_cb_l:
                try:
                    rssi_cb(mav_rssi, mav_noise, min(rx_errors, 65535), min(rx_fec, 65535), flags)
                except Exception:
                    log.err()

        if settings.common.debug:
            log.msg('RSSI %s TX %x %s %s' % (max(card_rssi_l) if card_rssi_l else 'N/A',
                                             self.tx_sel if self.tx_sel is not None else -1, packet_stats_by_rx, ant_stats_by_rx))


    def update_rx_stats(self, rx_id, packet_stats, ant_stats, session):
        self.cur_stats[rx_id] = (ant_stats, packet_stats)

        # Send stats to CLI sessions and logger
        for s in self.ui_sessions:
            s.send_stats(dict(type='rx',
                              timestamp = time.time(),
                              id=rx_id, tx_wlan=self.tx_sel,
                              packets=packet_stats, rx_ant_stats=ant_stats,
                              session=session))

    def update_tx_stats(self, tx_id, packet_stats, ant_latency):
        if settings.common.debug:
            log.msg("%s %r %r" % (tx_id, packet_stats, ant_latency))

        # Send stats to CLI sessions and logger
        for s in self.ui_sessions:
            rf_temperature = dict(self.rf_temp_meter.rf_temperature) if self.rf_temp_meter is not None else {}
            s.send_stats(dict(type='tx',
                              timestamp = time.time(),
                              id=tx_id,
                              packets=packet_stats,
                              latency=ant_latency,
                              rf_temperature=rf_temperature))



class RXAntennaProtocol(LineReceiver):
    delimiter = b'\n'

    """
    wfb_rx log parser
    """

    def __init__(self, ant_stat_cb, rx_id):
        self.ant_stat_cb = ant_stat_cb
        self.rx_id = rx_id
        self.ant = {}
        self.count_all = None
        self.session = None

    def lineReceived(self, line):
        line = line.decode('utf-8').strip()
        cols = line.split('\t')

        try:
            if len(cols) < 2:
                raise BadTelemetry()

            #ts = int(cols[0])
            cmd = cols[1]

            if cmd == 'RX_ANT':
                if len(cols) != 5:
                    raise BadTelemetry()
                self.ant[(tuple(int(i) for i in cols[2].split(':')), int(cols[3], 16))] = tuple(int(i) for i in cols[4].split(':'))

            elif cmd == 'PKT':
                if len(cols) != 3:
                    raise BadTelemetry()

                k_tuple = ('all', 'all_bytes', 'dec_err', 'dec_ok', 'fec_rec', 'lost', 'bad', 'out', 'out_bytes')
                counters = tuple(int(i) for i in cols[2].split(':'))
                assert len(counters) == len(k_tuple)

                if not self.count_all:
                    self.count_all = counters
                else:
                    self.count_all = tuple((a + b) for a, b in zip(counters, self.count_all))

                stats = dict(zip(k_tuple, zip(counters, self.count_all)))

                # Send stats to aggregators
                if self.ant_stat_cb is not None:
                    self.ant_stat_cb.update_rx_stats(self.rx_id, stats, dict(self.ant), self.session)

                self.ant.clear()

            elif cmd == 'SESSION':
                if len(cols) != 3:
                    raise BadTelemetry()

                epoch, fec_type, fec_k, fec_n = list(int(i) for i in cols[2].split(':'))
                self.session = dict(fec_type=fec_types.get(fec_type, 'Unknown'), fec_k=fec_k, fec_n=fec_n, epoch=epoch)
                log.msg('New session detected [%s]: FEC=%s K=%d, N=%d, epoch=%d' % (self.rx_id, fec_types.get(fec_type, 'Unknown'), fec_k, fec_n, epoch))

                if self.ant_stat_cb is not None:
                    self.ant_stat_cb.process_new_session(self.rx_id, self.session)
            else:
                raise BadTelemetry()
        except BadTelemetry:
            log.msg('Bad telemetry [%s]: %s' % (self.rx_id, line), isError=1)


class DbgProtocol(LineReceiver):
    delimiter = b'\n'

    """
    stderr parser
    """

    def __init__(self, rx_id):
        self.rx_id = rx_id

    def lineReceived(self, line):
        log.msg('%s: %s' % (self.rx_id, line.decode('utf-8')))



class TXAntennaProtocol(LineReceiver):
    delimiter = b'\n'

    def __init__(self, ant_stat_cb, tx_id, ports_df, control_port_df):
        self.ant_stat_cb = ant_stat_cb
        self.tx_id = tx_id
        self.ports_df = ports_df
        self.control_port_df = control_port_df
        self.ports = {}
        self.control_port = None
        self.ant = {}
        self.count_all = None

    def lineReceived(self, line):
        cols = line.decode('utf-8').strip().split('\t')
        if len(cols) < 2:
            return

        #ts = int(cols[0])
        cmd = cols[1]

        if cmd == 'LISTEN_UDP' and len(cols) == 3:
            port, wlan_id = cols[2].split(':', 1)
            self.ports[int(wlan_id, 16)] = int(port)

        elif cmd == 'LISTEN_UDP_END' and self.ports_df is not None:
            self.ports_df.callback(self.ports)

        elif cmd == 'LISTEN_UDP_CONTROL' and len(cols) == 3 and self.control_port_df is not None:
            port = cols[2]
            self.control_port = int(port)
            self.control_port_df.callback(self.control_port)

        elif cmd == 'TX_ANT':
            if len(cols) != 4:
                raise BadTelemetry()
            self.ant[int(cols[2], 16)] = tuple(int(i) for i in cols[3].split(':'))

        elif cmd == 'PKT':
            if len(cols) != 3:
                raise BadTelemetry()

            k_tuple = ('fec_timeouts', 'incoming', 'incoming_bytes', 'injected', 'injected_bytes', 'dropped', 'truncated')
            counters = tuple(int(i) for i in cols[2].split(':'))
            assert len(counters) == len(k_tuple)

            if not self.count_all:
                self.count_all = counters
            else:
                self.count_all = tuple((a + b) for a, b in zip(counters, self.count_all))

            stats = dict(zip(k_tuple, zip(counters, self.count_all)))

            # Send stats to aggregators
            if self.ant_stat_cb is not None:
                self.ant_stat_cb.update_tx_stats(self.tx_id, stats, dict(self.ant))

            self.ant.clear()


class RXProtocol(ProcessProtocol):
    """
    manager for wfb_rx process
    """

    def __init__(self, ant_stat_cb, cmd, rx_id):
        self.cmd = cmd
        self.rx_id = rx_id
        self.ant = RXAntennaProtocol(ant_stat_cb, rx_id) if ant_stat_cb else None
        self.dbg = DbgProtocol(rx_id)
        self.df = defer.Deferred()

    def connectionMade(self):
        log.msg('Started %s' % (self.rx_id,))

    def outReceived(self, data):
        if self.ant is not None:
            self.ant.dataReceived(data)

    def errReceived(self, data):
        self.dbg.dataReceived(data)

    def processEnded(self, status):
        rc = status.value.exitCode
        log.msg('Stopped RX %s with code %s' % (self.rx_id, rc))

        if rc == 0:
            self.df.callback(str(status.value))
        else:
            self.df.errback(status)

    def start(self):
        df = defer.maybeDeferred(reactor.spawnProcess, self, self.cmd[0], self.cmd, env=os.environ, childFDs={0: "w", 1: "r", 2: "r"})
        return df.addCallback(lambda _: self.df)


class TXProtocol(ProcessProtocol):
    """
    manager for wfb_tx process
    """

    def __init__(self, ant_stat_cb, cmd, tx_id, ports_df=None, control_port_df=None):
        self.cmd = cmd
        self.tx_id = tx_id
        self.dbg = DbgProtocol(tx_id)
        self.ports_df = ports_df
        self.control_port_df = control_port_df
        self.port_parser = TXAntennaProtocol(ant_stat_cb, tx_id, ports_df, control_port_df)
        self.df = defer.Deferred()

    def connectionMade(self):
        log.msg('Started %s' % (self.tx_id,))

    def outReceived(self, data):
        self.port_parser.dataReceived(data)

    def errReceived(self, data):
        self.dbg.dataReceived(data)

    def processEnded(self, status):
        rc = status.value.exitCode
        log.msg('Stopped TX %s with code %s' % (self.tx_id, rc))

        if self.ports_df is not None:
            self.ports_df.cancel()

        if self.control_port_df is not None:
            self.control_port_df.cancel()

        if rc == 0:
            self.df.callback(str(status.value))
        else:
            self.df.errback(status)

    def start(self):
        df = defer.maybeDeferred(reactor.spawnProcess, self, self.cmd[0], self.cmd, env=os.environ,
                                 childFDs={0: "w", 1: "r", 2: "r"})
        return df.addCallback(lambda _: self.df)


class SSHClientProtocol(ProcessProtocol):
    """
    manager for wfb_tx process
    """

    def __init__(self, host, username, cmd, *cmd_args, stdin=None, key=None, port=22, use_agent=True):
        self.host = host
        self.username = username
        self.cmd = cmd
        self.cmd_args = cmd_args
        self.stdin = stdin
        self.key = key
        self.port = 22
        self.use_agent = use_agent
        self.dbg = DbgProtocol('ssh %s' % (host,))
        self.df = defer.Deferred()

    def connectionMade(self):
        log.msg('Started ssh %s' % (self.host,))
        if self.stdin is not None:
            self.transport.write(self.stdin.encode('utf-8'))

    def outReceived(self, data):
        self.dbg.dataReceived(data)

    def errReceived(self, data):
        self.dbg.dataReceived(data)

    def processEnded(self, status):
        rc = status.value.exitCode
        log.msg('Stopped ssh %s with code %s' % (self.host, rc), isError=(rc != 0))

        if rc == 0:
            self.df.callback(str(status.value))
        else:
            self.df.errback(status)

    def start(self):
        args = ['ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'KbdInteractiveAuthentication=no',
                '-o', 'PasswordAuthentication=no']

        if self.stdin is None:
            args += ['-n']

        if self.key:
            args += ['-i', self.key,
                     '-o', 'IdentitiesOnly=yes']

        args += ['%s@%s' % (self.username, self.host), self.cmd] + list(self.cmd_args)

        env = dict(os.environ)

        if not self.use_agent:
            env.pop('SSH_AUTH_SOCK', None)

        df = defer.maybeDeferred(reactor.spawnProcess, self,
                                 args[0], args, env=env,
                                 childFDs={0: "w", 1: "r", 2: "r"})

        return df.addCallback(lambda _: self.df)
