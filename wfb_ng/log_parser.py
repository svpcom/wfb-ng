#!/usr/bin/env python3

import sys
import time
import msgpack
import struct
import gzip
from pprint import pformat
from .mavlink_protocol import unpack_mavlink


def main():
    for f in sys.argv[1:]:
        with gzip.GzipFile(f, 'rb') as fd:
            while True:
                hdr = fd.read(4)

                if len(hdr) < 4:
                    break

                data_len = struct.unpack('!I', hdr)[0]
                data = fd.read(data_len)

                if len(data) < data_len:
                    break

                msg =  msgpack.unpackb(data, strict_map_key=False, use_list=False, raw=False)
                ts = msg.pop('timestamp')
                mtype = msg.pop('type')

                if mtype == 'mavlink':
                    seq, sys_id, comp_id, msg_id = msg.pop('hdr')
                    msg['sys_id'] = sys_id
                    msg['comp_id'] = comp_id
                    msg['seq'] = seq

                    mav_message = msg.pop('msg')
                    try:
                        k, v = unpack_mavlink(msg_id, mav_message)
                        msg[k] = v
                    except Exception as v:
                        msg['msg'] = mav_message
                        msg['parse_error'] = v

                ts_txt = time.strftime('%Y-%m-%d %H:%M:%S.{} %Z'.format(('%.3f' % ((ts % 1),))[2:]), time.localtime(ts))
                msg_pp = ('\n%s\t%s\t' % (' ' * len(ts_txt), ' ' * len(mtype)))\
                                   .join(pformat(msg, compact=True, sort_dicts=False).split('\n'))
                print('%s\t%s\t%s' % (ts_txt, mtype, msg_pp))


if __name__ == '__main__':
    main()
