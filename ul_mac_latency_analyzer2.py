#!/usr/bin/python
# Filename: ul_mac_latency_analyzer.py
"""
ul_latency_breakdown_analyzer.py
An KPI analyzer to monitor mac layer waiting and processing latency

Author: Zhehui Zhang
"""

__all__ = ["UlMacLatencyAnalyzer2"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from mobile_insight.analyzer import *
from mobile_insight.analyzer.analyzer import *

import time
import dis
import json


class UlMacLatencyAnalyzer2(Analyzer):
    """
    An KPI analyzer to monitor and manage uplink latency breakdown
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.add_source_callback(self.__msg_callback)
        self.last_bytes = {} # LACI -> bytes <int> Last remaining bytes in MAC UL buffer
        self.buffer = {} # LCID -> [sys_time, packet_bytes] buffered mac ul packets
        self.ctrl_pkt_sfn = {} # LCID -> sys_fn*10 + sun_fn when last mac ul control packet comes
        self.cur_fn = -1 # Record current sys_fn*10+ sub_fn for mac ul buffer
        self.lat_stat = [] # Record ul waiting latency (ts, sys_time, pdu_size)
        self.queue_length = 0
        self.mapping = False
        self.bcast_dict = {}
        self.mac_buffer_dict = {}

        self._ana_delay = 0
        self._ana_delay1 = 0
        self._ana_delay2 = 0
        self._ana_delay3 = 0
        self._ana_delay4 = 0
        self._ul_pkt_num = 0
        self.__decode_delay = 0
        self._bytes = 0
        self._debug = False
        # dis.dis(self.__msg_callback)
        ul_latency_dict = {}
        ul_latency_dict['timestamp'] = '1000'
        ul_latency_dict['size'] = '75'
        self.broadcast_info('UL_LAT', ul_latency_dict)
        # self.broadcast_info('UL_LAT', {})
        # self.log_info("Received")

        self.cnt1 = 0
        self.cnt2 = 0

        self.trans_delay = []
        self.trans_size = 0

        self.buffer_bytes = 0 # current buffer size
        self.buffer_queue = []
        self.send_dict = {}
        self.round = 0
        self.buffer_backup = []


        


    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # Phy-layer logs
        # source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        source.enable_log("LTE_MAC_UL_Transport_Block")
        # source.enable_log("LTE_PDCP_UL_Cipher_Data_PDU")
        
    def enable_mapping(self):
        self.mapping = True

    def __del_lat_stat(self):
        """
        Delete one lat_buffer after it is matched with rlc packet
        :return:
        """
        del self.lat_stat[0]

    def __msg_callback(self, msg):
        # self.broadcast_info('UL_LAT', {})

        if msg.type_id == "LTE_MAC_UL_Buffer_Status_Internal":
            self.cnt1 += 1

            before_decode_time = time.time()
            log_item = msg.data.decode()

            self.__decode_delay += time.time() - before_decode_time
            before_ana_time = time.time()

            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:

                pkt_version = log_item['Subpackets'][0]['Version']
                for sample in log_item['Subpackets'][0]['Samples']:
                    before_ana_time1 = time.time()
                    sub_fn = int(sample['Sub FN'])
                    sys_fn = int(sample['Sys FN'])
                    sys_time = sys_fn*10 + sub_fn

         
                    prev_time = self.cur_fn
                    if sys_time < 10240:
                        if self.cur_fn > 0:
                            
                            lag = sys_time - self.cur_fn
                            if lag > 1 or -10239 < lag < 0:
                                self.last_bytes = {}
                                self.buffer = {}
                                self.ctrl_pkt_sfn = {}
                        self.cur_fn = sys_time
                    elif self.cur_fn >= 0: # if invalid and inited, add current sfn
                        self.cur_fn = (self.cur_fn + 1)%10240
                    else:
                        continue
                    if prev_time > self.cur_fn:
                        self.round += 1
                    
                    
                    

                    self._ana_delay1 += time.time() - before_ana_time1

                    for lcid in sample['LCIDs']:
                        before_ana_time2 = time.time()
                        idx = lcid['Ld Id']

                        if idx != 3:
                        
                            continue
                        #FIXME: Are these initializations valid?
                        if pkt_version == 24:
                            new_bytes = lcid.get('New Compressed Bytes', 0)
                        else:
                            new_bytes = lcid.get('New bytes', 0)
                        ctrl_bytes = lcid.get('Ctrl bytes', 0)
                        retx_bytes = lcid.get('Retx bytes',0)
                        total_bytes = new_bytes + ctrl_bytes +retx_bytes# if 'Total Bytes' not in lcid else int(lcid['Total Bytes'])
                        if total_bytes > 0:
                            print "Buffer",self.cnt1, log_item['timestamp'], self.round*10240 + self.cur_fn,self.cur_fn, total_bytes

                            
                        
                        
                        
                        self._ana_delay2 += time.time() - before_ana_time2
                        before_ana_time3 = time.time()

                        if total_bytes > self.buffer_bytes:
                            # if buffer grow --> new pkt adding in the buffer
                            increase_bytes = total_bytes - self.buffer_bytes
                            print "recieve:", increase_bytes
                            item = [self.cur_fn, increase_bytes] # recieve ts, recieve bytes
                            # print item
                            self.buffer_queue.append(item)
                            self.buffer_backup.append([self.cur_fn, increase_bytes])
                            
                        elif total_bytes < self.buffer_bytes:
                            print self.cur_fn, "current bytes:" , total_bytes , "previous bytes" , self.buffer_bytes , "send:" , self.buffer_bytes - total_bytes
                            # if buffer decrease --> may send data
                            # may recieve data at the same time discuss at transfer log
                            sent_bytes = self.buffer_bytes - total_bytes
                            self.send_dict[self.round*10240 + self.cur_fn] = sent_bytes

                            while len(self.buffer_queue) > 0 and sent_bytes > 0:
                                pkt = self.buffer_queue[0]
                                if len(pkt) == 2:
                                    pkt.append(self.cur_fn)
                                    pkt.append(pkt[1])
                                
                                if pkt[1] <= sent_bytes:
                                    # totally send
                                    pkt_delay = (self.cur_fn - pkt[0])%10240
                                    wait_delay = (self.cur_fn - pkt[2])%10240

                                    self.buffer_queue.pop(0)
                                    sent_bytes -= pkt[1]
                                    
                                    ul_latency_dict = {}
                                    ul_latency_dict['timestamp'] = self.cur_fn
                                    ul_latency_dict['size'] = pkt
                                    ul_latency_dict['latency'] = str(pkt_delay)

                                    self.broadcast_info('UL_LAT', ul_latency_dict)
                                    self.log_info("Should bcast")

                                    self.log_info("Send Packet: " + str(log_item['timestamp']) + " " +  str(self.cur_fn) + "Packet Size: "  + str(pkt[3]) + "Packet Delay: " + str(pkt_delay) + "Wait Delay: " + str(wait_delay))
                                    # print "Send Packet: " + str(log_item['timestamp']) + " " +  str(self.cur_fn) + "Packet Size: "  + str(pkt[3]) + "Packet Delay: " + str(pkt_delay) + "Wait Delay: " + str(wait_delay)
                                    # print "-----"*10
                                else:
                                    pkt[1] -= sent_bytes
                                    sent_bytes = 0
                                    print pkt
                        self.buffer_bytes = total_bytes


            self._ana_delay += time.time() - before_ana_time

            if self._debug:
                self.log_info('decode ' + str(self.__decode_delay))
                self.log_info('ana ' + str(self._ana_delay))
                self.log_info('ana1 ' + str(self._ana_delay1))
                self.log_info('ana2 ' + str(self._ana_delay2))
                self.log_info('ana3 ' + str(self._ana_delay3))
                self.log_info('ana4 ' + str(self._ana_delay4))
                self.log_info('bytes ' + str(self._bytes))

        elif msg.type_id == "LTE_MAC_UL_Transport_Block":
            self.cnt2 += 1
            before_decode_time = time.time()
            log_item = msg.data.decode()
            self.__decode_delay += time.time() - before_decode_time
            before_ana_time = time.time()
            ts = str(log_item['timestamp'])
            # print log_item
            # self.log_info(str(log_item))
            if 'Subpackets' in log_item:
                # print log_item['Subpackets']
                # self.bytes4 += log_item['Subpackets'][0]['SubPacket Size']
                for pkt in log_item['Subpackets'][0]['Samples']:
                    # print pkt
                    grant = pkt['Grant (bytes)']
                    harq_id = pkt['HARQ ID']
                    HDR = pkt['HDR LEN']
                    pkt_size = grant - HDR
                    self.trans_size += pkt_size
                    fn = int(pkt['SFN'])
                    sfn = int(pkt['Sub-FN'])
                    
                    BSR_trig = pkt['BSR trig']
                    if 'S-BSR' in BSR_trig:
                        pkt_size -= 1
                    elif 'L-BSR' in BSR_trig:
                        pkt_size -= 3

                    try:
                        cell_id = int(pkt['Cell Id'])
                    except KeyError:
                        cell_id = 0
                    print "Transfer", pkt['BSR event'],self.cnt2, log_item['timestamp'], fn *10 + sfn, pkt_size
                    sys_time = fn*10 + sfn
                    round_sys_time = self.round*10240 + sys_time
                    if self.send_dict.has_key(round_sys_time):
                        print "Ensure: transfer:", pkt_size, "buffer:", self.send_dict[round_sys_time]
                    # print sorted(self.send_dict.keys())
                    for key in sorted(self.send_dict.keys()):
                        
                        if key <= round_sys_time:
                            sent_bytes = self.send_dict[key]
                            print "key",key,"value",sent_bytes
                            
                            while len(self.buffer_backup) > 0 and sent_bytes > 0:
                                
                                pkt = self.buffer_backup[0]
                                
                                if len(pkt) == 2:
                                    pkt.append(key % 10240)
                                    pkt.append(pkt[1])
                                
                                if pkt[1] <= sent_bytes:
                                    # totally send
                                    pkt_delay = (key%10240- pkt[0])%10240
                                    wait_delay = (key%10240- pkt[2])%10240

                                    self.buffer_backup.pop(0)
                                    sent_bytes -= pkt[1]
                                    
                                    ul_latency_dict = {}
                                    ul_latency_dict['timestamp'] = key%10240
                                    ul_latency_dict['size'] = pkt
                                    ul_latency_dict['latency'] = str(pkt_delay)

                                    self.broadcast_info('UL_LAT', ul_latency_dict)
                                    self.log_info("Should bcast")

                                    self.log_info("B:Send Packet: " + str(log_item['timestamp']) + " " + str(key%10240)  + "Packet Size: "  + str(pkt[3]) + "Packet Delay: " + str(pkt_delay) + "Wait Delay: " + str(wait_delay))
                                    print "B:Send Packet: " + str(log_item['timestamp']) + " " +  str(key%10240) + "Packet Size: "  + str(pkt[3]) + "Packet Delay: " + str(pkt_delay) + "Wait Delay: " + str(wait_delay)
                                    print "-----"*10
                                else:
                                    pkt[1] -= sent_bytes
                                    sent_bytes = 0
                                

                            del self.send_dict[key]


        elif msg.type_id == "LTE_PDCP_UL_Cipher_Data_PDU":
            log_item = msg.data.decode()
            # print log_item
            if 'Subpackets' in log_item:
                for pkt in log_item['Subpackets'][0]['PDCPUL CIPH DATA']:
                    
                    idx = pkt['Cfg Idx']
                    if idx != 3:
                        continue
                    fn = int(pkt['Sys FN'])
                    sfn = int(pkt['Sub FN'])
                    sys_time = fn*10 + sfn
                    pdu_size = pkt['PDU Size']
                    print "PDCP",sys_time, pdu_size
                    
            





        

