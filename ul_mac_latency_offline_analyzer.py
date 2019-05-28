#!/usr/bin/python
# Filename: ul_mac_latency_analyzer.py
"""
ul_latency_breakdown_analyzer.py
An KPI analyzer to monitor mac layer waiting and processing latency

Author: Zhehui Zhang
"""

__all__ = ["UlMacLatencyOfflineAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from mobile_insight.analyzer import *
from mobile_insight.analyzer.analyzer import *

import time
import dis
import json


class UlMacLatencyOfflineAnalyzer(Analyzer):
    """
    An KPI analyzer to monitor and manage uplink latency breakdown
    """
    def __init__(self):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)

        self.receive_buffer = [] # queue: [increasing packet size, timestamp]
        self.send_buffer = [] # queue : [decrease packet size, timestamp]
        self.pdcp_pdu = [] # queue : [pdu size, timestamp]
        self.mac_pdu = []
        self.mac_cur_fn = 0 # mac sys fn timestamp 
        self.pdcp_cur_fn = 0 # pdcp sys fn timestamp
        self.buffer_bytes = 0
        self.pdcp_round = 0
        self.mac_round = 0
        self.mac_ts_dict = {}


    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # Phy-layer logs
        source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        source.enable_log("LTE_MAC_UL_Transport_Block")
        source.enable_log("LTE_PDCP_UL_Cipher_Data_PDU")
        
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
            log_item = msg.data.decode()
            # print log_item
            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:
                pkt_version = log_item['Subpackets'][0]['Version']
                for sample in log_item['Subpackets'][0]['Samples']:

                     # Count current system time
                    sub_fn = int(sample['Sub FN'])
                    sys_fn = int(sample['Sys FN'])
                    sys_time = sys_fn*10 + sub_fn

                    prev_time = self.mac_cur_fn
                    if sys_time < 10240:
                         # valid sys fn
                        if self.mac_cur_fn > 0:
                            self.mac_cur_fn = sys_time
                    elif self.mac_cur_fn >=0:
                        self.mac_cur_fn = (self.mac_cur_fn + 1) % 10240
                    else:
                        continue
                    if prev_time > self.mac_cur_fn:
                        self.mac_round += 1

                    for lcid in sample['LCIDs']:
                        idx = lcid['Ld Id']

                        if idx != 3:
                            continue

                        if pkt_version == 24:
                            new_bytes = lcid.get('New Compressed Bytes', 0)
                        else:
                            new_bytes = lcid.get('New bytes', 0)
                        ctrl_bytes = lcid.get('Ctrl bytes', 0)
                        retx_bytes = lcid.get('Retx bytes',0)
                        total_bytes = new_bytes +retx_bytes# if 'Total Bytes' not in lcid else int(lcid['Total Bytes'])
                        
                        # if total_bytes > 0:
                            # print "Buffer",log_item['timestamp'],self.mac_cur_fn, total_bytes

                        if total_bytes > self.buffer_bytes:
                            # if buffer increase --> new packet adding in the buffer
                            increase_bytes = total_bytes - self.buffer_bytes
                            # print str(self.mac_cur_fn + self.mac_round*10240)+','+str(increase_bytes)
                            # if sys_time < 10240:
                            #     print str(self.mac_cur_fn)+','+str(increase_bytes),str(log_item['timestamp']),sys_time
                            
                            self.receive_buffer.append([increase_bytes,self.mac_cur_fn+10240*self.mac_round])
                            self.mac_ts_dict[increase_bytes] = self.mac_cur_fn + self.mac_round*10240


                        elif total_bytes < self.buffer_bytes:
                            # print str(self.mac_cur_fn +self.mac_round*10240) +','+ str(self.buffer_bytes - total_bytes)
                            send_bytes = self.buffer_bytes - total_bytes
                            self.send_buffer.append([send_bytes,self.mac_cur_fn+10240*self.mac_round])

                            while len(self.mac_pdu) > 0 and send_bytes > 0:
                                pkt = self.mac_pdu[0]
                                # cur size, recieve time, orginal size, send time
                                if pkt[0] <= send_bytes:
                                    #totaly send
                                    pkt_delay = (self.mac_cur_fn - pkt[1])% 10240
                                    wait_delay = (self.mac_cur_fn - pkt[3]) % 10240

                                    self.mac_pdu.pop(0)
                                    send_bytes -= pkt[0]
                                    print "Send Packet: " + str(log_item['timestamp']) + " " +  str(self.mac_cur_fn) + " Packet Size: "  + str(pkt[2]) + " Packet Delay: " + str(pkt_delay) + " Wait Delay: " + str(wait_delay)
                                    print "-----"*10
                                else:
                                    pkt[0] -= send_bytes
                                    send_bytes = 0
                                    
                                    
                        
                        self.buffer_bytes = total_bytes


        elif msg.type_id == "LTE_PDCP_UL_Cipher_Data_PDU":
            log_item = msg.data.decode()
            if 'Subpackets' in log_item:
                for pkt in log_item['Subpackets'][0]['PDCPUL CIPH DATA']:
                    idx = pkt['Cfg Idx']
                    if idx != 3:
                        continue

                    fn = int(pkt['Sys FN'])
                    sfn = int(pkt['Sub FN'])
                    prev_time = self.pdcp_cur_fn

                    self.pdcp_cur_fn = fn*10 + sfn

                    if prev_time > self.pdcp_cur_fn:
                        self.pdcp_round += 1


                    pdu_size = pkt['PDU Size']
                    # print "-----"*10
                    
                    # print str(self.pdcp_cur_fn+ 10240*self.pdcp_round) +','+str( pdu_size)
                    # print "-----"*10
                    if self.mac_ts_dict.has_key(pdu_size):
                        print str(pdu_size)+','+str(self.pdcp_cur_fn+ 10240*self.pdcp_round)+','+str(self.mac_ts_dict[pdu_size])+','+str(self.pdcp_cur_fn+ 10240*self.pdcp_round - self.mac_ts_dict[pdu_size])
                    else:
                        print str(pdu_size)+','+str(self.pdcp_cur_fn+ 10240*self.pdcp_round)+',-1'
                    self.pdcp_pdu.append([pdu_size,self.pdcp_cur_fn + 10240*self.pdcp_round])
                    # find the place pdu recived
                    while len(self.pdcp_pdu) > 0 and len(self.receive_buffer) > 0:
                        pdu = self.pdcp_pdu[0]
                        recieve = self.receive_buffer[0]
                        
                        if recieve[0] < pdu[0]:
                            self.receive_buffer.remove(recieve)
                            print "pkt recieve at",recieve[1],pdu[0], pdu[1]
                            print "smaller size", recieve
                            self.mac_pdu.append([pdu[0],recieve[1],pdu[0],pdu[1]])                            
                            self.pdcp_pdu.remove(pdu) 
                            if recieve in self.receive_buffer:
                                self.receive_buffer.remove(recieve)
                            send_bytes = pdu[0]-recieve[0]
                            while len(self.mac_pdu) > 0 and send_bytes > 0:
                                pkt = self.mac_pdu[0]
                                # cur size, recieve time, orginal size, send time
                                if pkt[0] <= send_bytes:
                                    #totaly send
                                    pkt_delay = (self.mac_cur_fn - pkt[1])% 10240
                                    wait_delay = (self.mac_cur_fn - pkt[3]) % 10240

                                    self.mac_pdu.pop(0)
                                    send_bytes -= pkt[0]
                                    print "Send Packet: " + str(log_item['timestamp']) + " " +  str(self.mac_cur_fn) + " Packet Size: "  + str(pkt[2]) + " Packet Delay: " + str(pkt_delay) + " Wait Delay: " + str(wait_delay)
                                    print "-----"*10
                                else:
                                    pkt[0] -= send_bytes
                                    send_bytes = 0
                                    print "pkt display",pkt
                            

                        else:
                        #TODO: if the buffer did not increase before recieve pdcp
                            
                            print "pkt recieve at:",recieve[1],pdu[0], pdu[1]
                            recieve[0] -= pdu[0]
                            self.mac_pdu.append([pdu[0],recieve[1],pdu[0],pdu[1]])
                            self.pdcp_pdu.remove(pdu)
                            print self.mac_pdu[len(self.mac_pdu)-1]
                            print recieve
                            print pdu

                        while len(self.send_buffer) > 0 and len(self.mac_pdu) > 0 :
                            # print "send buffer", self.send_buffer
                            send_info = self.send_buffer.pop(0)
                            send_bytes = send_info[0]
                            send_ts = send_info[1]
                            if send_ts < self.mac_pdu[0][3]:
                                continue
                            while len(self.mac_pdu) > 0 and send_bytes > 0:
                                pkt = self.mac_pdu[0]
                                
                                # cur size, recieve time, orginal size, send time
                                if pkt[0] <= send_bytes:
                                    #totaly send
                                    pkt_delay = (send_ts - pkt[1])% 10240
                                    wait_delay = (send_ts - pkt[3]) % 10240

                                    self.mac_pdu.pop(0)
                                    send_bytes -= pkt[0]
                                    print "Send Packet: " + str(log_item['timestamp']) + " " +  str(send_ts) + " Packet Size: "  + str(pkt[2]) + " Packet Delay: " + str(pkt_delay) + " Wait Delay: " + str(wait_delay)
                                    print "-----"*10
                                    print "pkt",pkt
                                else:
                                    pkt[0] -= send_bytes
                                    send_bytes = 0
                            
                            
                    
                       
                        
                            
                            



                             

                    
            





        

