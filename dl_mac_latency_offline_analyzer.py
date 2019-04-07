"""
dl_mac_latency_offline_analyzer.py
Analyer to monitor downlink latency 
"""

__all__ = ["DLMacLatencyAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from mobile_insight.analyzer import *
from mobile_insight.analyzer.analyzer import *

import time
import dis
import json
import sys


class DLMacLatencyAnalyzer(Analyzer):
    """
    An KPI analyzer to monitor and manage downlink latency breakdown
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.add_source_callback(self.__msg_callback)
      
        self.rlc_round = 0 
        self.rlc_cur_fn = 0

        self.rlc_SN = -1

  

        self.pdcp_cur_fn = 0 
        self.pdcp_round = 0
        self.pdcp_pkts = []

        self.pdsch_cur_fn = 0
        self.pdsch_round = 0
        self.pdsch_fail_dict = {} # store the fail transfer block [HARQ ID : [timestamp, block size],...[timestamp, block size]]
        #store the first fail of the combine(HARQ ID, TB index)
        self.pdsch_rx = {} # store the retransmission block [[attempt tran ts, success timestamp, block size ]]
        self.missing_sn = -1
        self.block_sn = []
        self.pkt_num = 0
        self.rx_num = 0
        self.block_num = 0

        self.rlc_pdu_pkt = {}  # cycle array store the rlc pdu packet
        self.waiting_sn = -1
        self.waiting_time = 0
        self.debug = True
        self.num = 0
        self.tx_delay_num = 0
        self.block_delay_num = 0
       
    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # Phy-layer logs
        source.enable_log("LTE_RLC_DL_AM_All_PDU")
        # source.enable_log("LTE_PDCP_DL_Cipher_Data_PDU")
        # source.enable_log("LTE_PHY_PDSCH_Stat_Indication")
        
    def enable_mapping(self):
        self.mapping = True


    def __msg_callback(self, msg):
       
        if msg.type_id == "LTE_PHY_PDSCH_Stat_Indication":
            log_item = msg.data.decode()
            # print log_item
            if 'Records' in log_item and len(log_item['Records']) > 0:
                for record in log_item['Records']:
                   
                    prev_time = self.pdsch_cur_fn
                    sys_fn = record['Frame Num']
                    sub_fn = record['Subframe Num']
                    sys_time = sys_fn*10+ sub_fn
                    self.pdsch_cur_fn = sys_time
                    if prev_time > sys_time:
                        self.pdsch_round += 1
                    # block = record['Transport Blocks'][0]
                    # HARQ_id = block['HARQ ID']
                    print '-----',sys_time,'-----' 
                    # print record
                    for block in record['Transport Blocks']:
                        # print block
                        print sys_time, 'Harid:',block['HARQ ID'],block['CRC Result'],block['TB Size'],block['Did Recombining']

                    # print sys_time
                    # print record
                    # if block['CRC Result'] == 'Fail':
                    #     # print 'Fail', sys_time, record['Transport Blocks'][0]
                    #     if not self.pdsch_fail_dict.has_key(HARQ_id):
                    #         self.pdsch_fail_dict[HARQ_id] = [sys_time,block['TB Size']]
                       

                            
                    # elif  block['CRC Result'] == 'Pass':
                    #     if self.pdsch_fail_dict.has_key(HARQ_id):
                    #         if block['Did Recombining'] == 'Yes':
                    #             # print 'Pass',self.pdsch_fail_dict[HARQ_id][0], sys_time, self.pdsch_fail_dict[HARQ_id][1]
                    #             self.pdsch_rx[sys_time] = self.pdsch_fail_dict[HARQ_id][0]
                    #         del self.pdsch_fail_dict[HARQ_id]

        elif msg.type_id == "LTE_RLC_DL_AM_All_PDU":
            log_item = msg.data.decode()
            # print log_item 
            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:
                if log_item['Subpackets'][0]['RB Cfg Idx']==3 :
                    
                    # print log_item['Subpackets']
                    for pdu in log_item['Subpackets'][0]['RLCDL PDUs']:
                        # print pdu
                        if pdu['Status'] == 'PDU DATA' and pdu['RF'] == '0':
                            # print  pdu
                            if self.debug:
                                print '--------'
                                print log_item 
                                print pdu

                           
                            sys_fn = pdu['sys_fn']
                            sub_fn = pdu['sub_fn']
                           
                            prev_time = self.rlc_cur_fn
                            sys_time = sys_fn*10 + sub_fn
                            self.rlc_cur_fn = sys_time
                            if prev_time > sys_time:
                                self.rlc_round += 1
                            
                            pdu_bytes = pdu['pdu_bytes']-pdu['logged_bytes']
                            # print log_item['timestamp'], 10240*self.rlc_round+sys_time, pdu['SN'],pdu_bytes
                            cur_sys_time = sys_time + 10240*self.rlc_round
                        
                            
                            SN = pdu['SN']
                            FI = pdu['FI']
                            """
                            Store the partial pdu packet into lists
                            lists contains FI and size pair
                            list[0] : 00/01/10/11
                            list[1] : partial pdu size
                            """
                            lists = []
                            #list['00/01/10/11',size,timestamp]
                            if 'RLC DATA LI' in pdu:
                                LI = pdu['RLC DATA LI']
                                lists.append([FI[0]+'0',LI[0]['LI'],cur_sys_time])
                                pdu_bytes -= LI[0]['LI']
                                for i in range(1,len(LI)):
                                    lists.append(['00',LI[i]['LI'],cur_sys_time])
                                    pdu_bytes -= LI[i]['LI']
                                lists.append(['0'+FI[1],pdu_bytes,cur_sys_time])
                            else:
                                lists.append([FI,pdu_bytes,cur_sys_time])
                            
                            if self.debug:
                                print '--------'
                                print cur_sys_time,sys_time
                                
                            #Data start Transmitting, Sequence Number(SN) should arrive in increasing sequence from 0 to 1023
                            if SN == 0 and len(self.rlc_pdu_pkt) == 0:
                               self.waiting_sn = 0 
                               print 'Time:',sys_time, "Start Transmitting"

                            if self.debug:

                                print 'wait:' ,self.waiting_sn
                                print 'waiting time', self.waiting_time
                                print 'SN:',SN, 'Lists:',lists 

                            #first records 
                            if self.waiting_sn == -1:
                                self.waiting_sn = SN+1
                        
                                while len(lists) != 0:
                                    if lists[0][0] == '00':
                                        print  self.num, 'PDU SIZE:',lists[0][1]
                                        self.num += 1

                                        self.log_info('PDU SIZE:'+str(lists[0][1]))
                                        lists.pop(0)
                                    else:
                                        break

                                if self.debug:
                                    print lists

                                if len(lists) != 0:
                                    self.rlc_pdu_pkt[SN] = lists

                            
                            # store in the buffer and wait for the waiting SN        
                            elif self.waiting_sn != SN:
                                self.rlc_pdu_pkt[SN] = lists
                                self.waiting_time += 1 


                            # get the SN waiting for 
                            elif self.waiting_sn == SN:
                                left_SN = (SN-1)%1024
                                remain_size = 0
                                remain_FI = '00'
                                remain_sys_time = cur_sys_time

                                if self.rlc_pdu_pkt.has_key(left_SN):
                                    # remain_list = self.rlc_pdu_pkt[left_SN]
                                    remain_FI = self.rlc_pdu_pkt[left_SN][-1][0]
                                    remain_size = self.rlc_pdu_pkt[left_SN][-1][1]
                                    remain_sys_time = self.rlc_pdu_pkt[left_SN][-1][2]
                                    del self.rlc_pdu_pkt[left_SN]

                                    
                                lists[0][0] = remain_FI[0] + lists[0][0][1]
                                lists[0][1] = remain_size + lists[0][1]
                                lists[0][2] = min(remain_sys_time,cur_sys_time)


                                while len(lists) != 0:
                                    if lists[0][0] == '00':
                                        
                                        tx_delay = cur_sys_time-lists[0][2]
                                        
                                        self.num += 1
                                        if tx_delay > 0:
                                            self.tx_delay_num += 1
                                        self.log_info(str(self.num)+' PDU SIZE:'+str(lists[0][1])+' TX DELAY: '+str(tx_delay)+' Start: '+str(lists[0][2]%10240)+' End: '+str(cur_sys_time%10240))
                                        print str(self.num)+' PDU SIZE:'+str(lists[0][1])+' TX DELAY: '+str(tx_delay)+' Start: '+str(lists[0][2]%10240)+' End: '+str(cur_sys_time%10240)
                                        lists.pop(0)
                                    else:
                                        break

                                if len(lists) != 0:
                                    self.rlc_pdu_pkt[SN] = lists
                                
                                if self.debug:
                                    print 'dict: ',self.rlc_pdu_pkt


                                # release the blocked packet 
                                next_SN = (SN+1)%1024
                                min_sys_time = cur_sys_time
                                max_sys_time = cur_sys_time

                                while self.rlc_pdu_pkt.has_key(next_SN):
                                    next_list = self.rlc_pdu_pkt[next_SN]
                                    
                                    remain_size = 0
                                    remain_FI = '00'
                                    
                                    
                                    prev_SN = (next_SN-1)%1024
                                    if self.rlc_pdu_pkt.has_key(prev_SN):
                                        remain_FI = self.rlc_pdu_pkt[prev_SN][-1][0]
                                        remain_size = self.rlc_pdu_pkt[prev_SN][-1][1]
                                        max_sys_time = max(max_sys_time,self.rlc_pdu_pkt[prev_SN][-1][2])
                                        min_sys_time = min(min_sys_time,self.rlc_pdu_pkt[prev_SN][-1][2])
                                        
                                        
                                        del self.rlc_pdu_pkt[prev_SN]

                                    next_list[0][0] = remain_FI[0] + next_list[0][0][1]
                                    next_list[0][1] = remain_size + next_list[0][1]
                                    
                                   
                                    while len(next_list) != 0:
                                        if next_list[0][0] == '00':
                                            tx_delay = max_sys_time - min_sys_time
                                            block_delay = cur_sys_time-max_sys_time
                                            if tx_delay > 0 :
                                                self.tx_delay_num += 1
                                            self.block_delay_num += 1
                                            self.num += 1
                                            print  self.num, 'PDU SIZE:',next_list[0][1],'TX Delay: ', tx_delay, 'Blocked Delay:',block_delay, 'Blocked by', SN, 'Start:', min_sys_time%10240, 'End:',max_sys_time%10240
                                            self.log_info(str(self.num)+ ' PDU SIZE: '+str(next_list[0][1])+' TX Delay: '+str(tx_delay)+ ' Blocked Delay: '+str(block_delay)+ ' Blocked by :'+str(SN)+' Start: '+str( min_sys_time%10240)+' End: '+str(max_sys_time%10240))
                                            
                                            max_sys_time = next_list[0][2]
                                            min_sys_time = next_list[0][2]
                                            
                                            
                                            
                                            next_list.pop(0)
                                        else:
                                            break
                                        
                                    if len(next_list)==0:
                                        del self.rlc_pdu_pkt[next_SN%1024]
                                    next_SN = (next_SN+1)%1024


                                self.waiting_sn = next_SN
                                self.waiting_time = 0
                            
                            if self.debug:
                                print 'SN:',SN, 'residual lists:',lists
                                print 'residual dict:',self.rlc_pdu_pkt
                                print 'waiting for:',self.waiting_sn



                                


                                
                        
                                
                                    


                                    


                                    
                            

        elif msg.type_id == "LTE_PDCP_DL_Cipher_Data_PDU":
            log_item = msg.data.decode()
            # print log_item
            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:
                for pkt in log_item['Subpackets'][0]['PDCPDL CIPH DATA']:
                    
                    if pkt['Cfg Idx'] != 3:
                        continue

                    fn = int(pkt['Sys FN'])
                    sfn = int(pkt['Sub FN'])
                    prev_time = self.pdcp_cur_fn

                    self.pdcp_cur_fn = fn*10 + sfn

                    if prev_time > self.pdcp_cur_fn:
                        self.pdcp_round += 1


                    pdu_size = pkt['PDU Size']
                    print 'PDCP', log_item['timestamp'],  self.pdcp_cur_fn, pdu_size
                    # print pdu_size
                    self.pdcp_pkts.append([ self.pdcp_cur_fn, pdu_size])
