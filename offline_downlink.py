#!/usr/bin/python

import os
import sys
import shutil
import traceback
# import matplotlib.pyplot as plt
import csv

# from logging_analyzer import LoggingAnalyzer
# from service import mi2app_utils
from mobile_insight.monitor import OfflineReplayer, OnlineMonitor

from dl_mac_latency_offline_analyzer import DLMacLatencyAnalyzer
from dl_mac_latency_offline_analyzer2 import DLMacLatencyAnalyzer2

def kpi_analysis():


    src = OfflineReplayer()
    src.set_input_path(sys.argv[1])

    analyzer = DLMacLatencyAnalyzer()
    
    
    
     
    analyzer.set_source(src) 
    src.run()

    analyzer.log_info('Total packets: '+str(analyzer.num))
    analyzer.log_info('Number of TX delay: '+str(analyzer.tx_delay_num))

    analyzer.log_info('Number of blocked packets: '+str(analyzer.block_delay_num))
    
        
    
    # print analyzer.blocked_pkts
    
    
    # x = []
    # y = []
    # for row in analyzer.pdu_pkts:
    #     x.append(row[0])
    #     y.append(row[2])
    # x1 = []
    # y1 = []
    # for row in analyzer.pdu_pkts:
    #     x1.append(row[1])
    #     y1.append(row[2])
    # x2 = []
    # y2 = []
    # for row in analyzer.pdcp_pkts:
    #     x2.append(row[0])
    #     y2.append(row[1])
    
    # plt.scatter(x2,y2,s=10, color = 'g',label = 'pdcp packet')
    # plt.scatter(x1,y1,s=5, color = 'b', label='pdcp package finish recieving')
    # plt.scatter(x,y,s=2,color='r', label='pdcp package start recieving')
    # plt.xlabel('Timestamp')
    # plt.ylabel('Package Size')
    # plt.title('Demo')
    # plt.legend()
    # plt.show()

    # for i in range(0,min(len(analyzer.pdcp_pkts), len(analyzer.pdu_pkts))):
    #     if(analyzer.pdu_pkts[i][1] == analyzer.pdcp_pkts[i][0] and analyzer.pdu_pkts[i][2] == analyzer.pdcp_pkts[i][1]):
    #         print 'Match', analyzer.pdu_pkts[i]
    #     else:
    #         print 'Not', analyzer.pdu_pkts[i], analyzer.pdcp_pkts[i]



    
     
kpi_analysis()

