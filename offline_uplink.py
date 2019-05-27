#!/usr/bin/python
from __future__ import division
import os
import sys
import shutil
import traceback
import matplotlib.pyplot as plt
import csv

# from logging_analyzer import LoggingAnalyzer
# from service import mi2app_utils
from mobile_insight.monitor import OfflineReplayer, OnlineMonitor
from ul_mac_latency_analyzer import UlMacLatencyAnalyzer
from ul_lat_breakdown_analyzer import UlLatBreakdownAnalyzer
from ul_mac_latency_analyzer2 import UlMacLatencyAnalyzer2
from ul_mac_latency_offline_analyzer import UlMacLatencyOfflineAnalyzer
from ul_rlc_analyzer import UlRLCAnalyzer

def kpi_analysis():
    # src = OfflineReplayer()
    # src.set_input_path('/sdcard/mobileinsight/plugins/test_analyzer/vr_log.mi2log')
    # cache_directory = mi2app_utils.get_cache_dir()
    # log_directory = os.path.join(cache_directory, "mi2log")

    src = OfflineReplayer()
    src.set_input_path(sys.argv[1])

    analyzer = UlRLCAnalyzer()
    analyzer.set_source(src) 
    # analyzer.set_idx(3)
    src.run()

    
    x = []
    y = []
    for row in analyzer.pdu_pkts:
        x.append(row[0])
        y.append(row[2])
    x1 = []
    y1 = []
    for row in analyzer.pdu_pkts:
        x1.append(row[1])
        y1.append(row[2])
    x2 = []
    y2 = []
    for row in analyzer.receive_buffer_backup:
        x2.append(row[1])
        y2.append(row[0])
    x3 = []
    y3 = []
    for row in analyzer.pdcp_rx:
        x3.append(row[0])
        y3.append(row[1])



    total = len(analyzer.receive_buffer_backup)
    send = len(analyzer.pdu_pkts)
   
    
    analyzer.log_info("Total Recieve Package: " + str(total))
    print "Total Recieve Package: " + str(total)
    # analyzer.log_info("Total Send PDCP Package: " + str(send))
    analyzer.log_info("Total Match Package: " + str(analyzer.match))
    print "Total Match Package: " + str(analyzer.match)

    analyzer.log_info("Average wait delay: " + str(analyzer.total_wait_delay/analyzer.match))
    print "Average wait delay: " + str(analyzer.total_wait_delay/analyzer.match)
    analyzer.log_info("Average TX delay: " + str(analyzer.total_tx_delay/analyzer.match))
    print "Average TX delay: " + str(analyzer.total_tx_delay/analyzer.match)
   

    plt.scatter(x3,y3,s=5, color = 'y', label = 'retransmission')
    plt.scatter(x2,y2,s=10, color = 'g',label = 'buffer recieve')
    plt.scatter(x1,y1,s=5, color = 'b', label='pdcp package finish sending')
    plt.scatter(x,y,s=2,color='r', label='pdcp package start sending')
    plt.xlabel('Timestamp')
    plt.ylabel('Package Size')
    plt.title(sys.argv[1])
    plt.legend()
    plt.show()
    

    

kpi_analysis()

