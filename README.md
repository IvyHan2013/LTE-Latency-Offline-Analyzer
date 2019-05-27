# LTE Latency Offline Analyzer

## Downlink Analyzer


Analyzer code in: **dl_mac_latency_offline_analyzer.py**

### Usage
```
python offline_downlink.py [logfile name]
```

example:
```
python offline_downlink.py exp72.mi2log
```

### Issues:

#### 1. Using PDSCH to get the first attempt transmitting time:

When we try to use PDSCH to get the first attempt transmitting time, in the current version, we use the *success transmit time* as the key to find the *first attempt transmit time*. The issue is there may be multiple pdu packets success transmitted at same time which could make it difficult to identify. We could consider adding the size of the packet to the key. However there always is a small difference between the total size in PDU data and the block size in the PDSCH data, and the difference is not a fixed value. 

In this version, it will only try to find the *first attempt transmit* time when the SN does not come in sequence, which means that it definitely has been re-transmitte. 
   

#### 2. Lose data record:
    - Possible solution:
        1.    waiting_time: if the waiting time is larger than a threshold, we consider this record is lost. ***problem of this solution:*** it is difficult to determine the threshold, since sometime it will really take a long time to get the expected arriving SN. 



## Uplink Analyzer


Analyzer code in: **ul_rlc_analyzer.py**

### Usage
```
python offline_uplink.py [logfile name]
```

example:
```
python offline_uplink.py exp72.mi2log
```