# LTE Latency Offline Analyzer

## Downlink Analyzer

### Issues:

1. Lose data record:
    - Possible solution:
        1.    waiting_time: if the waiting time is larger than a threshold, we consider this record is lost. ***problem of this solution:*** it is difficult to determine the threshold, since sometime it will really take a long time to get the expected arriving SN. 