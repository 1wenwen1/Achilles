# Achilles: Efficient TEE-Assisted BFT Consensus via Rollback Resilient Recovery

This is the accompanying code to the paper "Achilles: Efficient TEE-Assisted BFT Consensus via Rollback Resilient Recovery" which was accepted to EuroSys 2025. A technical report is available [here](https://github.com/1wenwen1/damysus_updated/blob/main/doc/Achilles-%20Efficient%20TEE-Assisted%20BFT%20Consensus%20via%20Rollback%20Resilient%20Recovery.pdf)


## Current status

The software is under ongoing development.

## Description
The main implementation of the project is located in the App and enclave directories. The core consensus logic is implemented in App/Handler.cpp, and the primary functionalities within SGX are implemented in Enclave/EnclaveChComb.cpp. We add a macro named ACHILLES for our protocol in the code, and its corresponding implementation is guarded by the preprocessor condition #if defined(ACHILLES). The extension includes modifications to the trusted components, and reduces the normal-case three-phase operations of Damysus to a two-phase process.

## Installing

We use the
[Salticidae](https://github.com/Determinant/salticidae) library, which
is added here as git submodule.

### Salticidae

If you decide to install Salticidae locally, you will need git and cmake.
In which case, after cloning the repository you need to type this to initialize the
Salticidae git submodule:

`git submodule init`

followed by:

`git submodule update`

Salticidea has the following dependencies:

* CMake >= 3.9
* C++14
* libuv >= 1.10.0
* openssl >= 1.1.0

`sudo apt install cmake libuv1-dev libssl-dev`

Then, to instance Salticidae, type:
`(cd salticidae; cmake . -DCMAKE_INSTALL_PREFIX=.; make; make install)`

### Python

We use python version 3.8.10.  You will need python3-pip to install
the required modules.

The Python script relies on the following modules:
- subprocess
- pathlib
- matplotlib
- time
- math
- os
- glob
- datetime
- argparse
- enum
- json
- multiprocessing
- random
- shutil
- re
- scp
- threading

If you haven't installed those modules yet, run:

`python3 -m pip install subprocess pathlib matplotlib time math os glob datetime argparse enum json multiprocessing random shutil re scp threading`

### SGX 
We use SGX SDK 2.23.

followed by:

`bash deployment/init.sh`




## Experiments

### Default command

To tests our protocols, we provide a Python script, called
`run.py`. We explain the various options our Python scripts provides. You will
run commands of the following form, followed by various options
explained below:

`python3 run.py --local --p1`

### Options

In addition, you can use the following options to change some of the parameters:
- `--pall` is to run all protocols, instead you can use `--p1` up to `--p3`
    - `--p1`: Achilles
    - `--p2`: FlexiBFT
    - `--p3`: Damysus
- `--payload n` to change the payload size to `n`
- `--faults n` to change the number of faults to `n`
- `--batchsize n` to change the batch size to `n`
- `--local` is to run the experiment locally



### Local Experiemnts

Use `--local` to conduct local experiments.

For example, if you run:

`python3 run.py  --local --p1  --faults 1 --payload 256 --batchsize 400`

then you will run the replicas locally, test the Achilles (`--p1`), test for number of faults is 1 (`--faults 1`), payload size is 256 (`--payload 256`), and batchsize is 400 (`--batchsize 400`).

The results will be printed directly to the command line. For example, if you see output:
```
all processes are done
throughput-view: 175.84404966666668 out of 3
latency-view: 15.088674666666668 out of 3
```
this indicates that the experiment executed successfully, with an average throughput of 175.84K TPS and an average latency of 15.08 ms across 3 nodes.


## Ali Clould Experiemnts

### Launch Instances

Starting instances:
  ```
    cd deployment
    bash cloud_deploy.sh
  ```
By default, 7 instances are deployed and 31 servers addresses are generated (5 times for each IP).
If you want to change the number of instances, please modify the "instance_count" in file`config.json`.
Besides, if you want to change the number of servers addresses, please run `python3 /root/damysus_updated/deployment/gen_ip.py {m} {n}` to generate m servers addresses with every IP using n times.


Config the SGX environments for all instances:
```
    bash cloud_config.sh
```
Then you can check the process of configuration by runing `tmux a`, and exit the tmux terminal by `exit`.
When the configuration finished, close the tmux terminal by runing:
```
    bash close.sh
```

### Conduct Experiments:

Then conduct one experiment by run `run.py`:
  ```
    cd ..
    python3 run.py  --p1  --faults 1 --payload 256 --batchsize 400
  ```
For example, if you run:

`python3 run.py  --p1  --faults 1 --payload 256 --batchsize 400`

then you will run the replicas, test the Achilles (`--p1`), test for number of faults is 1 (`--faults 1`), payload size is 256 (`--payload 256`), and batchsize is 400 (`--batchsize 400`).

In case something goes wrong, you can stop all instances as follows:
  ```
    python3 close.py
  ```

If you want to conduct a group of experiments, the scrips in `scripts/` will help.

For example, if you run:
  ```
    cd scripts
    bash batchsize_LAN.sh
  ```
then you will run the replicas, test the  Achilles, FlexiBFT, and Damysus with batchsize varing [200, 400, 600].

### Analysis Results:

All the execution results of Ali Cloud experiments can be found in file damysus_updated/stats.txt.
For example, 
```
Achilles\_1\_\\256\_400\_0, 18.1715414, 26.598315
```
indicates that the throughput and latency for the \sysname protocol, with 1 fault, 400 transactions per block, and a 256 B payload per transaction, are 18.1715414K TPS and 26.598315ms, respectively.


### Shutdown Instances:

After finished the experiments, use `python3 deployment/delete_instances.py` to terminate all the instances.



