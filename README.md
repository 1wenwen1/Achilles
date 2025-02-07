# Achilles: Efficient TEE-Assisted BFT Consensus via Rollback Resilient Recovery

This is the accompanying code to the paper "Achilles: Efficient TEE-Assisted BFT Consensus via Rollback Resilient Recovery" which was accepted to EuroSys
2025.
## Current status

The software is under ongoing development.

## Installing

To tests our protocols, we provide a Python script, called
`run.py`. We use the
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


### Default command

We explain the various options our Python scripts provides. You will
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

### Examples

For example, if you run:

`python3 run.py  --local --p1  --faults 1 --payload 256 --batchsize 400`

then you will run the replicas locally, test the Achilles (`--p1`), test for number of faults is 1 (`--faults 1`), payload size is 256 (`--payload 256`), and batchsize is 400 (`--batchsize 400`).



### Ali Clould Service

The Ali Clould experiments are more adhoc. They require starting instance:
  ```
    cd deployment
    bash cloud_deploy.sh
  ```
Then you can check that the servers addresses are listed in `/damysus_updated/servers`.
By default, 7 instances are deployed and 31 servers addresses are generated (5 times for each IP).

If you want to change the number of instances, please modify the "instance_count" in file`config.json`.
Besides, if you want to change the number of servers addresses, please run `python3 /root/damysus_updated/deployment/gen_ip.py {m} {n}` to generate m servers addresses with every IP using n times.


Then, config the SGX environments for all instances:
```
    bash cloud_config.sh
```
Then you can check the process of configuration by runing `tmux a`, and exit the tmux terminal by `exit`.
When the configuration finished, close the tmux terminal by runing:
```
    bash close.sh
```


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

After finished the experiments, use `python3 deployment/delete_instances.py` to terminate all the instances.



