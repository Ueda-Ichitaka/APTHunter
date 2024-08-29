# Attention!

this is a fork of APTHunter and still needs a lot of work! currently there are my working changes in here and a lot of stubs for readmes etc. those are not complete yet. please be patient and wait for all updates within the next 6 monts


# APTHunter: Detecting Advanced Persistent Threats in Early Stages

Original work and [publication](https://dl.acm.org/doi/10.1145/3559768) by Mahmoud et al.
This is a fork of their work intendet to improve and extend it. It is used to evaluate APTHunter on existing datasets and our own infrastructure/dataset as part of my master's thesis. The following will provide a brief overview of APTHunter, more detailled info will be with the respective subdirectories.


## 1-0-Audit

Configuration and execution of auditd as whole-system auditing system.

## 1-1-TC-DAS

Configuring Kafka for log consumption. This is basically a copy of the tools provided by Darpa Transparent Computing Engagement 3 and 5 as well as Raytheon BBN. We did not use this directly, instead we used the tools and installations provided with the datasets itself. Therefore, all utility scrips will reference taht instead of this directory.

## 2-LogCore

For Log parsersing, Normalization and for Causality Tracking. Output from this stage is used to generate the whole system provenance graph. Subfolder `parser` holds everything to process data collected from `1-0-Audit`, while `Log Normalizer and Causality Tracker` serves to process TC E5 data. Does also contain extracted data from Mahmoud et al. and our processing runs.

## 3-Generate-Graph

This folder basically contains the scripts to import data into neo4j. We only use `import_all.sh` which in turn uses `neo4j-load-forward-tracing-csv.sh`.

## 4-Detection-Engine

Hold the detection engine created by Mahmoud et al.



# How to use

This section holds the complete list of tasks to perform.



0. Prerequisites

    Install required packages and setup a Python virtualenv. Important: Use Python3.11 since 3.12 has shown to be incompatible with parts of the codebase. There are requirements files for Debian/Ubuntu packages as well as python pip packages. The apt packages include those required for audit-userspace/auparse which is required to run the auditd event extractor. Tested on Kubuntu 24.04 LTS.

    Overall a folder structure like this might be reasonable:

    ```
    home
    |
    └─── Engagement5
    |    |    convert_data.sh
    |    |
    |    └─── Data
    |    |
    |    └─── Tools
    |
    └─── APTHunter
    |    |    apt-requirements.txt
    |    |    requirements.txt
    |    |
    |    └─── 1-0-Audit
    |    |
    |    └─── 2-LogCore
    |    |
    |    └─── 3-Generate-Graph
    |    |
    |    └─── 4-Detection-Engine
    |         |
    |         └─── results
    |
    └─── audit-userspace
    ```


        ```
        cd APTHunter/
        sudo dpkg --set-selections < apt-requirements.txt
        cd ..

        git clone https://github.com/linux-audit/audit-userspace.git
        cd audit-userspace/
        sudo ./autogen.sh
        sudo ./configure --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib64 --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info --sbindir=/sbin --libdir=/lib64 --with-python=yes --with-python3=yes --enable-gssapi-krb5=no --with-libcap-ng=yes --without-golang --with-io_uring --with-libwrap --enable-tcp=yes --enable-systemd
        sudo make
        sudo make install
        cd ..

        cd APTHunter/
        python3 -m pip install virtualenv
        python3 -m venv apthunter
        source apthunter/bin/activate
        python3 -m pip install -r requirements.txt
        ```

1. Gather Data

    APTHunter is able to use data from Darpa Transparent Computing Engagement 5 (and 3 if the parser is modified to CDM18) or/and raw auditd data

    1. Darpa TC Engagement 5

        - [ ] Download all required data from [Github](https://github.com/darpa-i2o/Transparent-Computing) and [Googledrive](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
        - [ ] Unzip and convert data to json -> `convert_data.sh` from [https://github.com/Ueda-Ichitaka/Darpa-TC-E5](https://github.com/Ueda-Ichitaka/Darpa-TC-E5). Remember to modify all variables and paths to accordingly to your system!

    2. auditd - 1-0-Audit

        - [ ] Install auditd
        - [ ] Configure auditing rules (or just record everything)
        - [ ] Start auditing
        - [ ] Perform your attacks
        - [ ] Stop auditing

2. Parse data - 2-LogCore


    1. Darpa TC E5 - Log Normalizer and Causality Tracker

       Use Python3.11 for the venv. Also, use the venv for all stages and variants, so it might be reasonable to create it on the parent dir

        ```
        cd 2-LogCore/Log Normalizer and Causality Tracker/
        mkdir extracted_events
        ```

       - [ ] Modify path variables in `stage_locator_multi_process.py`
       - [ ] execute `python3 stage_locator_multi_process.py`

    2. auditd

        1. Install audit-userspace [https://github.com/linux-audit/audit-userspace/tree/master](https://github.com/linux-audit/audit-userspace/tree/master)

        2. Execute parser

            ```
            cd 2-LogCore/parser
            python3 parser-full.py /path/to/audit/log
            ```

3. Graphs - 3-Generate-Graph

    1. Install Neo4j

        1. Java 11

            ```
            sudo apt-get update
            sudo apt-get install -f openjdk-11-jdk
            ```

        2. neo4j

            ```
            wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
            echo 'deb https://debian.neo4j.com stable 4.1' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
            sudo apt-get update
            apt list -a neo4j
            sudo apt-get install neo4j=1:4.1.1
            update-java-alternatives --list
            sudo update-java-alternatives --jre --set java-1.11.0-openjdk-amd64
            sudo service neo4j start
            sudo service neo4j status
            ```
            - [ ] Browse to 127.0.0.1:7474
            - [ ] Login with neo4j neo4j
            - [ ] Change the credentials to neo4j neo4jchanged

    2. Reset neo4j

        To reset the database, for example to import new data. Execute the following in a shell

        ```
        sudo service neo4j stop
        sudo rm -rf /var/lib/neo4j/data/databases/graph.db
        sudo service neo4j start
        ```

        If you previously had data in neo4j you will have to purge it before importing new data. It is not strictly necessary to re-create the index since the queries in APTHunters detection engine ignore them.

        ```
        CALL db.indexes()
        DROP Index index_81529c5b
        match (n) detach delete n
        CALL db.indexes()
        ```

    3. Import data into neo4j

        APTHunter only populates the forward.csv files in its LogCore stage. Therefore we utilize the neo4j-load-forward-tracing-csv.sh in our wrapper script which visits each subfolder in our extracted_events folder from stage 2. Modify the path variables accordingly to your system before execution.

        ```
        cd 3-Generate-Graph
        sudo bash import_all.sh
        ```

        ```
        CREATE INDEX FOR (r:SYSCALL) ON (r.timestampq)
        :schema
        MATCH p=(n1)-[r]->(n2) RETURN p limit 1000
        ```

4. Detection engine

    This is the heart of APTHunter which implements the grammars presented in the paper as neo4j                                                                                        queries. Modify the output directory and execute it with `python3 detection_engine.py` or `python3 detection_engine_DARPA.py`

    There are some queries, that try to wildcard all binaries e.g. in the /bin/ directory. However, at least the TC-E5 dataset does not contain the full path of these binaries which means, these cyphers will not match datapoints which should be matched. The full list of binaries in these directories sum up to approx. 4k binaires, which are way too many, therefore there is a solution to this. We compiled lists of these binaries (the bins*.txt files in 2 LogCore) and a small bash script `get_bins.sh` which combs the dataset for occurances of these binaries and prints them to stdout for easy copy-paste to the query. If you need to re-do these lists:
    ```
    ls /sbin/ > bins.txt
    ls /bin/ >> bins.txt
    ls /usr/bin/ >> bins.txt
    ls /usr/local/ >> bins.txt
    ls /usr/sbin/ >> bins.txt

    ls /usr/bin/ >> bins_foothold.txt

    cat bins.txt | sort | uniq > APTHunter/2-LogCore/Log Normalizer and Causality Tracker/bins.txt
    cat bins_foothold.txt | sort | uniq > APTHunter/2-LogCore/Log Normalizer and Causality Tracker/bins_foothold.txt
    ```


