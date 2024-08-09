# Attention!

this is a fork of APTHunter and still needs a lot of work! currently there are my working changes in here and a lot of stubs for readmes etc. those are not complete yet. please be patient and wait for all updates within the next 6 monts







# APTHunter: Detecting Advanced Persistent Threats in Early Stages

## 1-0-Audit

To start system audit and configure audit rules. 

## 1-1-TC-DAS

Configuring Kafka for log consumption. 

## 2-LogCore

For Log parsersing, Normalization and for Causality Tracking. Output from this stage is used to generate the whole system provenance graph. 

## 3-Generate-Graph
To generate the whole system provenance graph based on the normalized log form. 

## 4-Detection-Engine
To run APTHunter's provenance queries on the whole system graph.  









1. daten vorbereiten
    1.1 darpa tc engagement 5
        1.1.1 dataset erlangen, downloaden
        1.1.2 tc daten entpacken und zu json consumen -> convert_data.sh
        todo: abhängigkeit tc5 und dort notwendige schritte dokumentieren
    1.2 auditd
        1.2.1 auditd (und auparse?) installieren
        1.2.2 audit tracing -> 1-0-Audit
2. daten parsen - 2-LogCore
    1.1 darpa tc e5
        1.1.0 cd 2-LogCore/Log Normalizer and Causality Tracker/
        1.1.0 ordner extracted events erstellen (aus irgendwelchen gründen erstellt python den nicht selber)
        1.1.1 python venv erstellen oder dependencies global installieren (todo bash commands einfügen)
        1.1.2 stage locator multi process.py pfade und timestamps anpassen
        1.1.3 stage locator py ausführen python3 stage_locator_multi_process.py
        wichtig: python 11!
    1.2 auditd
        1.2.0 audit-userspace (https://github.com/linux-audit/audit-userspace/tree/master) installieren
            1.2.0.0 download (todo bash commands einfügen)
            1.2.0.1 dependencies installieren (todo bash commands einfügen)
            1.2.0.2 sudo ./autogen.sh
            1.2.0.3 sudo ./configure --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib64 --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info --sbindir=/sbin --libdir=/lib64 --with-python=yes --with-python3=yes --enable-gssapi-krb5=no --with-libcap-ng=yes --without-golang --with-io_uring --with-libwrap --enable-tcp=yes --enable-systemd
            1.2.0.4 sudo make
            1.2.0.5 sudo make install
            1.2.0.6 jetzt sollte das global installiert sein. wichtig: in venv ist das nicht verfügbar!
        1.2.1 parser ausführen
            1.2.1.1 cd 2-LogCore/parser
            1.2.1.2 python3 parser-full.py /path/to/audit/log
3. Graphen
    3.0 Neo4j installieren
        3.0.1 java 11
            3.0.1.1 sudo apt-get update
            3.0.1.2 sudo apt-get install -f openjdk-11-jdk
        3.0.2 neo4j
            3.0.2.1 wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
            3.0.2.2 echo 'deb https://debian.neo4j.com stable 4.1' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
            3.0.2.3 sudo apt-get update
            3.0.2.4 apt list -a neo4j
            3.0.2.5 sudo apt-get install neo4j=1:4.1.1
            3.0.2.6 update-java-alternatives --list
            3.0.2.7 sudo update-java-alternatives --jre --set java-1.11.0-openjdk-amd64
            3.0.2.8 sudo service neo4j start
            3.0.2.9 sudo service neo4j status
            3.0.2.10 browser -> 127.0.0.1:7474 aufrufen
            3.0.2.11 einloggen: neo4j neo4j
            3.0.2.12 ändern auf neo4j neo4jchanged
    3.1 neo4j zurücksetzen
        sudo service neo4j stop
        sudo rm -rf /var/lib/neo4j/data/databases/graph.db
        sudo service neo4j start

        CALL db.indexes()
        DROP Index index_81529c5b
        match (n) detach delete n
        CALL db.indexes()
    3.2 daten einpflegen
        cd 3-Generate-Graph
        import all sh anpassen (pfade zu extracted events ordner)
        sudo bash import_all.sh
        debug: wenn bash meint das script gibt es nicht, mit chmod die ganzen bash scripte ausführbar machen

        CREATE INDEX FOR (r:SYSCALL) ON (r.timestampq)
        :schema
4. detection engine
    4.1 python scripte sichten, pfade für ausgabe anpassen
    4.2 python3 detection_engine.py
