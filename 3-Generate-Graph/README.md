todo:
                neo4j readme markieren als vom originalen projekt
                anleitung aus parent readme reinkopieren
                code dokumentieren, was macht was




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
