todo: aufräumen
                    anleitung benutzung aus parent readme reinkopieren
                    code aufhübschen



2. daten parsen - 2-LogCore

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
