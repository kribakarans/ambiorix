#!/bin/sh

case $1 in
    start|boot)
        export FCGI_SOCKET_DIR=/var/run/http/
        export LIGHTTPD_USER=lighttpd
        export LIGHTTPD_CHROOT=/webui
        export FCGI_SOCKET=amx-fcgi.sock
        mkdir -p $LIGHTTPD_CHROOT$FCGI_SOCKET_DIR
        chown lighttpd $LIGHTTPD_CHROOT$FCGI_SOCKET_DIR
        mkdir -p /tmp/upload && chmod 1777 /tmp/upload
        mkdir -p /tmp/download && chmod 1777 /tmp/download
        amx-fcgi -D
        ;;
    stop)
        if [ -f /var/run/amx-fcgi.pid ]; then
            kill `cat /var/run/amx-fcgi.pid`
        fi
        ;;
    debuginfo)
	echo "TODO debuginfo"
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    log)
	echo "TODO log amx-fcgi"
	;;
    *)
        echo "Usage : $0 [start|boot|stop|debuginfo|log]"
        ;;
esac
