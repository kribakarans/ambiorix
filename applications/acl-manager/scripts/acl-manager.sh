#!/bin/sh

case $1 in
    start|boot)
        acl-manager -D
        ;;
    stop)
        if [ -f /var/run/acl-manager.pid ]; then
            kill `cat /var/run/acl-manager.pid`
        fi
        ;;
    debuginfo)
        ubus-cli "ACLManager.?"
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    log)
        echo "TODO log acl-manager"
        ;;
    *)
        echo "Usage : $0 [start|boot|stop|debuginfo|log]"
        ;;
esac
