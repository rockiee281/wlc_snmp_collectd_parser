# wlc_snmp_collectd_parser
get cisco wlc metrics via snmp and invoke by collectd


collectd.conf demo:
```bash
FQDNLookup   false
Interval 30

Timeout  15
ReadThreads  30
WriteThreads 10

LoadPlugin logfile
<Plugin logfile>
    LogLevel "debug"
    File "/var/log/collectd.log"
    Timestamp true
    PrintSeverity false
</Plugin>

LoadPlugin python
<Plugin python>
        LogTraces true
        ModulePath "/home/tools/bin/"
        Import "get_wlc_collectd"

        <Module get_wlc_collectd>
                host 10.xx.xx.xx
                community public
                version 2
        </Module>

</Plugin>


LoadPlugin write_graphite
<Plugin write_graphite>
  <Node "graphite">
    Host "10.xx.xx.xx"
    Port "2003"
    Protocol "tcp"
    Prefix "xx."
    EscapeCharacter "."
  </Node>
</Plugin>
```
