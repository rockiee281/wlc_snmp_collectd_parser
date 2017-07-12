from easysnmp import Session
import collectd
import re
import json

CONFIGS = []


def config(conf):
  collectd.info('------ config ------')

  for node in conf.children:
    key = node.key.lower()
    val = node.values[0]
    if key == 'host':
      host = val
    elif key == 'community':
      community = val
    elif key == 'version':
      version = int(val)
    else:
      collectd.warning('get_wlc_collectd plugin: Unknown config key: %s' % key)
  CONFIGS.append({
    'host': host,
    'community': community,
    'version': version
  })


def read():
#  collectd.info('------ read ------')
  pattern = re.compile(r'(.*)\.(\d+)')

  for config in CONFIGS:
    #collectd.info('------ read1 ------' + json.dumps(config))
    session = Session(hostname=config['host'], community=config['community'], version=config['version'])
    
    # You may also specify the OID as a tuple (name, index)
    # Note: the index is specified as a string as it can be of other types than
    # just a regular integer
    
    # Perform an SNMP walk
    ap_name_items = session.walk('1.3.6.1.4.1.14179.2.2.1.1.3')
    ap_table = {}
    for ap in ap_name_items:
      ap_table[ap.oid_index] = ap.value
    
    # for 2.4G/5G metrices
    # too many metrics, uncomment this if needed
    #multi_items = (('user_of_ap_items','1.3.6.1.4.1.14179.2.2.13.1.4'), ('rx_util_items', '1.3.6.1.4.1.14179.2.2.13.1.1'), ('tx_util_items','1.3.6.1.4.1.14179.2.2.13.1.2'), ('channel_util_items','1.3.6.1.4.1.14179.2.2.13.1.3'), ('num_of_channel_used_items','1.3.6.1.4.1.14179.2.2.2.1.4'), ('load_of_ap_items','1.3.6.1.4.1.14179.2.2.16.1.1'), ('noise_of_ap_items','1.3.6.1.4.1.14179.2.2.16.1.3'), ('interference_of_ap_items','1.3.6.1.4.1.14179.2.2.16.1.2'), ('coverage_of_ap_items','1.3.6.1.4.1.14179.2.2.16.1.4')) 
    multi_items = (('user_of_ap_items','1.3.6.1.4.1.14179.2.2.13.1.4'), ('rx_util_items', '1.3.6.1.4.1.14179.2.2.13.1.1'), ('tx_util_items','1.3.6.1.4.1.14179.2.2.13.1.2'), ('channel_util_items','1.3.6.1.4.1.14179.2.2.13.1.3'), ('num_of_channel_used_items','1.3.6.1.4.1.14179.2.2.2.1.4'), ('load_of_ap_items','1.3.6.1.4.1.14179.2.2.16.1.1')) 
    
    for target in multi_items:
      result = session.walk(target[1])
      for item in result:
        match = pattern.match(item.oid_index)
        if match:
          oid_index = match.group(1)
          wifi_type = match.group(2)
          ap_name = ap_table[oid_index]
	else:
	  continue
	val = collectd.Values(plugin='get_wlc_collectd')
	val.type = 'gauge'
	val.type_instance = ap_name + "." + wifi_type + "." + item.oid
	val.values = [item.value]
	val.dispatch()
    
    #for single metrics
    single_items = []
    single_items.append(('bsnAPOperationStatus', '1.3.6.1.4.1.14179.2.2.1.1.6'))

    for target in single_items:
      result = session.walk(target[1])
      for item in result:
	val = collectd.Values(plugin='get_wlc_collectd')
	val.type = 'gauge'
	val.type_instance = ap_table[item.oid_index] + "." + item.oid
	val.values = [item.value]
	val.dispatch()

  

    # for per client metrics
    # too many metrics, uncomment this if needed
#    per_client_metrics = ('1.3.6.1.4.1.14179.2.1.6.1.1','1.3.6.1.4.1.14179.2.1.6.1.26')
#    for target in per_client_metrics:
#      result = session.walk(target)
#      for item in result:
#        val = collectd.Values(plugin='get_wlc_collectd')
#	val.type = 'gauge'
#	val.type_instance = item.oid + "." + "_".join(format(int(x),'02x') for x in item.oid_index.split('.'))
#	val.values = [item.value]
#	val.dispatch()


    # client of ap  dict
    client_ap_dict = {}
    for item in session.walk('1.3.6.1.4.1.14179.2.1.4.1.4'):
      common_ap_name = '.'.join(['%d' % ord(_) for _ in item.value])
      if common_ap_name in ap_table:
        client_ap_dict[item.oid_index] = ap_table[common_ap_name]
      else:
        collectd.debug("bad ap_mac:[%s]" % common_ap_name)

    # client of ssid dict
    client_ssid_dict = {}
    for item in session.walk('1.3.6.1.4.1.14179.2.1.4.1.7'):
      client_ssid_dict[item.oid_index] = item.value

    # per client traffic
    traffic_dict = {}
    per_client_trafic = ('1.3.6.1.4.1.14179.2.1.6.1.2', '1.3.6.1.4.1.14179.2.1.6.1.3')
    for target in per_client_trafic:
      result = session.walk(target)

      # aggregate traffice
      for item in result:
        if item.oid_index not in client_ap_dict:
	  collectd.debug("bad oid index %s" % item.oid_index)
	  continue
	# aggregate metrics by ap & mac
	metric_key = item.oid + "." + client_ap_dict[item.oid_index] + "." + '_'.join('%0.2x' % int(x) for x in item.oid_index.split('.'))
	if metric_key in traffic_dict:
	  traffic_dict[metric_key] += long(item.value)
	else:
	  traffic_dict[metric_key] = long(item.value)
	
	# aggregate metrics by ssid
	metric_ssid_key = item.oid + "." + client_ssid_dict[item.oid_index]
	if metric_ssid_key in traffic_dict:
	  traffic_dict[metric_ssid_key] += long(item.value)
	else:
	  traffic_dict[metric_ssid_key] = long(item.value)

    
    #output metrics
    for key in traffic_dict:
      val = collectd.Values(plugin='get_wlc_collectd')
      val.type = "derive"
      val.type_instance = key
      val.values = [traffic_dict[key]]
      val.dispatch()


collectd.register_config(config)
collectd.register_read(read)
