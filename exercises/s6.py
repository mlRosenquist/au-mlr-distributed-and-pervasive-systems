import rssi

interface = 'wlp40s0'
ssids = ['emilie']

rssi_scanner = rssi.RSSI_Scan(interface)
ap_info = rssi_scanner.getAPinfo(networks=ssids, sudo=True)
print(ap_info)