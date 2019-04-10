function FindProxyForURL(url, host) {

// VARIABLE SETTINGS
	// VARDEF01 - Web Gateway
	var prxwga = '10.159.30.48:8080';
	var prxwgc = '10.159.30.48:9090';
	
	// VARDEF02 - Captura do endereço IP do usuário
	//var userip = myIpAddress();
	var userip = '200.192.218.230';
	
	// VARDEF03 - Prefix-list de endereços IP autorizados
	var net_prefix_list = new Array(
		"200.192.218.230",
		"200.192.218.231",
		"200.192.218.232",
		"200.192.218.233"
	);
	
	// VARDEF04 - Lista para Bypass de URLs
	var bypass_list = new Array(
		"*sts.arcelormittal.com*",
		"*sts2.arcelormittal.com*"
	);

// POLICIES SETTINGS	
			// POL01 - LOCAL IP BYPASS
					if (isPlainHostName(host) ||
						shExpMatch(host, "*.local") ||
						isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
						isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0") ||
						isInNet(dnsResolve(host), "192.168.0.0",  "255.255.0.0") ||
						isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
					return "DIRECT";
					
			// POL02 - PROTOCOL BYPASS
				if (url.substring(0, 4) == "ftp:")
					{
						return "DIRECT";
					}
		
			// POL01 - URL DIRECT BYPASS
			for(var i=0; i<bypass_list.length; i++) {
				var bypass_list_url = bypass_list[i];
				if ( shExpMatch(url, bypass_list_url)){
				return "DIRECT";
				}
			}

			// Retorna o Proxy caso Liberado na lista
			for(var i=0; i<net_prefix_list.length; i++) {
				var net_prefix_Ip = net_prefix_list[i];
				if ( isInNet(userip,net_prefix_Ip,"255.255.255.255")){
				return "PROXY "+prxwga;
				}
				if ( isPlainHostName(host) ){
				return "PROXY "+prxwga;
				}
			}
				
return "PROXY "+prxwgc;
}