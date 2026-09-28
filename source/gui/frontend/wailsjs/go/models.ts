export namespace models {
	
	export class PaidProviderEntry {
	    id: string;
	    name: string;
	    type: string;
	    url?: string;
	    username?: string;
	    password?: string;
	    token?: string;
	    subscription_url?: string;
	    enabled: boolean;
	    insecure_tls?: boolean;
	    last_fetched?: number;
	
	    static createFrom(source: any = {}) {
	        return new PaidProviderEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.url = source["url"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.token = source["token"];
	        this.subscription_url = source["subscription_url"];
	        this.enabled = source["enabled"];
	        this.insecure_tls = source["insecure_tls"];
	        this.last_fetched = source["last_fetched"];
	    }
	}
	export class SourceConfig {
	    id: string;
	    name: string;
	    url: string;
	    type: string;
	    enabled: boolean;
	    auto_update: boolean;
	    update_interval_hours: number;
	
	    static createFrom(source: any = {}) {
	        return new SourceConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.url = source["url"];
	        this.type = source["type"];
	        this.enabled = source["enabled"];
	        this.auto_update = source["auto_update"];
	        this.update_interval_hours = source["update_interval_hours"];
	    }
	}
	export class AppConfig {
	    auto_connect: boolean;
	    check_interval_sec: number;
	    max_latency_ms: number;
	    enable_chain: boolean;
	    enable_kill_switch: boolean;
	    dns_over_tls: string;
	    bypass_list: string[];
	    force_list: string[];
	    disallowed_apps?: string[];
	    sources: SourceConfig[];
	    singbox_path: string;
	    listen_port: number;
	    webui_port: number;
	    setup_done: boolean;
	    user_country: string;
	    mode: string;
	    safety_filter: boolean;
	    switch_only_on_fail: boolean;
	    min_uptime_sec: number;
	    node_auto_switch_enabled: boolean;
	    cyclic_node_search: boolean;
	    node_race_enabled: boolean;
	    notify_on_switch: boolean;
	    notify_on_fail: boolean;
	    block_ipv6_leak: boolean;
	    block_webrtc: boolean;
	    encrypt_storage: boolean;
	    emergency_hotkey: string;
	    dns_leak_test_interval: number;
	    traffic_padding_enabled: boolean;
	    traffic_padding_aggressive: boolean;
	    cdn_worker_domain: string;
	    shadowtls_enabled: boolean;
	    shadowtls_sni: string;
	    shadowtls_password: string;
	    multihop_enabled: boolean;
	    multihop_count: number;
	    sticky_session_policy: string;
	    adblock_profile: string;
	    connection_mode: string;
	    set_system_proxy: boolean;
	    selection_mode: string;
	    paid_providers?: PaidProviderEntry[];
	    anti_block_enabled: boolean;
	    anti_block_residential_only: boolean;
	    anti_block_auto_switch: boolean;
	    anti_block_api_key?: string;
	    relay_server_addr?: string;
	    relay_server_fingerprint?: string;
	    max_connected_clients?: number;
	    server_role_wizard_completed?: boolean;
	    last_active_node_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new AppConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.auto_connect = source["auto_connect"];
	        this.check_interval_sec = source["check_interval_sec"];
	        this.max_latency_ms = source["max_latency_ms"];
	        this.enable_chain = source["enable_chain"];
	        this.enable_kill_switch = source["enable_kill_switch"];
	        this.dns_over_tls = source["dns_over_tls"];
	        this.bypass_list = source["bypass_list"];
	        this.force_list = source["force_list"];
	        this.disallowed_apps = source["disallowed_apps"];
	        this.sources = this.convertValues(source["sources"], SourceConfig);
	        this.singbox_path = source["singbox_path"];
	        this.listen_port = source["listen_port"];
	        this.webui_port = source["webui_port"];
	        this.setup_done = source["setup_done"];
	        this.user_country = source["user_country"];
	        this.mode = source["mode"];
	        this.safety_filter = source["safety_filter"];
	        this.switch_only_on_fail = source["switch_only_on_fail"];
	        this.min_uptime_sec = source["min_uptime_sec"];
	        this.node_auto_switch_enabled = source["node_auto_switch_enabled"];
	        this.cyclic_node_search = source["cyclic_node_search"];
	        this.node_race_enabled = source["node_race_enabled"];
	        this.notify_on_switch = source["notify_on_switch"];
	        this.notify_on_fail = source["notify_on_fail"];
	        this.block_ipv6_leak = source["block_ipv6_leak"];
	        this.block_webrtc = source["block_webrtc"];
	        this.encrypt_storage = source["encrypt_storage"];
	        this.emergency_hotkey = source["emergency_hotkey"];
	        this.dns_leak_test_interval = source["dns_leak_test_interval"];
	        this.traffic_padding_enabled = source["traffic_padding_enabled"];
	        this.traffic_padding_aggressive = source["traffic_padding_aggressive"];
	        this.cdn_worker_domain = source["cdn_worker_domain"];
	        this.shadowtls_enabled = source["shadowtls_enabled"];
	        this.shadowtls_sni = source["shadowtls_sni"];
	        this.shadowtls_password = source["shadowtls_password"];
	        this.multihop_enabled = source["multihop_enabled"];
	        this.multihop_count = source["multihop_count"];
	        this.sticky_session_policy = source["sticky_session_policy"];
	        this.adblock_profile = source["adblock_profile"];
	        this.connection_mode = source["connection_mode"];
	        this.set_system_proxy = source["set_system_proxy"];
	        this.selection_mode = source["selection_mode"];
	        this.paid_providers = this.convertValues(source["paid_providers"], PaidProviderEntry);
	        this.anti_block_enabled = source["anti_block_enabled"];
	        this.anti_block_residential_only = source["anti_block_residential_only"];
	        this.anti_block_auto_switch = source["anti_block_auto_switch"];
	        this.anti_block_api_key = source["anti_block_api_key"];
	        this.relay_server_addr = source["relay_server_addr"];
	        this.relay_server_fingerprint = source["relay_server_fingerprint"];
	        this.max_connected_clients = source["max_connected_clients"];
	        this.server_role_wizard_completed = source["server_role_wizard_completed"];
	        this.last_active_node_id = source["last_active_node_id"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TransportConfig {
	    type: string;
	    path?: string;
	    host?: string;
	
	    static createFrom(source: any = {}) {
	        return new TransportConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.path = source["path"];
	        this.host = source["host"];
	    }
	}
	export class RealityConfig {
	    public_key: string;
	    short_id: string;
	
	    static createFrom(source: any = {}) {
	        return new RealityConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.public_key = source["public_key"];
	        this.short_id = source["short_id"];
	    }
	}
	export class TLSConfig {
	    enabled: boolean;
	    server_name?: string;
	    reality?: RealityConfig;
	    insecure?: boolean;
	    fingerprint?: string;
	
	    static createFrom(source: any = {}) {
	        return new TLSConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.server_name = source["server_name"];
	        this.reality = this.convertValues(source["reality"], RealityConfig);
	        this.insecure = source["insecure"];
	        this.fingerprint = source["fingerprint"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Node {
	    id: string;
	    name: string;
	    protocol: string;
	    address: string;
	    port: number;
	    uuid?: string;
	    password?: string;
	    method?: string;
	    flow?: string;
	    alt_id?: number;
	    wg_private_key?: string;
	    wg_public_key?: string;
	    wg_local_address?: string;
	    wg_reserved?: number[];
	    awg_jc?: number;
	    awg_jmin?: number;
	    awg_jmax?: number;
	    tls?: TLSConfig;
	    transport?: TransportConfig;
	    latency_ms: number;
	    jitter_ms: number;
	    loss_percent: number;
	    speed_mbps: number;
	    score: number;
	    status: string;
	    // Go type: time
	    last_checked: any;
	    fail_count: number;
	    success_count: number;
	    // Go type: time
	    blacklisted_until?: any;
	    source: string;
	    // Go type: time
	    added_at: any;
	    extra_params?: Record<string, string>;
	    is_chain_partner?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.protocol = source["protocol"];
	        this.address = source["address"];
	        this.port = source["port"];
	        this.uuid = source["uuid"];
	        this.password = source["password"];
	        this.method = source["method"];
	        this.flow = source["flow"];
	        this.alt_id = source["alt_id"];
	        this.wg_private_key = source["wg_private_key"];
	        this.wg_public_key = source["wg_public_key"];
	        this.wg_local_address = source["wg_local_address"];
	        this.wg_reserved = source["wg_reserved"];
	        this.awg_jc = source["awg_jc"];
	        this.awg_jmin = source["awg_jmin"];
	        this.awg_jmax = source["awg_jmax"];
	        this.tls = this.convertValues(source["tls"], TLSConfig);
	        this.transport = this.convertValues(source["transport"], TransportConfig);
	        this.latency_ms = source["latency_ms"];
	        this.jitter_ms = source["jitter_ms"];
	        this.loss_percent = source["loss_percent"];
	        this.speed_mbps = source["speed_mbps"];
	        this.score = source["score"];
	        this.status = source["status"];
	        this.last_checked = this.convertValues(source["last_checked"], null);
	        this.fail_count = source["fail_count"];
	        this.success_count = source["success_count"];
	        this.blacklisted_until = this.convertValues(source["blacklisted_until"], null);
	        this.source = source["source"];
	        this.added_at = this.convertValues(source["added_at"], null);
	        this.extra_params = source["extra_params"];
	        this.is_chain_partner = source["is_chain_partner"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Chain {
	    nodes: Node[];
	    score: number;
	
	    static createFrom(source: any = {}) {
	        return new Chain(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodes = this.convertValues(source["nodes"], Node);
	        this.score = source["score"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConnectionState {
	    connected: boolean;
	    verified: boolean;
	    active_node?: Node;
	    active_chain?: Chain;
	    mode: string;
	    // Go type: time
	    since?: any;
	    bytes_sent: number;
	    bytes_recv: number;
	    ipv6_blocked: boolean;
	    webrtc_blocked: boolean;
	    pinned_node_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connected = source["connected"];
	        this.verified = source["verified"];
	        this.active_node = this.convertValues(source["active_node"], Node);
	        this.active_chain = this.convertValues(source["active_chain"], Chain);
	        this.mode = source["mode"];
	        this.since = this.convertValues(source["since"], null);
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_recv = source["bytes_recv"];
	        this.ipv6_blocked = source["ipv6_blocked"];
	        this.webrtc_blocked = source["webrtc_blocked"];
	        this.pinned_node_id = source["pinned_node_id"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	

}

export namespace singbox {
	
	export class LocalIPCandidate {
	    ip: string;
	    interface_name: string;
	
	    static createFrom(source: any = {}) {
	        return new LocalIPCandidate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.interface_name = source["interface_name"];
	    }
	}

}

export namespace web {
	
	export class DomainRouteResult {
	    domain: string;
	    outbound: string;
	    direct: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DomainRouteResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.outbound = source["outbound"];
	        this.direct = source["direct"];
	    }
	}

}

