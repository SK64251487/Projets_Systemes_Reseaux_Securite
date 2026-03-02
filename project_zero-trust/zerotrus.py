#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero Trust SDN Controller with Dynamic Access Revocation
Implements authentication, dynamic segmentation, threat detection, and automatic revocation

DETECTIONS:
1. Port Scanning
2. Data Exfiltration (via flow stats)
3. ICMP Flood Attack 
4. Network Segmentation Violations
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib import hub
import json
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque

class ZeroTrustController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ZeroTrustController, self).__init__(*args, **kwargs)
        
        # Datapath registry
        self.datapaths = {}
        
        # MAC to port mapping
        self.mac_to_port = {}
        
        # Authentication and trust management
        self.auth_table = {}  # {ip: {authenticated, auth_time, trust_score, last_seen}}
        self.trust_scores = {}  # {ip: score}
        self.blocked_hosts = set()
        
        # Flow monitoring
        self.flow_stats_by_ip = defaultdict(lambda: {
            'total_bytes': 0,
            'total_packets': 0,
            'start_time': time.time(),
            'last_check': time.time()
        })
        
        # Threat detection trackers
        self.port_scan_tracker = defaultdict(lambda: {
            'scanned_ports': deque(maxlen=20),
            'timestamps': deque(maxlen=20),
            'last_reset': time.time()
        })
        
        self.data_exfil_tracker = defaultdict(lambda: {
            'bytes_sent': 0,
            'packets_sent': 0,
            'start_time': time.time(),
            'last_bytes': 0,
            'connections': []
        })
        
        # ICMP Flood detection tracker avec deque pour fenêtre glissante
        self.icmp_flood_tracker = defaultdict(lambda: {
            'timestamps': deque(maxlen=150),  # Garde les 150 derniers timestamps
            'packet_count': 0,
            'last_log': time.time()
        })
        
        # Connection tracking
        self.connection_tracker = defaultdict(lambda: defaultdict(int))
        
        # Network topology configuration
        self.REMEDIATION_SERVER = '10.0.0.20'
        self.WEB_SERVER = '10.0.0.10'
        self.CLIENT_HOSTS = ['10.0.0.1', '10.0.0.2']
        
        # Network segmentation
        self.network_segments = {
            'clients': ['10.0.0.1', '10.0.0.2'],
            'web_server': ['10.0.0.10'],
            'isolated': ['10.0.0.20']
        }
        
        # Segment-based policies
        self.segment_policies = {
            'clients': {
                'allowed_protocols': ['TCP', 'UDP', 'ICMP'],
                'max_connections': 100,
                'bandwidth_limit': 100000000,
                'can_communicate_with': ['clients', 'web_server']
            },
            'web_server': {
                'allowed_protocols': ['TCP', 'UDP', 'ICMP'],
                'max_connections': 200,
                'bandwidth_limit': 1000000000,
                'can_communicate_with': ['clients', 'web_server']
            },
            'isolated': {
                'allowed_protocols': [],
                'max_connections': 0,
                'bandwidth_limit': 0,
                'can_communicate_with': []
            }
        }
        
        # Detection thresholds
        self.PORT_SCAN_THRESHOLD = 5
        self.PORT_SCAN_WINDOW = 10
        self.EXFIL_BYTE_THRESHOLD = 1000000
        self.EXFIL_TIME_WINDOW = 10
        
        # ICMP Flood thresholds - plus sensibles et réalistes
        self.ICMP_FLOOD_THRESHOLD = 50   # 50 paquets ICMP
        self.ICMP_FLOOD_WINDOW = 2.0     # en 2 secondes (fenêtre glissante)
        
        # Metrics collection
        self.metrics = {
            'total_authentications': 0,
            'total_revocations': 0,
            'port_scan_detections': 0,
            'exfil_detections': 0,
            'icmp_flood_detections': 0,
            'isolation_blocks': 0,
            'revocation_times': [],
            'detection_times': [],
            'icmp_packets_seen': 0  # compteur total ICMP
        }
        
        # Start monitoring threads
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.stats_thread = hub.spawn(self._request_stats_loop)
        
        self.logger.info("=" * 70)
        self.logger.info("Zero Trust SDN Controller")
        self.logger.info("=" * 70)
        self.logger.info(f"Topology: Clients={self.CLIENT_HOSTS}, Web={self.WEB_SERVER}, Remediation(ISOLATED)={self.REMEDIATION_SERVER}")
        self.logger.info("DETECTIONS ACTIVES:")
        self.logger.info("  [1] Port Scanning Detection")
        self.logger.info("  [2] Data Exfiltration Detection (flow stats)")
        self.logger.info(f"  [3] ICMP Flood Attack Detection - Threshold: {self.ICMP_FLOOD_THRESHOLD} packets in {self.ICMP_FLOOD_WINDOW}s")
        self.logger.info("  [4] Network Segmentation Enforcement")
        self.logger.info("=" * 70)
        
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Track datapath connections"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f'Register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f'Unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install default flow"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Install ISOLATION rules for remediation server
        self._install_isolation_rules(datapath)
        
        self.logger.info(f"Switch {datapath.id} connected - default flow and isolation rules installed")
        
    def _install_isolation_rules(self, datapath):
        """Install strict isolation rules for remediation server"""
        parser = datapath.ofproto_parser
        
        # Block all traffic TO remediation server
        match_to_remediation = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=self.REMEDIATION_SERVER
        )
        self.add_flow(datapath, 1000, match_to_remediation, [])
        
        # Block all traffic FROM remediation server
        match_from_remediation = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=self.REMEDIATION_SERVER
        )
        self.add_flow(datapath, 1000, match_from_remediation, [])
        
        self.logger.info(f"ISOLATION RULES INSTALLED: {self.REMEDIATION_SERVER} is completely isolated")
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add a flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match, 
                                   instructions=inst,
                                   idle_timeout=idle_timeout,
                                   hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst,
                                   idle_timeout=idle_timeout,
                                   hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        
    def delete_flow(self, datapath, match):
        """Delete flows matching the given match"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        mod = parser.OFPFlowMod(datapath=datapath,
                               command=ofproto.OFPFC_DELETE,
                               out_port=ofproto.OFPP_ANY,
                               out_group=ofproto.OFPG_ANY,
                               match=match)
        datapath.send_msg(mod)
        
    def authenticate_host(self, src_ip):
        """Authenticate host and assign initial trust score"""
        current_time = time.time()
        
        if src_ip not in self.auth_table:
            segment = self.get_segment_for_ip(src_ip)
            
            if segment == 'web_server':
                initial_trust = 100
            elif segment == 'clients':
                initial_trust = 80
            else:
                initial_trust = 0
            
            self.auth_table[src_ip] = {
                'authenticated': True if segment != 'isolated' else False,
                'auth_time': current_time,
                'trust_score': initial_trust,
                'last_seen': current_time,
                'segment': segment
            }
            self.trust_scores[src_ip] = initial_trust
            self.metrics['total_authentications'] += 1
            
            self.logger.info(f"✓ Host {src_ip} authenticated - Segment: {segment}, Trust: {initial_trust}")
            return True if segment != 'isolated' else False
        else:
            self.auth_table[src_ip]['last_seen'] = current_time
            return self.auth_table[src_ip]['authenticated']
            
    def get_segment_for_ip(self, ip):
        """Get network segment for IP address"""
        for segment, ips in self.network_segments.items():
            if ip in ips:
                return segment
        return 'unknown'
        
    def is_communication_allowed(self, src_ip, dst_ip):
        """Check if communication between src and dst is allowed"""
        if src_ip == self.REMEDIATION_SERVER or dst_ip == self.REMEDIATION_SERVER:
            self.metrics['isolation_blocks'] += 1
            self.logger.warning(f"ISOLATION BLOCK: {self.REMEDIATION_SERVER} access denied")
            return False
        
        src_segment = self.get_segment_for_ip(src_ip)
        dst_segment = self.get_segment_for_ip(dst_ip)
        
        if src_segment == 'unknown' or dst_segment == 'unknown':
            self.logger.warning(f"Unknown segment: {src_ip} ({src_segment}) -> {dst_ip} ({dst_segment})")
            return False
        
        src_policy = self.segment_policies.get(src_segment, {})
        allowed_segments = src_policy.get('can_communicate_with', [])
        
        if dst_segment in allowed_segments:
            return True
        
        self.logger.debug(f"Communication blocked: {src_ip} ({src_segment}) -> {dst_ip} ({dst_segment})")
        return False
        
    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect port scanning behavior"""
        detection_start = time.time()
        current_time = time.time()
        tracker = self.port_scan_tracker[src_ip]
        
        if current_time - tracker['last_reset'] > self.PORT_SCAN_WINDOW:
            tracker['scanned_ports'].clear()
            tracker['timestamps'].clear()
            tracker['last_reset'] = current_time
            
        tracker['scanned_ports'].append(dst_port)
        tracker['timestamps'].append(current_time)
        
        unique_ports = len(set(tracker['scanned_ports']))
        
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            detection_time = time.time() - detection_start
            self.metrics['detection_times'].append(detection_time)
            self.metrics['port_scan_detections'] += 1
            
            self.logger.warning(f"PORT SCAN DETECTED: {src_ip} scanned {unique_ports} ports to {dst_ip}")
            return True
            
        return False
    
    def detect_icmp_flood(self, src_ip):
        """
        Détection d'attaque ICMP Flood avec fenêtre glissante
        Détecte si un hôte envoie trop de paquets ICMP en peu de temps
        """
        detection_start = time.time()
        current_time = time.time()
        tracker = self.icmp_flood_tracker[src_ip]
        
        # Ajouter le timestamp actuel
        tracker['timestamps'].append(current_time)
        tracker['packet_count'] += 1
        
        # Incrémenter le compteur global
        self.metrics['icmp_packets_seen'] += 1
        
        # Nettoyer les timestamps trop anciens (fenêtre glissante)
        cutoff_time = current_time - self.ICMP_FLOOD_WINDOW
        
        # Compter les paquets dans la fenêtre
        recent_packets = sum(1 for ts in tracker['timestamps'] if ts >= cutoff_time)
        
        # Log périodique pour debug (tous les 10 paquets)
        if tracker['packet_count'] % 10 == 0:
            elapsed = current_time - tracker['timestamps'][0] if tracker['timestamps'] else 0
            rate = recent_packets / self.ICMP_FLOOD_WINDOW if self.ICMP_FLOOD_WINDOW > 0 else 0
            
            self.logger.info(
                f"ICMP Monitor: {src_ip} | "
                f"Recent: {recent_packets}/{self.ICMP_FLOOD_THRESHOLD} packets in {self.ICMP_FLOOD_WINDOW}s | "
                f"Total: {tracker['packet_count']} | "
                f"Rate: {rate:.1f} pkt/s"
            )
        
        # Vérifier le seuil
        if recent_packets >= self.ICMP_FLOOD_THRESHOLD:
            detection_time = time.time() - detection_start
            self.metrics['detection_times'].append(detection_time)
            self.metrics['icmp_flood_detections'] += 1
            
            # Calculer le taux réel
            actual_window = current_time - tracker['timestamps'][0] if tracker['timestamps'] else self.ICMP_FLOOD_WINDOW
            rate = recent_packets / actual_window if actual_window > 0 else 0
            
            self.logger.critical(
                f"ICMP FLOOD DETECTED\n"
                f"    Source IP      : {src_ip}\n"
                f"    Packets        : {recent_packets} in {self.ICMP_FLOOD_WINDOW}s\n"
                f"    Threshold      : {self.ICMP_FLOOD_THRESHOLD} packets\n"
                f"    Rate           : {rate:.1f} packets/second\n"
                f"    Total ICMP     : {tracker['packet_count']}\n"
                f"    Detection Time : {detection_time*1000:.2f}ms"
            )
            return True
        
        return False
        
    def detect_data_exfiltration_from_stats(self, src_ip, total_bytes):
        """Détection d'exfiltration basée sur les statistiques de flows"""
        detection_start = time.time()
        tracker = self.data_exfil_tracker[src_ip]
        current_time = time.time()
        
        bytes_delta = total_bytes - tracker['last_bytes']
        tracker['last_bytes'] = total_bytes
        tracker['bytes_sent'] += bytes_delta
        tracker['packets_sent'] += 1
        
        elapsed = current_time - tracker['start_time']
        
        if elapsed >= self.EXFIL_TIME_WINDOW:
            bytes_per_second = tracker['bytes_sent'] / elapsed
            
            if tracker['bytes_sent'] > 100000:
                self.logger.debug(
                    f"Exfil check for {src_ip}: {tracker['bytes_sent']} bytes "
                    f"in {elapsed:.2f}s ({bytes_per_second:.2f} B/s)"
                )
            
            if tracker['bytes_sent'] > self.EXFIL_BYTE_THRESHOLD:
                detection_time = time.time() - detection_start
                self.metrics['detection_times'].append(detection_time)
                self.metrics['exfil_detections'] += 1
                
                self.logger.warning(
                    f"DATA EXFILTRATION DETECTED: {src_ip} sent {tracker['bytes_sent']} bytes "
                    f"in {elapsed:.2f}s ({bytes_per_second:.2f} B/s)"
                )
                return True
                
            tracker['bytes_sent'] = 0
            tracker['packets_sent'] = 0
            tracker['start_time'] = current_time
            
        return False
        
    def revoke_access(self, datapath, src_ip, reason="suspicious activity"):
        """Dynamically revoke access for a host"""
        revocation_start = time.time()
        
        # Vérifier si déjà bloqué pour éviter les doublons
        if src_ip in self.blocked_hosts:
            self.logger.warning(f"{src_ip} already blocked, skipping revocation")
            return
        
        self.blocked_hosts.add(src_ip)
        
        if src_ip in self.auth_table:
            self.auth_table[src_ip]['authenticated'] = False
            self.auth_table[src_ip]['trust_score'] = 0
            
        parser = datapath.ofproto_parser
        
        # Supprimer les flows existants
        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.delete_flow(datapath, match_src)
        
        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
        self.delete_flow(datapath, match_dst)
        
        # Ajouter une règle de blocage stricte (DROP)
        match_drop = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.add_flow(datapath, 1000, match_drop, [], idle_timeout=0, hard_timeout=600)
        
        revocation_time = time.time() - revocation_start
        self.metrics['revocation_times'].append(revocation_time)
        self.metrics['total_revocations'] += 1
        
        self.logger.critical(
            f"ACCESS REVOKED\n"
            f"    IP             : {src_ip}\n"
            f"    Reason         : {reason}\n"
            f"    Revocation Time: {revocation_time*1000:.2f}ms\n"
            f"    Total Blocked  : {len(self.blocked_hosts)}"
        )
        
    def check_segment_policy(self, src_ip, protocol):
        """Check if traffic is allowed based on segment policy"""
        segment = self.get_segment_for_ip(src_ip)
        
        if segment == 'isolated':
            return False
            
        policy = self.segment_policies.get(segment, {'allowed_protocols': []})
        return protocol in policy.get('allowed_protocols', [])
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Vérifier si l'hôte est déjà bloqué AVANT toute autre vérification
            if src_ip in self.blocked_hosts:
                self.logger.debug(f"Dropped packet from blocked host {src_ip}")
                return
            
            if not self.is_communication_allowed(src_ip, dst_ip):
                return
                
            if not self.authenticate_host(src_ip):
                self.logger.warning(f"Authentication failed for {src_ip}")
                self.revoke_access(datapath, src_ip, "authentication failure")
                return
                
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            
            protocol = None
            dst_port = None
            
            if tcp_pkt:
                protocol = 'TCP'
                dst_port = tcp_pkt.dst_port
                
                if self.detect_port_scan(src_ip, dst_ip, dst_port):
                    self.revoke_access(datapath, src_ip, "port scanning detected")
                    return
                    
            elif udp_pkt:
                protocol = 'UDP'
                dst_port = udp_pkt.dst_port
                
            elif icmp_pkt:
                protocol = 'ICMP'
                
                #Détection ICMP Flood - APPELÉE POUR CHAQUE PAQUET ICMP
                if self.detect_icmp_flood(src_ip):
                    self.revoke_access(datapath, src_ip, "ICMP flood attack detected")
                    return
                
            if protocol and not self.check_segment_policy(src_ip, protocol):
                self.logger.warning(f"Protocol {protocol} not allowed for {src_ip}")
                return
                
        actions = [parser.OFPActionOutput(out_port)]
        
        #Ne pas installer de flow pour ICMP si on surveille le flood
        if out_port != ofproto.OFPP_FLOOD and ip_pkt:
            # Pour ICMP, on n'installe pas de flow pour forcer chaque paquet à passer par le contrôleur
            if not icmp_pkt:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src,
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
                self.add_flow(datapath, 10, match, actions, idle_timeout=15, hard_timeout=30)
            
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _request_stats_loop(self):
        """Request flow statistics periodically"""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)
    
    def _request_stats(self, datapath):
        """Send flow stats request to switch"""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        body = ev.msg.body
        datapath = ev.msg.datapath
        
        ip_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        
        for stat in body:
            if 'ipv4_src' in stat.match:
                src_ip = stat.match['ipv4_src']
                ip_stats[src_ip]['bytes'] += stat.byte_count
                ip_stats[src_ip]['packets'] += stat.packet_count
        
        for src_ip, stats in ip_stats.items():
            if src_ip in self.blocked_hosts:
                continue
            
            if src_ip in [self.REMEDIATION_SERVER]:
                continue
            
            if self.detect_data_exfiltration_from_stats(src_ip, stats['bytes']):
                self.logger.critical(f"EXFILTRATION via flow stats: {src_ip}")
                self.revoke_access(datapath, src_ip, "data exfiltration detected (flow stats)")
        
    def _monitor_loop(self):
        """Background monitoring loop"""
        while True:
            hub.sleep(30)
            self._cleanup_stale_entries()
            self._log_metrics()
            
    def _cleanup_stale_entries(self):
        """Remove stale authentication entries"""
        current_time = time.time()
        stale_threshold = 300
        
        stale_hosts = []
        for ip, info in self.auth_table.items():
            if current_time - info['last_seen'] > stale_threshold:
                stale_hosts.append(ip)
                
        for ip in stale_hosts:
            del self.auth_table[ip]
            if ip in self.trust_scores:
                del self.trust_scores[ip]
            self.logger.info(f"Removed stale entry for {ip}")
            
    def _log_metrics(self):
        """Log current metrics"""
        self.logger.info("=" * 70)
        self.logger.info("ZERO TRUST CONTROLLER METRICS")
        self.logger.info("=" * 70)
        self.logger.info(f"Topology: Clients={len(self.CLIENT_HOSTS)}, Web=1, Remediation=1 (ISOLATED)")
        self.logger.info(f"Authentications    : {self.metrics['total_authentications']}")
        self.logger.info(f"Revocations        : {self.metrics['total_revocations']}")
        self.logger.info(f"Port Scans         : {self.metrics['port_scan_detections']}")
        self.logger.info(f"Exfiltrations      : {self.metrics['exfil_detections']}")
        self.logger.info(f"ICMP Floods        : {self.metrics['icmp_flood_detections']}")
        self.logger.info(f"ICMP Packets Seen  : {self.metrics['icmp_packets_seen']}")
        self.logger.info(f"Isolation Blocks   : {self.metrics['isolation_blocks']}")
        self.logger.info(f"Blocked Hosts      : {len(self.blocked_hosts)} - {list(self.blocked_hosts)}")
        
        if self.metrics['revocation_times']:
            avg_revocation = sum(self.metrics['revocation_times']) / len(self.metrics['revocation_times'])
            self.logger.info(f"Avg Revocation Time: {avg_revocation*1000:.2f}ms")
            
        if self.metrics['detection_times']:
            avg_detection = sum(self.metrics['detection_times']) / len(self.metrics['detection_times'])
            self.logger.info(f"Avg Detection Time : {avg_detection*1000:.2f}ms")
        
        self.logger.info("=" * 70)
            
        metrics_data = {
            'timestamp': datetime.now().isoformat(),
            'topology': {
                'clients': self.CLIENT_HOSTS,
                'web_server': self.WEB_SERVER,
                'remediation_server': self.REMEDIATION_SERVER,
                'remediation_isolated': True
            },
            'metrics': self.metrics,
            'blocked_hosts': list(self.blocked_hosts),
            'active_authentications': len(self.auth_table)
        }
        
        try:
            with open('metrics/controller_metrics.json', 'w') as f:
                json.dump(metrics_data, f, indent=2)
        except:
            pass
 
