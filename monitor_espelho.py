import subprocess
import re
import os
import sys
from collections import defaultdict

# Configurações
CMD = ["docker", "logs", "-f", "espelho"]
OUTPUT_FILE = "saida.txt"
TOPICS_FILE = "topicos.conf"
FIXED_IP = "192.168.58.102" # O IP da interface da placa (origem no comando de drop)

# Prefixos dos Comandos P4
PREFIX_NORMAL = "sudo /opt/netronome/p4/bin/rtecli tables add -t ingress::espelho_udp -r capture_"
PREFIX_INNER = "sudo /opt/netronome/p4/bin/rtecli tables add -t ingress::espelho_udp_inner -r capture_"
PREFIX_EGRESS = "sudo /opt/netronome/p4/bin/rtecli tables add -t ingress::force_egress_port -r force_port_"
PREFIX_EGRESS_INNER = "sudo /opt/netronome/p4/bin/rtecli tables add -t ingress::force_egress_port_inner -r force_inner_port_"
PREFIX_DROP   = "sudo /opt/netronome/p4/bin/rtecli tables add -t ingress::drop_packet_middleware -r drop_flow_to_"

class EspelhoMonitor:
    def __init__(self):
        self.subscriber_map = defaultdict(set)
        
        self.active_entries = {}
        
        self.flow_config = {}
        self.load_topics()

    def load_topics(self):
        """Ler o arquivo (fluxo,ip)"""
        self.flow_config = {}
        if os.path.exists(TOPICS_FILE):
            with open(TOPICS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            fluxo = parts[0].strip()
                            ip = parts[1].strip()
                            self.flow_config[fluxo] = ip
        else:
            print(f"[AVISO] {TOPICS_FILE} não encontrado.")

    def get_mac_from_ip(self, ip):
        try:
            cmd = f"sudo ip neigh show {ip} | awk '{{print $5}}'"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            if result and len(result) == 17:
                return result
        except Exception:
            pass
        return "00:00:00:00:00:00"

    def process_log_line(self, line):
        line = line.strip()
        if not line: return

        # Mapeamento - Subscriber conectou
        match = re.search(r"Subscriber conectou; (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            ip_subscriber = match.group(1)
            if ip_subscriber not in self.subscriber_map:
                self.subscriber_map[ip_subscriber] = set()
            return

        # Associando nome ao fluxo em relacao ao IP
        # Mensagem base: Fazendo proxy do webcam para o endereço 192.168.58.103
        match = re.search(r"Fazendo proxy do (\S+) para o endere[çc]o (\S+)", line)
        if match:
            fluxo_nome = match.group(1)
            ip_subscriber = match.group(2)
            self.subscriber_map[ip_subscriber].add(fluxo_nome)
            self.write_output()
            return

        # Trafego dos dados -> Criar a Regra
        # 172.22.0.8 46461 2509 => 192.168.58.103 42038
        match = re.search(r"(\d+\.\d+\.\d+\.\d+) (\d+) (\d+) => (\d+\.\d+\.\d+\.\d+) (\d+)", line)
        if match:
            ip_origem = match.group(1)
            porta_origem = int(match.group(2))
            porta_mux = int(match.group(3))
            ip_destino = match.group(4)
            porta_destino = int(match.group(5))

            fluxos_possiveis = self.subscriber_map.get(ip_destino, set())
            
            if not fluxos_possiveis:
                return 

            for nome in fluxos_possiveis:
                self.update_entry(ip_origem, porta_origem, porta_mux, ip_destino, porta_destino, nome)
            
            self.write_output()

    def update_entry(self, ip1, porta1, porta2, ip2, porta3, fluxo_nome):
        key = (ip1, porta2, fluxo_nome)

        if key not in self.active_entries:
            if len(self.active_entries) >= 200: return
            self.active_entries[key] = {
                'fluxo': fluxo_nome,
                'ip1': ip1,         # IP Origem (ex: 172.22.0.8)
                'porta1': porta1,   # Porta Origem
                'porta2': porta2,   # Porta do Fluxo
                'destinations': {}  
            }

        entry = self.active_entries[key]
        
        if ip2 not in entry['destinations'] or entry['destinations'][ip2]['port'] != porta3:
            mac = self.get_mac_from_ip(ip2)
            entry['destinations'][ip2] = {
                'port': porta3,
                'mac': mac
            }

    def write_output(self):
        self.load_topics()
        
        with open(OUTPUT_FILE, 'w') as f:
            f.write("#!/bin/bash\n\n")
            
            for key, entry in self.active_entries.items():
                fluxo_nome = entry['fluxo']
                
                if fluxo_nome not in self.flow_config:
                    continue

                target_ip_config = self.flow_config[fluxo_nome]
                destinations = entry['destinations']

                if target_ip_config not in destinations:
                    continue

                dst_data = destinations[target_ip_config]
                dst_port = dst_data['port']
                dst_mac = dst_data['mac']

                ip1 = entry['ip1']
                porta1 = entry['porta1']
                porta2 = entry['porta2'] # Porta do fluxo (2509)

                is_inner = (ip1 == "172.22.0.8")
                cmd_encaminha = ""
                
                if is_inner:
                    # Match Inner (GTP)
                    match_json = (f"{{ \"udp_inner.srcPort\" : {{ \"value\" : \"{porta1}\" }}, "
                                  f"\"ipv4_inner.dstAddr\" : {{ \"value\" : \"{FIXED_IP}\" }}, "
                                  f"\"udp_inner.dstPort\" : {{ \"value\" : \"{porta2}\" }} }}")

                    match_egress_json = (f"{{ \"ipv4_inner.dstAddr\" : {{ \"value\" : \"{FIXED_IP}\" }} }}")

                    # Action Inner (GTP)
                    action_json = (f"{{ \"type\": \"ingress::encaminhaDecapture_inner\", "
                                   f"\"data\": {{ \"egressPort\": {{ \"value\": \"v0.2\" }}, "
                                   f"\"defaultEgressPort\": {{ \"value\": \"v0.1\" }}, "
                                   f"\"dataPort\": {{ \"value\": \"{porta2}\" }}, "
                                   f"\"ip_dec1\": {{ \"value\": \"{target_ip_config}\" }}, "
                                   f"\"port_dec1\": {{ \"value\": \"{dst_port}\" }}, "
                                   f"\"mac_dec1\": {{ \"value\": \"{dst_mac}\" }} }} }}")
                    
                    action_egress_json = (f"{{ \"type\": \"ingress::change_egress_port\", "
                                   f"\"data\": {{ \"egressPort\": {{ \"value\": \"v0.2\" }} }} }}")
                    

                    cmd_force_port = f"{PREFIX_EGRESS_INNER}{fluxo_nome} -m '{match_egress_json}' -a '{action_egress_json}'" 
                    cmd_encaminha = f"{PREFIX_INNER}{fluxo_nome} -m '{match_json}' -a '{action_json}'"
                else:
                    # Match Normal
                    match_json = (f"{{ \"ipv4.srcAddr\" : {{ \"value\" : \"{ip1}\" }}, "
                                  f"\"udp.srcPort\" : {{ \"value\" : \"{porta1}\" }}, "
                                  f"\"ipv4.dstAddr\" : {{ \"value\" : \"{FIXED_IP}\" }}, "
                                  f"\"udp.dstPort\" : {{ \"value\" : \"{porta2}\" }} }}")

                    match_egress_json = (f"{{ \"ipv4.dstAddr\" : {{ \"value\" : \"{FIXED_IP}\" }} }}")
                    
                    # Action Normal
                    action_json = (f"{{ \"type\": \"ingress::encaminhaDecapture\", "
                                   f"\"data\": {{ \"egressPort\": {{ \"value\": \"v0.2\" }}, "
                                   f"\"defaultEgressPort\": {{ \"value\": \"v0.1\" }}, "
                                   f"\"ip_dec1\": {{ \"value\": \"{target_ip_config}\" }}, "
                                   f"\"port_dec1\": {{ \"value\": \"{dst_port}\" }}, "
                                   f"\"mac_dec1\": {{ \"value\": \"{dst_mac}\" }} }} }}") # Note: removi ip_dec2, etc, para simplificar conforme pedido
                    
                    action_egress_json = (f"{{ \"type\": \"ingress::change_egress_port\", "
                                   f"\"data\": {{ \"egressPort\": {{ \"value\": \"v0.2\" }} }} }}")

                    cmd_force_port = f"{PREFIX_EGRESS_INNER}{fluxo_nome} -m '{match_egress_json}' -a '{action_egress_json}'" 
                    cmd_encaminha = f"{PREFIX_NORMAL}{fluxo_nome} -m '{match_json}' -a '{action_json}'"

                f.write(cmd_encaminha + "\n")
                f.write(cmd_force_port + "\n")
                
                match_drop = (f"{{ \"ipv4.srcAddr\" : {{ \"value\" : \"{FIXED_IP}\" }}, "
                              f"\"udp.srcPort\" : {{ \"value\" : \"{porta2}\" }}, "
                              f"\"ipv4.dstAddr\" : {{ \"value\" : \"{target_ip_config}\" }}, "
                              f"\"udp.dstPort\" : {{ \"value\" : \"{dst_port}\" }} }}")
                
                action_drop = "{ \"type\": \"ingress::drop\", \"data\": {} }"
                
                cmd_drop = f"{PREFIX_DROP}{fluxo_nome} -m '{match_drop}' -a '{action_drop}'"
                
                f.write(cmd_drop + "\n")

    def run(self):
        print("Monitorando logs (Modo Estrito: Topicos + IP)...")
        open(OUTPUT_FILE, 'w').close()
        
        process = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in process.stdout:
                self.process_log_line(line)
        except KeyboardInterrupt:
            process.terminate()

if __name__ == "__main__":
    monitor = EspelhoMonitor()
    monitor.run()
