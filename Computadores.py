#!/usr/bin/env python3
import subprocess
import socket
import os
import sys
import time
import ipaddress
import concurrent.futures
import signal
from datetime import datetime
import paramiko
from paramiko.ssh_exception import SSHException, AuthenticationException, NoValidConnectionsError

# ===== Config sensível via ambiente (NOVIDADE) =====
SSH_USER = os.getenv("SSH_USER", "")           # ex.: export SSH_USER=root
SSH_PASS = os.getenv("SSH_PASS", "")           # ex.: export SSH_PASS='sua_senha'
TARGET_IPS = [ip.strip() for ip in os.getenv("TARGET_IPS", "").split(",") if ip.strip()]
PAYLOAD_DIR = os.getenv("PAYLOAD_DIR", "./payload")
REMOTE_DIR = os.getenv("REMOTE_DIR", "/tmp/Atualizacao_automatica")
# ===================================================

# Definir um timeout global para operações
OPERATION_TIMEOUT = 300  # 5 minutos em segundos

# Função para lidar com timeout
def timeout_handler(signum, frame):
    raise TimeoutError("A operação excedeu o tempo limite")

def ping_ip(ip):
    """Verifica se o IP responde ao ping."""
    response = subprocess.call(['ping', '-c', '3', ip],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    return response == 0

def is_linux(ip):
    """Verifica se o IP é de uma máquina Linux através da porta SSH."""
    try:
        for _ in range(3):
            try:
                sock = socket.create_connection((ip, 22), timeout=2)
                sock.close()
                return True
            except (socket.timeout, ConnectionRefusedError, socket.error):
                time.sleep(1)
        return False
    except Exception:
        return None

def log_update_status(ip, status):
    date_str = datetime.now().strftime("%d-%m-%Y")
    updated_entry = f"{ip} ({status}-{date_str})\n"
    ip_parts = ip.split('.')
    filename = f"ip-{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.txt" if len(ip_parts) >= 3 else "ip-outros.txt"
    lines = []
    try:
        with open(filename, "r") as log_file:
            lines = log_file.readlines()
        updated = False
        for i in range(len(lines)):
            if lines[i].startswith(ip):
                lines[i] = updated_entry
                updated = True
                break
        if not updated:
            lines.append(updated_entry)
    except FileNotFoundError:
        lines = [updated_entry]
    try:
        with open(filename, "w") as log_file:
            log_file.writelines(lines)
        print(f"\033[32mRegistro de status adicionado: {updated_entry.strip()}\033[0m")
    except Exception as e:
        print(f"\033[31mErro ao registrar status: {e}\033[0m")

def get_system_info(ip, username, password):
    system_info = {
        'ip': ip,
        'debian_version': 'N/A',
        'chrome_version': 'N/A',
        'firefox_version': 'N/A',
        'hostname': 'N/A'
    }
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        try:
            _, stdout, _ = ssh.exec_command('hostname')
            hostname = stdout.read().decode().strip()
            if hostname:
                system_info['hostname'] = hostname
        except:
            pass

        try:
            _, stdout, _ = ssh.exec_command('cat /etc/os-release | grep VERSION_ID')
            version_info = stdout.read().decode().strip()
            if version_info:
                version_number = version_info.split('=')[1].strip('"')
                system_info['debian_version'] = version_number
        except:
            try:
                _, stdout, _ = ssh.exec_command('cat /etc/debian_version')
                version_info = stdout.read().decode().strip()
                if version_info:
                    system_info['debian_version'] = version_info
            except:
                pass

        try:
            _, stdout, _ = ssh.exec_command('google-chrome --version 2>/dev/null')
            chrome_output = stdout.read().decode().strip()
            if chrome_output and 'Google Chrome' in chrome_output:
                chrome_version = chrome_output.split()[-1] if chrome_output.split() else 'Instalado'
                system_info['chrome_version'] = chrome_version
            else:
                _, stdout, _ = ssh.exec_command('chromium --version 2>/dev/null')
                chromium_output = stdout.read().decode().strip()
                if chromium_output:
                    chromium_version = chromium_output.split()[-1] if chromium_output.split() else 'Chromium instalado'
                    system_info['chrome_version'] = f"Chromium {chromium_version}"
        except:
            pass

        try:
            _, stdout, _ = ssh.exec_command('firefox --version 2>/dev/null')
            firefox_output = stdout.read().decode().strip()
            if firefox_output and 'Firefox' in firefox_output:
                firefox_version = firefox_output.split()[-1] if firefox_output.split() else 'Instalado'
                system_info['firefox_version'] = firefox_version
            else:
                _, stdout, _ = ssh.exec_command('firefox-esr --version 2>/dev/null')
                firefox_esr_output = stdout.read().decode().strip()
                if firefox_esr_output:
                    firefox_version = firefox_esr_output.split()[-1] if firefox_esr_output.split() else 'ESR instalado'
                    system_info['firefox_version'] = f"ESR {firefox_version}"
        except:
            pass

        ssh.close()
        return system_info

    except Exception:
        return system_info

def check_debian_version(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        _, stdout, _ = ssh.exec_command('cat /etc/os-release | grep VERSION_ID')
        version_info = stdout.read().decode().strip()
        ssh.close()
        if version_info:
            version_number = version_info.split('=')[1].strip('"')
            return version_number
        return None
    except Exception as e:
        print(f"\033[31mErro ao verificar a versão do Debian: {e}\033[0m")
        return None

def transfer_file_sftp(local_path, remote_path, ip, username, password):
    try:
        transport = paramiko.Transport((ip, 22))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(local_path, remote_path)
        sftp.chmod(remote_path, 0o755)
        sftp.close()
        transport.close()
        return True
    except Exception as e:
        print(f"\033[31mErro ao transferir arquivo via SFTP: {e}\033[0m")
        return False

def execute_remote_command(ip, username, password, command, timeout=60):
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        channel = ssh.get_transport().open_session()
        channel.settimeout(timeout)
        channel.exec_command(command)
        while True:
            if channel.exit_status_ready():
                break
            while channel.recv_ready():
                output = channel.recv(1024).decode()
                print(output, end='')
                sys.stdout.flush()
            while channel.recv_stderr_ready():
                error = channel.recv_stderr(1024).decode()
                print(error, end='')
                sys.stderr.flush()
            time.sleep(0.1)
        exit_status = channel.recv_exit_status()
        return exit_status
    except Exception as e:
        print(f"\033[31mErro ao executar comando remoto: {e}\033[0m")
        return -1
    finally:
        if ssh:
            ssh.close()

def transfer_and_execute_script(ip, username, password):
    """Transfere e executa o script auto.py (payload) em uma máquina específica usando Paramiko."""
    for attempt in range(3):
        try:
            print(f"\033[34mTentativa {attempt + 1}: Conectando a {ip} com o usuário {username}...\033[0m")
            print(f"\033[34mColetando informações do sistema para {ip}...\033[0m")
            system_info = get_system_info(ip, username, password)

            print(f"\033[36m┌─ Informações do Sistema [{ip}] ─┐\033[0m")
            print(f"\033[36m│ Hostname: {system_info['hostname']:<25} │\033[0m")
            print(f"\033[36m│ Debian: {system_info['debian_version']:<27} │\033[0m")
            print(f"\033[36m│ Chrome: {system_info['chrome_version']:<27} │\033[0m")
            print(f"\033[36m│ Firefox: {system_info['firefox_version']:<26} │\033[0m")
            print(f"\033[36m└────────────────────────────────────┘\033[0m")

            # Diretório local/arquivo (AGORA externo)
            local_dir = PAYLOAD_DIR
            remote_dir = REMOTE_DIR
            remote_auto_path = f"{remote_dir}/auto.py"

            mkdir_cmd = f"mkdir -p {remote_dir}"
            mkdir_status = execute_remote_command(ip, username, password, mkdir_cmd, 30)
            if mkdir_status != 0:
                print(f"\033[31mFalha ao criar diretório remoto\033[0m")
                raise Exception("Falha ao criar diretório remoto")

            local_file_path = os.path.join(local_dir, 'auto.py')
            if os.path.isfile(local_file_path):
                print(f"\033[34mTransferindo arquivo auto.py para {ip}...\033[0m")
                if not transfer_file_sftp(local_file_path, remote_auto_path, ip, username, password):
                    raise Exception("Falha ao transferir arquivo via SFTP")
                print(f"\033[32mArquivo auto.py transferido com sucesso para {ip}.\033[0m")
            else:
                print(f"\033[31mArquivo auto.py não encontrado em {local_dir}.\033[0m")
                raise Exception("Arquivo não encontrado")

            # ⚠️ REMOVIDO: escrita em /etc/hosts (era sensível/desnecessário)

            python_check_cmd = 'which python3 || which python'
            _ = execute_remote_command(ip, username, password, python_check_cmd, 30)

            print(f"\033[34mExecutando o script auto.py em {ip} com visualização em tempo real...\033[0m")
            exec_cmd = f'cd {remote_dir} && python3 {remote_auto_path}'
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(600)  # 10 minutos

            try:
                exit_status = execute_remote_command(ip, username, password, exec_cmd, 600)
                if exit_status == 0:
                    print(f"\n\033[32mProcesso de atualização concluído com sucesso em {ip}\033[0m")
                    log_update_status(ip, 'atualizado')
                    return True
                else:
                    print(f"\n\033[31mAtualização em {ip} falhou com status {exit_status}\033[0m")
                    log_update_status(ip, 'erro')
                    return False
            except TimeoutError:
                print("\n\033[31mTIMEOUT: A execução está demorando muito tempo e será interrompida.\033[0m")
                log_update_status(ip, 'erro')
                return False
            except KeyboardInterrupt:
                print("\n\033[33mProcesso interrompido pelo usuário (Ctrl+C).\033[0m")
                log_update_status(ip, 'erro')
                return False
            finally:
                signal.alarm(0)

        except (SSHException, AuthenticationException, NoValidConnectionsError) as e:
            print(f"\033[31mErro de SSH na tentativa {attempt + 1}: {e}\033[0m")
            log_update_status(ip, 'erro')
            time.sleep(3)
        except Exception as e:
            print(f"\033[31mErro na tentativa {attempt + 1}: {e}\033[0m")
            log_update_status(ip, 'erro')
            time.sleep(3)

    print(f"\033[31mFalha em conectar e executar o script em {ip} após 3 tentativas.\033[0m")
    log_update_status(ip, 'erro')
    return False

def scan_subnet(subnet, username, password):
    linux_machines = []
    network = ipaddress.ip_network(subnet, strict=False)
    print(f"\033[34m  → Escaneando {subnet}...\033[0m")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {
            executor.submit(check_ip_and_info, str(ip), username, password): str(ip)
            for ip in network.hosts()
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    linux_machines.append(result)
                    print(f"\033[32m    ✓ Máquina Linux: {result['ip']} ({result['hostname']}) - Debian {result['debian_version']}\033[0m")
            except Exception:
                pass
    return linux_machines

def check_ip_and_info(ip, username, password):
    try:
        if ping_ip(ip):
            if is_linux(ip):
                try:
                    system_info = get_system_info(ip, username, password)
                    return system_info
                except:
                    return {
                        'ip': ip,
                        'debian_version': 'N/A',
                        'chrome_version': 'N/A',
                        'firefox_version': 'N/A',
                        'hostname': 'N/A'
                    }
        return None
    except Exception:
        return None

# (demais funções save_system_info_to_file, create_final_outdated_report, etc.)
# === Mantidas iguais ao seu código original ===

# ...  (COLE aqui todas as funções a partir de save_system_info_to_file()
#       até create_summary_file() sem alterações — já estão OK e não expõem sigilo)

# === A PARTIR DAQUI, APENAS O main() COM AJUSTE NAS VARIÁVEIS ===
def main():
    signal.signal(signal.SIGALRM, timeout_handler)

    # Agora dependem do ambiente, sem hardcode:
    username = SSH_USER or "root"   # fallback opcional
    password = SSH_PASS or ""       # vazio se usar chave/agent etc.

    target_update_ips = TARGET_IPS  # lista via env (pode ficar vazia)

    print("\033[34m" + "="*80 + "\033[0m")
    print("\033[34m              SCANNER COMPLETO DE REDES LINUX 192.168.x.x\033[0m")
    print("\033[34m" + "="*80 + "\033[0m")
    print("\033[33mEste processo irá escanear TODAS as redes de 192.168.1.x a 192.168.255.x\033[0m")
    print("\033[33mColetando informações de Debian, Chrome e Firefox de cada máquina...\033[0m")
    print("\033[34m" + "="*80 + "\033[0m\n")

    # Verifica o payload local sem expor caminho pessoal
    if not os.path.exists(PAYLOAD_DIR):
        print(f"\033[33mAviso: O diretório {PAYLOAD_DIR} não existe!\033[0m")
        print(f"\033[33mO scan das redes será executado, mas a execução do auto.py será desabilitada.\033[0m\n")
        auto_py_available = False
    else:
        if not os.path.exists(os.path.join(PAYLOAD_DIR, 'auto.py')):
            print(f"\033[33mAviso: O arquivo auto.py não existe em {PAYLOAD_DIR}!\033[0m")
            print(f"\033[33mO scan das redes será executado, mas a execução do auto.py será desabilitada.\033[0m\n")
            auto_py_available = False
        else:
            auto_py_available = True

    start_time = time.time()
    all_linux_machines = find_all_linux_machines(username, password)
    end_time = time.time()
    total_time = end_time - start_time

    print(f"\033[34m{'='*80}\033[0m")
    print(f"\033[34m                    RESUMO FINAL DO SCAN\033[0m")
    print(f"\033[34m{'='*80}\033[0m")

    total_machines = sum(len(machines) for machines in all_linux_machines.values())
    total_networks_found = len(all_linux_machines)

    print(f"\033[32m✓ Redes escaneadas: 255 (192.168.1.x a 192.168.255.x)\033[0m")
    print(f"\033[32m✓ Redes com máquinas Linux: {total_networks_found}\033[0m")
    print(f"\033[32m✓ Total de máquinas Linux encontradas: {total_machines}\033[0m")
    print(f"\033[34m✓ Tempo total de scan: {total_time:.2f} segundos ({total_time/60:.1f} minutos)\033[0m")

    if total_machines > 0:
        print(f"\n\033[36mArquivos TXT criados:\033[0m")
        for subnet_num in sorted(all_linux_machines.keys()):
            machines_count = len(all_linux_machines[subnet_num])
            print(f"\033[32m  • ip-192.168.{subnet_num}.txt ({machines_count} máquinas)\033[0m")
        print(f"\033[32m  • RESUMO_GERAL_LINUX_MACHINES.txt (resumo completo)\033[0m")

        print(f"\n\033[36mRedes com máquinas Linux encontradas:\033[0m")
        for subnet_num in sorted(all_linux_machines.keys()):
            machines = all_linux_machines[subnet_num]
            print(f"\033[32m  192.168.{subnet_num}.x: {len(machines)} máquina(s)\033[0m")
    else:
        print(f"\033[33m⚠ Nenhuma máquina Linux foi encontrada nas redes escaneadas.\033[0m")

    print(f"\033[34m{'='*80}\033[0m")

    if auto_py_available and target_update_ips:
        print(f"\n\033[34mIniciando execução do auto.py nos IPs específicos...\033[0m")
        for target_ip in target_update_ips:
            print(f"\n\033[34m{'='*50}\033[0m")
            print(f"\033[34mIniciando execução do auto.py na máquina {target_ip}\033[0m")
            print(f"\n\033[33mAntes de iniciar: Verificando conectividade...\033[0m")
            print(f"\033[34m{'='*50}\033[0m\n")
            if ping_ip(target_ip) and is_linux(target_ip):
                success = transfer_and_execute_script(target_ip, username, password)
                if success:
                    print(f"\n\033[32m✓ Execução do auto.py concluída com sucesso em {target_ip}\033[0m")
                else:
                    print(f"\n\033[31m✗ Falha na execução do auto.py em {target_ip}\033[0m")
            else:
                print(f"\n\033[31mO IP de destino {target_ip} não está acessível ou não é uma máquina Linux.\033[0m")
                log_update_status(target_ip, 'erro')
    elif not auto_py_available:
        print(f"\n\033[33m⚠ Execução do auto.py desabilitada (arquivo não encontrado)\033[0m")
    elif not target_update_ips:
        print(f"\n\033[33m⚠ Nenhum IP específico definido para execução do auto.py (defina TARGET_IPS)\033[0m")

    print(f"\n\033[34m{'='*80}\033[0m")
    print(f"\033[34m                        PROCESSO CONCLUÍDO\033[0m")
    print(f"\033[34m{'='*80}\033[0m")
    print(f"\033[32m✓ Scan de redes completo!\033[0m")
    if auto_py_available and target_update_ips:
        print(f"\033[32m✓ Execução do auto.py nos IPs específicos concluída!\033[0m")
    print(f"\033[36mVerifique os arquivos TXT gerados para mais detalhes.\033[0m")
    print(f"\033[34m{'='*80}\033[0m\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\033[33m⚠ Script interrompido pelo usuário (Ctrl+C)\033[0m")
        print(f"\033[36mProcesso finalizado.\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[31m✗ Erro inesperado: {e}\033[0m")
        sys.exit(1)
