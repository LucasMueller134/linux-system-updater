import os
import re
import subprocess
import shutil
import tempfile
import sys
import glob
import time
from datetime import datetime

# Diretório de logs (fallback para /tmp se /var/log não estiver disponível)
LOG_DIR = "/var/log/auto-upgrade"
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    LOG_DIR = "/tmp/auto-upgrade"
    os.makedirs(LOG_DIR, exist_ok=True)

EARTH_LOG = os.path.join(LOG_DIR, "earth_update.log")
CHROME_LOG = os.path.join(LOG_DIR, "chrome_update.log")


def _tail_file(path: str, n: int = 120) -> str:
    try:
        # tenta usar tail (mais rápido)…
        out = subprocess.check_output(f"tail -n {n} '{path}'", shell=True, text=True, stderr=subprocess.STDOUT)
        return out
    except Exception:
        # …ou faz na unha
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return "".join(f.readlines()[-n:])
        except Exception:
            return ""

def _parse_ver_tuple(s: str):
    m = re.search(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?', s or "")
    if not m: return (0,0,0)
    return (int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0))

def diagnose_chrome_update_failure(target_major: int = 139) -> str:
    reasons = []

    # 1) Está em hold?
    try:
        hold = subprocess.run("apt-mark showhold | grep -x 'google-chrome-stable'", shell=True)
        if hold.returncode == 0:
            reasons.append("Pacote **google-chrome-stable** está em *hold* (apt-mark hold).")
    except Exception:
        pass

    # 2) Policy: instalado vs candidato
    installed = candidate = ""
    try:
        pol = subprocess.check_output("apt-cache policy google-chrome-stable", shell=True, text=True, stderr=subprocess.STDOUT)
        m1 = re.search(r"Installed:\s*(.+)", pol)
        m2 = re.search(r"Candidate:\s*(.+)", pol)
        installed = (m1.group(1) if m1 else "").strip()
        candidate = (m2.group(1) if m2 else "").strip()
        if candidate in ("(none)", "", "none"):
            reasons.append("Nenhum **Candidate** encontrado no repositório (lista do Chrome ausente/desabilitada ou `apt update` falhou).")
        else:
            cmaj = _parse_ver_tuple(candidate)[0]
            if cmaj < target_major:
                reasons.append(f"O repositório não oferece versão >= {target_major} (Candidate: {candidate}).")
    except Exception:
        pass

    # 3) Mensagens clássicas no log
    log_tail = _tail_file(CHROME_LOG, 200)
    if "Held packages were changed" in log_tail:
        reasons.append("Falha devido a pacote em **hold** (mensagem: *Held packages were changed*).")
    if "NO_PUBKEY" in log_tail or "The following signatures couldn't be verified" in log_tail:
        reasons.append("Problema de **assinatura GPG** nos repositórios do Google.")
    if ("Temporary failure resolving" in log_tail or "Connection timed out" in log_tail or
        "Proxy" in log_tail or "proxy" in log_tail or "403" in log_tail or "404" in log_tail):
        reasons.append("Problema de **rede/proxy** ao acessar `dl.google.com`.")
    if "kept back" in log_tail or "mantidos" in log_tail:
        reasons.append("Pacote foi **mantido (kept back)** por resolução de dependências/pin/prioridade.")

    # 4) Preferência/pin?
    try:
        pins = subprocess.check_output(
            "grep -R --line-number -E 'google-chrome-stable|^Package:.*chrome' /etc/apt/preferences* 2>/dev/null || true",
            shell=True, text=True
        ).strip()
        if pins:
            reasons.append("Existe **pin/prioridade** em `/etc/apt/preferences*` afetando o Chrome:\n" + pins)
    except Exception:
        pass

    # 5) Resumo Installed/Candidate
    if installed or candidate:
        reasons.append(f"Installed: `{installed}` | Candidate: `{candidate}`")

    if not reasons:
        reasons.append("Motivo não conclusivo — verifique o log consolidado e a saída do `apt-cache policy`.")

    reasons.append(f"\n📄 Log: `{CHROME_LOG}`\n\n--- LOG (últimas linhas) ---\n{log_tail}\n--- FIM ---")
    return "\n- " + "\n- ".join(reasons)

def run_remote_command(host, command):
    """Executa um comando remoto com tratamento de erros de codificação."""
    try:
        ssh_command = f"ssh {host} '{command}'"
        process = subprocess.Popen(
            ssh_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate()
        
        # Decodificar com tratamento de erros
        stdout = stdout.decode('utf-8', errors='replace')
        stderr = stderr.decode('utf-8', errors='replace')
        
        if process.returncode != 0:
            print(f"Erro ao executar comando remoto em {host}:\n{stderr}")
            return False
        
        return True
    except Exception as e:
        print(f"Erro na conexão remota com {host}: {str(e)}")
        return False

def get_debian_version():
    """Obtém a versão atual do Debian instalada no sistema (9,10,11,12)."""
    try:
        # 1) /etc/debian_version
        try:
            with open('/etc/debian_version', 'r') as f:
                version = f.read().strip()
            if version.startswith('9.'):
                return 9
            elif version.startswith('10.'):
                return 10
            elif version.startswith('11.'):
                return 11
            elif version.startswith('12.'):
                return 12
        except FileNotFoundError:
            pass

        # 2) lsb_release
        result = subprocess.run(['lsb_release', '-r'], capture_output=True, text=True)
        if result.returncode == 0:
            m = re.search(r'Release:\s+(\d+)', result.stdout)
            if m:
                return int(m.group(1))

        print("Versão do Debian não reconhecida.")
        return None
    except Exception as e:
        print(f"Erro ao detectar versão do Debian: {e}")
        return None
    

def write_canonical_sources(codename: str):
    """
    Escreve /etc/apt/sources.list canônico para o codinome indicado,
    usando HTTPS e signed-by com o debian-archive-keyring.
    """
    sources_path = '/etc/apt/sources.list'
    backup_path = f"{sources_path}.bak.{codename}"
    try:
        if os.path.exists(sources_path):
            shutil.copy2(sources_path, backup_path)
            print(f"Backup do sources.list em {backup_path}")
    except Exception as e:
        print(f"Aviso ao salvar backup do sources.list: {e}")

    base_components = "main contrib non-free"
    components = f"{base_components} non-free-firmware" if codename == "bookworm" else base_components

    signed_by = "signed-by=/usr/share/keyrings/debian-archive-keyring.gpg"
    lines = [
        f"deb [{signed_by}] https://deb.debian.org/debian {codename} {components}",
    ]

    if codename in ("buster", "bullseye"):
        sec = f"deb [{signed_by}] https://security.debian.org/debian-security {codename}/updates {components}"
        upd = f"deb [{signed_by}] https://deb.debian.org/debian {codename}-updates {components}"
    elif codename == "bookworm":
        sec = f"deb [{signed_by}] https://security.debian.org/debian-security {codename}-security {components}"
        upd = f"deb [{signed_by}] https://deb.debian.org/debian {codename}-updates {components}"
    else:
        sec = f"deb [{signed_by}] https://security.debian.org/debian-security {codename}-security {components}"
        upd = f"deb [{signed_by}] https://deb.debian.org/debian {codename}-updates {components}"

    lines += [
        f"deb [{signed_by}] https://deb.debian.org/debian {codename}-backports {components}",
        sec,
        upd,
        ""
    ]
    try:
        with open(sources_path, "w") as f:
            f.write("\n".join(lines))
        print(f"/etc/apt/sources.list atualizado para '{codename}' (HTTPS + signed-by).")
        return True
    except Exception as e:
        print(f"Erro ao escrever sources.list: {e}")
        try:
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, sources_path)
        except:
            pass
        return False

def ensure_debian_archive_keyring():
    """
    Garante keyring do Debian. Se dpkg estiver travado por pacotes pendentes,
    tenta configurar e só então reinstala o keyring.
    """
    try:
        # tenta destravar estado quebrado antes
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)
        subprocess.run("apt-get update || true", shell=True)

        # reinstala o keyring e utilitários SSL/GPG
        subprocess.run(
            "apt-get install -y --reinstall ca-certificates gnupg debian-archive-keyring",
            shell=True, check=True
        )

        ok = os.path.exists("/usr/share/keyrings/debian-archive-keyring.gpg")
        if not ok:
            print("ERRO: debian-archive-keyring.gpg ausente após reinstalação.")
        return ok
    except subprocess.CalledProcessError as e:
        print(f"Falha ao garantir debian-archive-keyring: {e}")
        return False


def codename_for_version(ver: int) -> str:
    mapping = {9: "stretch", 10: "buster", 11: "bullseye", 12: "bookworm"}
    return mapping.get(ver)

def clean_sources_list():
    """Remove linhas duplicadas do arquivo sources.list."""
    sources_path = '/etc/apt/sources.list'
    
    backup_path = f"{sources_path}.bak"
    shutil.copy2(sources_path, backup_path)
    print(f"Backup do sources.list criado em {backup_path}")
    
    try:
        with open(sources_path, 'r') as f:
            lines = f.readlines()
        
        # Remover qualquer referência ao stretch (Debian 9)
        filtered_lines = []
        for line in lines:
            if " stretch " not in line and " stretch/" not in line and " stretch-" not in line:
                filtered_lines.append(line)
            else:
                # Comentar a linha com stretch em vez de incluí-la
                filtered_lines.append(f"# {line.strip()} # Removido - Debian 9 não suportado\n")
        
        content_lines = [line.strip() for line in filtered_lines if line.strip() and not line.strip().startswith('#')]
        
        unique_content = []
        seen = set()
        for line in content_lines:
            if line not in seen:
                unique_content.append(line)
                seen.add(line)
        
        if len(unique_content) < len(content_lines):
            print(f"Encontradas {len(content_lines) - len(unique_content)} linhas duplicadas no sources.list")
            
            clean_lines = []
            seen = set()
            for line in filtered_lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    clean_lines.append(line)
                elif stripped not in seen:
                    clean_lines.append(line)
                    seen.add(stripped)
            
            with open(sources_path, 'w') as f:
                f.writelines(clean_lines)
            
            print("Arquivo sources.list limpo de duplicatas e referências ao Debian 9.")
        else:
            with open(sources_path, 'w') as f:
                f.writelines(filtered_lines)
            
            print("Arquivo sources.list limpo de referências ao Debian 9.")

        with open(sources_path, 'r') as f:
            content = f.read()
        
        if " versão " in content or " versão/" in content:
            fixed_content = re.sub(r'(\s+)versão(\s+|/)', r'\1bookworm\2', content)
            
            with open(sources_path, 'w') as f:
                f.write(fixed_content)
            
            print("Corrigida entrada inválida 'versão' no sources.list.")
            
    except Exception as e:
        print(f"Erro ao limpar sources.list: {e}")
        shutil.copy2(backup_path, sources_path)
        print("Restaurado o backup do sources.list devido a erro.")

def _write_stub(path: str):
    """Cria um stub de maintainer-script que sempre retorna 0."""
    try:
        with open(path, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
    except Exception as e:
        print(f"Aviso: não consegui criar stub em {path}: {e}")

def neutralize_qgis_maintscripts():
    """
    Neutraliza maintainer scripts dos pacotes QGIS que estão causando segfault
    no postinst, substituindo-os por stubs 'exit 0'.
    """
    pkgs = ["qgis-providers", "qgis", "qgis-plugin-grass", "python3-qgis"]
    scripts = ["preinst", "postinst", "prerm", "postrm", "triggers"]
    for p in pkgs:
        for s in scripts:
            info = f"/var/lib/dpkg/info/{p}.{s}"
            if os.path.exists(info):
                try:
                    backup = f"{info}.disabled"
                    if not os.path.exists(backup):
                        shutil.move(info, backup)
                        print(f"Backup do maintscript: {backup}")
                except Exception as e:
                    print(f"Aviso ao mover {info}: {e}")
                _write_stub(info)

def purge_qgis_broken():
    """
    Desabilita repo QGIS, neutraliza scripts, força PURGE dos pacotes QGIS
    e saneia o dpkg/apt para permitir o restante da atualização.
    """
    print("\n=== QUARENTENA QGIS (corrigindo segfault postinst) ===")
    try:
        # 1) Desabilitar repo do QGIS para não reaparecer durante o conserto
        subprocess.run("mv /etc/apt/sources.list.d/qgis* /tmp/ 2>/dev/null || true",
                       shell=True, check=False)

        # 2) Neutralizar scripts que causam segfault
        neutralize_qgis_maintscripts()

        # 3) Tentar configurar o que der, depois PURGE dos QGIS
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -y --fix-broken install || true", shell=True)

        # Remover pacotes QGIS completamente (sem travar no maintscript)
        subprocess.run("apt-get remove --purge -y 'qgis*' 'python3-qgis*' 'libqgis*'",
                       shell=True, check=False)
        subprocess.run("apt-get autoremove -y || true", shell=True)

        # 4) Limpar resíduos de info do dpkg
        subprocess.run("rm -f /var/lib/dpkg/info/qgis* /var/lib/dpkg/info/python3-qgis* "
                       "/var/lib/dpkg/info/libqgis* 2>/dev/null || true", shell=True)

        # 5) DB estável
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -y --fix-broken install || true", shell=True)

        print("=== QGIS removido e dpkg estabilizado ===")
        return True
    except Exception as e:
        print(f"[ERRO] purge_qgis_broken: {e}")
        return False

def allow_releaseinfo_change():
    """
    Aceita mudanças de Suite/Origin/Label/Codename dos repositórios (ex: bookworm->oldstable,
    Assinador mudou metadados). Evita os E: exibidos no log.
    """
    try:
        path = "/etc/apt/apt.conf.d/99allow-releaseinfo-change"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write('Acquire::AllowReleaseInfoChange "true";\n')
            f.write('Acquire::AllowReleaseInfoChange::Suite "true";\n')
            f.write('Acquire::AllowReleaseInfoChange::Origin "true";\n')
            f.write('Acquire::AllowReleaseInfoChange::Label "true";\n')
            f.write('Acquire::AllowReleaseInfoChange::Codename "true";\n')
        print(f"ReleaseInfoChange liberado em {path}")
        return True
    except Exception as e:
        print(f"Aviso em allow_releaseinfo_change: {e}")
        return False


def update_version_file(host=None):
    """Atualiza o arquivo de versão local ou remoto."""
    version_file = '/etc/pmjs/ver'
    command = f"if [ -f {version_file} ]; then sed -i 's/(A)//g' {version_file} && echo ' (A)' >> {version_file}; fi"
    
    if host:
        return run_remote_command(host, command)
    else:
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"Arquivo de versão atualizado: {version_file}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Erro ao atualizar arquivo de versão: {str(e)}")
            return False

def clean_sources_list_d():
    """Limpa arquivos duplicados em /etc/apt/sources.list.d/"""
    sources_dir = '/etc/apt/sources.list.d/'
    
    try:
        backup_dir = '/etc/apt/sources.list.d.bak/'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        for file in glob.glob(f"{sources_dir}*.list"):
            backup_file = os.path.join(backup_dir, os.path.basename(file))
            shutil.copy2(file, backup_file)
        
        print(f"Backup dos arquivos .list criado em {backup_dir}")
        
        # Remover referências ao stretch em todos os arquivos
        for file_path in glob.glob(f"{sources_dir}*.list"):
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            filtered_lines = []
            for line in lines:
                # Ignorar linhas relacionadas ao QGIS
                if "qgis.org" in line.lower():
                    filtered_lines.append(f"# {line.strip()} # Mantido inalterado - QGIS\n")
                elif " stretch " not in line and " stretch/" not in line and " stretch-" not in line:
                    filtered_lines.append(line)
                else:
                    # Comentar a linha com stretch em vez de incluí-la
                    filtered_lines.append(f"# {line.strip()} # Removido - Debian 9 não suportado\n")
            
            with open(file_path, 'w') as f:
                f.writelines(filtered_lines)
            
            print(f"Removidas referências ao Debian 9 de {file_path}")
        
        # Continuar com a remoção de duplicatas, exceto para QGIS
        duplicate_files = set()
        file_contents = {}
        
        for file_path in glob.glob(f"{sources_dir}*.list"):
            if "qgis" in file_path.lower():
                continue  # Pular arquivos do QGIS
            
            with open(file_path, 'r') as f:
                content = f.read().strip()
                
            if content in file_contents.values():
                duplicate_files.add(file_path)
            else:
                file_contents[file_path] = content
        
        for file_path in duplicate_files:
            os.rename(file_path, f"{file_path}.duplicate")
            print(f"Arquivo duplicado movido para {file_path}.duplicate")
        
        for file_path in glob.glob(f"{sources_dir}*.list"):
            if os.path.isfile(file_path) and "qgis" not in file_path.lower():
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                
                content_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
                
                unique_lines = []
                seen = set()
                for line in content_lines:
                    if line.strip() not in seen:
                        unique_lines.append(line)
                        seen.add(line.strip())
                
                if len(unique_lines) < len(content_lines):
                    final_lines = []
                    seen = set()
                    for line in lines:
                        if not line.strip() or line.strip().startswith('#'):
                            final_lines.append(line)
                        elif line.strip() not in seen:
                            final_lines.append(line)
                            seen.add(line.strip())
                    
                    with open(file_path, 'w') as f:
                        f.writelines(final_lines)
                    
                    print(f"Removidas entradas duplicadas de {file_path}")
        
        print("Limpeza de sources.list.d concluída.")
    except Exception as e:
        print(f"Erro ao limpar sources.list.d: {e}")

def ensure_net_download_tools():
    """
    Garante utilitários necessários para baixar chaves (curl/wget), além de gnupg e ca-certificates.
    Não falha se 'apt-get update' tiver warnings — usa índices já presentes.
    """
    try:
        # Instala o que faltar (sem recomendações para ser leve)
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        subprocess.run(
            "apt-get install -y --no-install-recommends curl wget gnupg ca-certificates",
            shell=True, check=False, env=env
        )
        return True
    except Exception as e:
        print(f"Aviso: falha em ensure_net_download_tools: {e}")
        return False
    

def check_and_fix_dpkg_config():
    """Verifica e corrige problemas no arquivo de configuração do dpkg."""
    config_path = '/etc/dpkg/dpkg.cfg.d/local'
    
    if os.path.exists(config_path):
        print(f"Verificando configuração do dpkg em {config_path}...")
        backup_path = f"{config_path}.bak"
        
        try:
            shutil.copy2(config_path, backup_path)
            print(f"Backup criado em {backup_path}")
            
            with open(config_path, 'r') as f:
                lines = f.readlines()
            
            fixed_lines = []
            modified = False
            
            for line in lines:
                stripped = line.strip()
                if stripped.startswith('dpkg'):
                    fixed_line = f"# {line} (comentado automaticamente - configuração inválida)\n"
                    fixed_lines.append(fixed_line)
                    modified = True
                    print(f"Linha problemática encontrada e comentada: {stripped}")
                else:
                    fixed_lines.append(line)
            
            if modified:
                with open(config_path, 'w') as f:
                    f.writelines(fixed_lines)
                print(f"Arquivo {config_path} corrigido.")
            else:
                print(f"Nenhum problema específico encontrado em {config_path}, mas ele pode estar causando erros.")
                os.rename(config_path, f"{config_path}.disabled")
                print(f"Arquivo renomeado para {config_path}.disabled como precaução.")
                
            return True
        except Exception as e:
            print(f"Erro ao corrigir configuração do dpkg: {e}")
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, config_path)
            return False
    else:
        print(f"Arquivo de configuração {config_path} não encontrado.")
        return True

def install_expect_if_needed():
    """Instala o pacote expect se não estiver disponível."""
    try:
        # Verificar se o expect está instalado
        result = subprocess.run("which expect", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print("Pacote 'expect' não encontrado. Instalando...")
            subprocess.run("apt-get update", shell=True, check=True)
            subprocess.run("apt-get install -y expect", shell=True, check=True)
            print("Pacote 'expect' instalado com sucesso.")
        else:
            print("Pacote 'expect' já está instalado.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao instalar o pacote 'expect': {e}")
        return False

def create_expect_script():
    """Cria um script expect para automatizar respostas a prompts interativos."""
    expect_script = "/tmp/auto_respond.exp"
    
    with open(expect_script, "w") as f:
        f.write("""#!/usr/bin/expect -f
# Script para automatizar respostas a prompts interativos

# Definir timeout (em segundos)
set timeout 300

# Capturar o comando dos argumentos
set command [lindex $argv 0]

# Iniciar o comando
spawn {*}$command

# Responder aos prompts conhecidos
expect {
    # Prompt de inicialização automática do Assinador
    "Iniciar o Assinador junto com o sistema ?" {
        send "N\\r"
        exp_continue
    }
    
    # Prompt genérico Sim/Não (responder Não)
    -re "\\\\<Sim\\\\>.*\\\\<Não\\\\>" {
        send "N\\r"
        exp_continue
    }
    
    # Prompt de configuração de pacotes (manter configuração atual)
    "Manter a versão atualmente instalada" {
        send "N\\r"
        exp_continue
    }
    
    # Prompt de reinicialização de serviços
    "Serviços a serem reiniciados" {
        send "\\r"
        exp_continue
    }
    
    # Prompt de configuração de pacotes (aceitar configuração do mantenedor)
    "instalar a versão do mantenedor do pacote" {
        send "Y\\r"
        exp_continue
    }
    
    # Timeout
    timeout {
        puts "Timeout atingido."
        exit 1
    }
    
    # Fim do comando
    eof
}

# Capturar código de saída
lassign [wait] pid spawnid os_error_flag value
exit $value
""")
    
    os.chmod(expect_script, 0o755)
    print(f"Script expect criado em {expect_script}")
    return expect_script

def check_and_fix_corrupted_python_packages():
    """Verifica e corrige pacotes Python corrompidos ou com versões incompatíveis.
    
    Esta função foi atualizada para resolver problemas específicos com pacotes Python
    corrompidos durante a atualização para o Debian 12, incluindo:
    1. Pacotes com dados corrompidos (erro de descompressão LZMA)
    2. Versões incompatíveis entre pacotes Python relacionados
    3. Dependências desencontradas entre pacotes Python
    """
    print("\n=== Verificando pacotes Python potencialmente corrompidos ou incompatíveis ===")
    
    # Instalar expect se necessário
    install_expect_if_needed()
    
    # Criar script expect para automação de respostas
    expect_script = create_expect_script()
    
    # Lista de pacotes Python que podem apresentar problemas durante a atualização
    problematic_packages = [
        "libpython3.11-stdlib",
        "python3.11",
        "python3.11-minimal",
        "libpython3.11-minimal",
        "libpython3.11",
        "libpython3.11-dev",
        "python3.11-dev"
    ]
    
    # Verificar status dos pacotes
    print("Verificando status dos pacotes Python...")
    
    packages_to_fix = []
    version_conflicts = False
    
    # Primeiro, verificar se há pacotes com problemas de instalação
    for package in problematic_packages:
        try:
            # Verificar se o pacote está instalado
            result = subprocess.run(
                f"dpkg -l {package} | grep -E '^[hi]i'",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Verificar se há erros no status do pacote
                status_result = subprocess.run(
                    f"dpkg -s {package} 2>/dev/null | grep 'Status:'",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if "Status: install ok installed" not in status_result.stdout:
                    print(f"Pacote {package} está em estado inconsistente.")
                    packages_to_fix.append(package)
                else:
                    print(f"Pacote {package} parece estar instalado corretamente.")
            else:
                print(f"Pacote {package} não está instalado ou não foi encontrado.")
        except Exception as e:
            print(f"Erro ao verificar pacote {package}: {e}")
    
    # Agora, verificar se há conflitos de versão entre os pacotes
    print("\nVerificando conflitos de versão entre pacotes Python...")
    
    # Executar apt check para verificar dependências
    apt_check_result = subprocess.run(
        "apt-get check",
        shell=True,
        capture_output=True,
        text=True
    )
    
    if apt_check_result.returncode != 0:
        print("Detectados problemas de dependências. Verificando detalhes...")
        
        # Verificar se há problemas específicos com pacotes Python
        apt_fix_broken_result = subprocess.run(
            "apt --fix-broken -s install",
            shell=True,
            capture_output=True,
            text=True
        )
        
        # Procurar por conflitos de versão nos pacotes Python
        for package in problematic_packages:
            if package in apt_fix_broken_result.stdout:
                if package not in packages_to_fix:
                    packages_to_fix.append(package)
                version_conflicts = True
        
        if version_conflicts:
            print("Detectados conflitos de versão entre pacotes Python.")
            print("Detalhes do problema:")
            print(apt_fix_broken_result.stdout)
    
    if not packages_to_fix and not version_conflicts:
        print("Nenhum pacote Python corrompido ou com versões incompatíveis encontrado.")
        return True
    
    if version_conflicts:
        print(f"\nEncontrados conflitos de versão entre pacotes Python.")
    else:
        print(f"\nEncontrados {len(packages_to_fix)} pacotes Python com problemas: {', '.join(packages_to_fix)}")
    
    print("Iniciando procedimento de correção...")
    
    # Limpar o cache de pacotes
    print("\nLimpando cache de pacotes APT...")
    try:
        subprocess.run("apt clean", shell=True, check=True)
        print("Cache de pacotes limpo com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao limpar cache de pacotes: {e}")
    
    # Atualizar a lista de pacotes
    print("\nAtualizando lista de pacotes...")
    try:
        subprocess.run("apt update", shell=True, check=True)
        print("Lista de pacotes atualizada com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Aviso: Erro ao atualizar lista de pacotes: {e}")
        print("Continuando mesmo assim...")
    
    # Se houver conflitos de versão, tentar corrigir com --fix-broken install usando expect
    if version_conflicts:
        print("\nTentando corrigir conflitos de versão com apt --fix-broken install...")
        try:
            # Usar o script expect para automatizar respostas
            subprocess.run(f"{expect_script} \"apt --fix-broken install -y\"", shell=True, check=True)
            print("Conflitos de versão corrigidos com sucesso.")
            
            # Verificar se os conflitos foram resolvidos
            apt_check_result = subprocess.run(
                "apt-get check",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if apt_check_result.returncode != 0:
                print("Ainda há problemas de dependências. Tentando abordagem mais agressiva...")
                
                # Tentar remover e reinstalar os pacotes Python problemáticos
                print("\nRemovendo pacotes Python problemáticos para reinstalação limpa...")
                
                # Primeiro, tentar remover os pacotes em ordem inversa de dependência
                for package in reversed(problematic_packages):
                    try:
                        # Usar o script expect para automatizar respostas
                        subprocess.run(f"{expect_script} \"apt remove -y --purge {package}\"", shell=True)
                    except:
                        pass
                
                # Agora reinstalar os pacotes principais
                print("\nReinstalando pacotes Python essenciais...")
                try:
                    # Usar o script expect para automatizar respostas
                    subprocess.run(f"{expect_script} \"apt install -y python3-minimal python3\"", shell=True, check=True)
                    print("Pacotes Python essenciais reinstalados com sucesso.")
                except subprocess.CalledProcessError as e:
                    print(f"Erro ao reinstalar pacotes Python essenciais: {e}")
                    
                # Tentar reinstalar os pacotes específicos
                for package in problematic_packages:
                    try:
                        # Usar o script expect para automatizar respostas
                        subprocess.run(f"{expect_script} \"apt install -y {package}\"", shell=True)
                        print(f"Pacote {package} reinstalado.")
                    except:
                        print(f"Não foi possível reinstalar {package}, continuando...")
            else:
                print("Todos os conflitos de versão foram resolvidos.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao corrigir conflitos de versão: {e}")
            
            # Tentar uma abordagem mais agressiva
            print("\nTentando abordagem mais agressiva para corrigir conflitos de versão...")
            
            # Forçar a reinstalação de todos os pacotes Python relacionados
            python_packages_cmd = "dpkg -l | grep python3 | awk '{print $2}' | xargs"
            python_packages_result = subprocess.run(python_packages_cmd, shell=True, capture_output=True, text=True)
            
            if python_packages_result.stdout.strip():
                try:
                    # Usar o script expect para automatizar respostas
                    reinstall_cmd = f"{expect_script} \"apt install --reinstall -y {python_packages_result.stdout.strip()}\""
                    subprocess.run(reinstall_cmd, shell=True)
                    print("Pacotes Python reinstalados.")
                except:
                    print("Erro ao reinstalar pacotes Python.")
    else:
        # Corrigir pacotes quebrados
        print("\nCorrigindo pacotes quebrados...")
        try:
            # Usar o script expect para automatizar respostas
            subprocess.run(f"{expect_script} \"apt --fix-broken install -y\"", shell=True, check=True)
            print("Pacotes quebrados corrigidos com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"Aviso: Erro ao corrigir pacotes quebrados: {e}")
            print("Tentando abordagem alternativa...")
        
        # Tentar reinstalar os pacotes com problemas
        success = True
        for package in packages_to_fix:
            print(f"\nTentando reinstalar o pacote {package}...")
            try:
                # Usar o script expect para automatizar respostas
                subprocess.run(f"{expect_script} \"apt install --reinstall -y {package}\"", shell=True, check=True)
                print(f"Pacote {package} reinstalado com sucesso.")
            except subprocess.CalledProcessError as e:
                print(f"Erro ao reinstalar o pacote {package}: {e}")
                success = False
    
    # Verificar se ainda há problemas
    apt_check_result = subprocess.run(
        "apt-get check",
        shell=True,
        capture_output=True,
        text=True
    )
    
    if apt_check_result.returncode != 0:
        print("\nAinda há problemas de dependências. Tentando solução radical...")
        
        # Solução radical: remover completamente os pacotes Python problemáticos e reinstalar
        print("Removendo completamente os pacotes Python problemáticos...")
        
        # Criar um script temporário para remover e reinstalar pacotes Python
        script_path = "/tmp/fix_python_packages.sh"
        with open(script_path, "w") as f:
            f.write("""#!/bin/bash
set -e

echo "=== Iniciando correção radical de pacotes Python ==="

# Remover pacotes Python problemáticos
echo "Removendo pacotes Python problemáticos..."
apt-get remove -y --purge libpython3.11-stdlib libpython3.11-minimal python3.11 python3.11-minimal libpython3.11 libpython3.11-dev python3.11-dev || true

# Limpar pacotes órfãos
echo "Removendo pacotes órfãos..."
apt-get autoremove -y || true

# Limpar cache
echo "Limpando cache de pacotes..."
apt-get clean

# Atualizar lista de pacotes
echo "Atualizando lista de pacotes..."
apt-get update

# Corrigir pacotes quebrados
echo "Corrigindo pacotes quebrados..."
apt-get --fix-broken install -y || true

# Reinstalar pacotes Python essenciais
echo "Reinstalando pacotes Python essenciais..."
apt-get install -y python3-minimal python3 || true

# Reinstalar pacotes específicos
echo "Reinstalando pacotes Python específicos..."
apt-get install -y libpython3.11-stdlib libpython3.11-minimal python3.11 || true

echo "=== Correção radical concluída ==="
""")
        
        os.chmod(script_path, 0o755)
        print(f"Script de correção radical criado em {script_path}")
        
        try:
            # Usar o script expect para automatizar respostas
            subprocess.run(f"{expect_script} \"{script_path}\"", shell=True)
            print("Correção radical aplicada.")
        except:
            print("Erro durante a correção radical.")
            
        # Verificar novamente
        apt_check_result = subprocess.run(
            "apt-get check",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if apt_check_result.returncode != 0:
            print("\nAinda há problemas após a correção radical.")
            print("Recomendações adicionais:")
            print("1. Verifique a conexão com a internet")
            print("2. Tente mudar o mirror do Debian em /etc/apt/sources.list")
            print("3. Verifique se há problemas no sistema de arquivos")
            print("4. Verifique o espaço disponível em disco")
            print("5. Como último recurso, considere reinstalar o sistema")
            return False
        else:
            print("\nTodos os problemas foram resolvidos após a correção radical.")
            return True
    else:
        print("\nTodos os problemas de pacotes Python foram corrigidos com sucesso.")
        return True

def run_upgrade_process(interactive=False):
    """Executa o core upgrade usando respostas automáticas.
       Desabilita Chrome (repo/pacote), poe b43 em quarentena e abre espaço em /boot antes."""
    qgis_pkgs = ["qgis", "qgis-plugin-grass", "python3-qgis"]

    try:
        # --- tudo que você já tem dentro da função fica igual daqui pra baixo ---
        # Garantir expect instalado
        if not check_and_install_expect():
            print("ERRO: Não foi possível instalar o pacote 'expect'. Abortando atualização.")
            return False

        # Silencia aviso do chrome.list.off
        tidy_chrome_off_file()

        # Desabilita repositório do Chrome e segura/remove pacote (evita 404 no cache)
        try:
            print("\n=== DESABILITANDO CHROME DURANTE O CORE UPGRADE ===")
            subprocess.run(
                "mv /etc/apt/sources.list.d/google-chrome.list "
                "/etc/apt/sources.list.d/google-chrome.list.disabled 2>/dev/null || true",
                shell=True
            )
            subprocess.run("apt-mark hold google-chrome-stable 2>/dev/null || true", shell=True)
            subprocess.run("apt-get remove -y google-chrome-stable || true", shell=True)
        except Exception as e:
            print(f"Aviso ao desabilitar Chrome: {e}")

        quarantine_b43_installer()
        free_boot_space(min_free_mb=220)

        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)

        # Purga QGIS antes do core upgrade
        try:
            print("\n=== REMOVENDO QGIS ANTES DO CORE UPGRADE ===")
            subprocess.run("apt remove --purge -y 'qgis*' 'python3-qgis*' 'libqgis*'", shell=True, check=False)
            subprocess.run("apt autoremove -y", shell=True, check=False)
        except Exception as e:
            print(f"Aviso: falha ao remover QGIS antes do upgrade: {e}")

        if not ensure_debian_archive_keyring():
            print("ERRO: keyring Debian inválido. Abortando.")
            return False

        if not check_and_clear_apt_locks():
            print("AVISO: Não foi possível limpar todos os locks. Tentando continuar mesmo assim.")

        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
        env["APT_LISTCHANGES_FRONTEND"] = "none"
        env["DEBIAN_PRIORITY"] = "critical"
        env["TERM"] = "dumb"

        # Debconf do Assinador
        try:
            with open("/tmp/assinador_selections", "w") as f:
                f.write("assinador iniciar_automaticamente boolean false\n")
            subprocess.run("cat /tmp/assinador_selections | debconf-set-selections", shell=True, check=True)
        except Exception as e:
            print(f"Erro ao carregar configurações do assinador: {e}")

        monitor_and_kill_whiptail()

        print("\nVerificando pacotes Python antes da atualização principal...")
        if not check_and_fix_corrupted_python_packages():
            print("Problemas Python detectados; tentando continuar mesmo assim...")

        subprocess.run("mv /etc/apt/sources.list.d/qgis* /tmp/ 2>/dev/null || true", shell=True)

        for pkg in qgis_pkgs:
            subprocess.run(f"apt-mark hold {pkg} 2>/dev/null || true", shell=True)

        print("\nExecutando: apt update")
        auto_respond_command("apt update", env=env)

        print("\nExecutando: apt upgrade -y")
        if not auto_respond_command("apt upgrade -y", env=env, timeout=900):
            print("Problemas no apt upgrade. Tentando liberar /boot e corrigir dependências...")
            free_boot_space(min_free_mb=220)
            subprocess.run("dpkg --configure -a || true", shell=True)
            subprocess.run("apt-get -f install -y || true", shell=True)
            if not auto_respond_command("apt upgrade -y", env=env, timeout=900):
                print("Problemas persistem no apt upgrade. Tentando correção Python e repetir...")
                if check_and_fix_corrupted_python_packages():
                    check_and_clear_apt_locks()
                    free_boot_space(min_free_mb=220)
                    auto_respond_command("apt upgrade -y", env=env, timeout=900)

        print("\nExecutando: apt -y full-upgrade")
        if not auto_respond_command("apt -y full-upgrade", env=env, timeout=1200):
            print("Problemas no full-upgrade. Tentando liberar /boot e repetir...")
            free_boot_space(min_free_mb=220)
            subprocess.run("dpkg --configure -a || true", shell=True)
            subprocess.run("apt-get -f install -y || true", shell=True)
            if not auto_respond_command("apt -y full-upgrade", env=env, timeout=1200):
                print("Tentando corrigir Python e repetir full-upgrade...")
                if check_and_fix_corrupted_python_packages():
                    check_and_clear_apt_locks()
                    free_boot_space(min_free_mb=220)
                    auto_respond_command("apt -y full-upgrade", env=env, timeout=1200)

        print("\nExecutando: apt autoremove -y")
        auto_respond_command("apt autoremove -y", env=env)

        print("\nExecutando: apt clean")
        auto_respond_command("apt clean", env=env)

        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)

        print("\nVerificando pacotes Python após a atualização...")
        check_and_fix_corrupted_python_packages()

        subprocess.run("mv /tmp/qgis* /etc/apt/sources.list.d/ 2>/dev/null || true", shell=True)
        for pkg in qgis_pkgs:
            subprocess.run(f"apt-mark unhold {pkg} 2>/dev/null || true", shell=True)

        update_version_file()

        print("\nProcesso de atualização concluído!")
        return True

    finally:
        # 🔓 GARANTE que o Chrome não fique em hold mesmo se a função abortar no meio
        subprocess.run("apt-mark unhold google-chrome-stable 2>/dev/null || true", shell=True)
        # E também garante que os pacotes do QGIS não fiquem presos em hold se houve erro antes do unhold
        for pkg in ["qgis", "qgis-plugin-grass", "python3-qgis"]:
            subprocess.run(f"apt-mark unhold {pkg} 2>/dev/null || true", shell=True)


def monitor_and_kill_whiptail():
    """
    Monitora e mata processos whiptail do assinador em segundo plano.
    """
    import threading
    import time
    
    def background_monitor():
        print("Iniciando monitoramento de processos whiptail...")
        try:
            while True:
                # Verifica se há processos whiptail relacionados ao assinador
                whiptail_check = subprocess.run(
                    "ps aux | grep -i 'whiptail.*[Ii]nicia' | grep -v grep", 
                    shell=True, capture_output=True, text=True
                )
                
                if whiptail_check.stdout.strip():
                    print("Processo whiptail do assinador detectado! Tentando matar...")
                    # Tenta responder ao diálogo enviando "N"
                    try:
                        # Encontra o PID do processo whiptail
                        pid_search = re.search(r'\s+(\d+)\s+', whiptail_check.stdout)
                        if pid_search:
                            whiptail_pid = pid_search.group(1)
                            # Tenta enviar 'n' diretamente para o processo
                            os.system(f"echo n | sudo tee /proc/{whiptail_pid}/fd/0 > /dev/null")
                            time.sleep(0.5)
                            # Agora tenta tab e enter
                            os.system(f"echo -e '\\t\\r' | sudo tee /proc/{whiptail_pid}/fd/0 > /dev/null")
                            time.sleep(0.5)
                    except Exception as e:
                        print(f"Erro ao tentar responder ao diálogo: {e}")
                    
                    # Se ainda persistir, mata o processo
                    subprocess.run("pkill -f 'whiptail.*[Ii]nicia'", shell=True)
                    
                time.sleep(2)  # Verifica a cada 2 segundos
        except Exception as e:
            print(f"Erro no monitoramento de whiptail: {e}")
    
    # Inicia o monitoramento em uma thread separada
    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()
    print("Monitoramento de processos whiptail iniciado em segundo plano.")

def check_and_install_expect():
    """Verifica se o pacote expect está instalado e o instala se necessário."""
    try:
        # Verificar se expect já está instalado
        subprocess.run("which expect", shell=True, check=True, 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Pacote expect já está instalado.")
        return True
    except subprocess.CalledProcessError:
        print("Instalando pacote expect...")
        try:
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            subprocess.run("apt-get update -qq && apt-get install -y expect", 
                          shell=True, check=True, env=env)
            print("Pacote expect instalado com sucesso.")
            return True
        except subprocess.CalledProcessError:
            print("Falha ao instalar expect. Tentando método alternativo...")
            try:
                subprocess.run("apt-get install -y --force-yes expect", 
                              shell=True, check=True)
                print("Pacote expect instalado com sucesso pelo método alternativo.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erro ao instalar o expect: {e}")
                return False

def auto_respond_command(command, env=None, timeout=1800, log_path=None):
    print(f"\nExecutando comando com respostas automáticas: {command}")

    inject = ' -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"'
    cmd = command

    # Injeta APENAS quando o comando começa com 'apt ' ou 'apt-get ' (evita 'apt-mark')
    m = re.match(r'^\s*(apt|apt-get)\s+', cmd)
    if m and "Dpkg::Options::=" not in cmd:
        # insere após o prefixo encontrado
        prefix = cmd[:m.end()].rstrip()  # ex: 'apt' ou 'apt-get'
        rest   = cmd[m.end():]
        cmd = f"{prefix}{inject} {rest}"

    # Logging opcional seguro
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        cmd = f"( {cmd} ) 2>&1 | tee -a '{log_path}'"

    # Ambiente não interativo
    if env is None:
        env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("DEBCONF_NONINTERACTIVE_SEEN", "true")
    env.setdefault("APT_LISTCHANGES_FRONTEND", "none")
    env.setdefault("DEBCONF_NOWARNINGS", "yes")

    try:
        subprocess.run("echo 'assinador iniciar_automaticamente boolean false' | debconf-set-selections",
                       shell=True, capture_output=True, text=True)
    except Exception:
        pass

    expect_script = create_auto_response_script(cmd)

    try:
        proc = subprocess.Popen(f"expect {expect_script}", shell=True, env=env)
        start = time.time()
        while time.time() - start < timeout:
            if proc.poll() is not None:
                break
            try:
                dialog_check = subprocess.run(
                    "ps aux | grep -i 'whiptail.*[Ii]nicia' | grep -v grep",
                    shell=True, capture_output=True, text=True
                )
                if dialog_check.stdout.strip():
                    handle_assinador_dialog()
            except Exception:
                pass
            time.sleep(5)

        if proc.poll() is None:
            proc.terminate(); time.sleep(2)
            if proc.poll() is None:
                proc.kill()
            print(f"Timeout atingido após {timeout}s: {command}")
            return False

        return proc.returncode == 0
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return False
    finally:
        try:
            if os.path.exists(expect_script): os.remove(expect_script)
        except Exception:
            pass


def preconfigure_assinador():
    print("Pré-configurando respostas para o pacote Assinador...")
    debconf_file = os.path.join(tempfile.gettempdir(), "assinador_debconf.conf")

    # Tentativas de nomes de templates (cobrimos variações comuns)
    lines = [
        # genéricas
        "assinador iniciar_automaticamente boolean false",
        "assinador iniciar_com_sistema boolean false",
        "assinador autostart boolean false",

        # variações prováveis do pacote
        "assinador-serpro iniciar_automaticamente boolean false",
        "assinador-serpro iniciar_com_sistema boolean false",
        "assinador-serpro autostart boolean false",

        # nomes estilo debconf (namespace/pkg + chave)
        "assinador-serpro/auto_start boolean false",
        "assinador-serpro/autostart boolean false",
        "assinador/auto_start boolean false",
        "assinador/autostart boolean false"
    ]

    with open(debconf_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    try:
        subprocess.run(f"cat {debconf_file} | debconf-set-selections", shell=True, check=True)
        print("Respostas pré-configuradas com sucesso.")

        # Força comportamento não interativo + manter conffiles locais
        apt_conf_path = "/etc/apt/apt.conf.d/99custom-noninteractive"
        with open(apt_conf_path, "w") as f:
            f.write('DPkg::Options {"--force-confdef";"--force-confold";}\n')
            f.write('APT::Get::Assume-Yes "true";\n')
            f.write('APT::Get::allow-downgrades "true";\n')
        print(f"Arquivo de configuração do APT criado em {apt_conf_path}")
        return True
    except Exception as e:
        print(f"Erro ao pré-configurar respostas: {e}")
        return False
    finally:
        if os.path.exists(debconf_file):
            os.remove(debconf_file)



def create_auto_response_script(command):
    """
    Cria um script expect para responder automaticamente a prompts (dpkg/apt),
    preferindo SEMPRE manter a configuração local e responder NÃO ao autostart.
    """
    script_path = os.path.join(tempfile.gettempdir(), f"auto_respond_{int(time.time())}.exp")
    escaped_command = command.replace('"', '\\"')

    content = f'''#!/usr/bin/expect -f
set timeout -1
# Evita eco confuso
log_user 1

spawn bash -c "{escaped_command}"

# Regras:
#  - Sempre responder "N" para inicialização automática
#  - Manter conffiles locais (N nas perguntas de dpkg)
#  - Confirmar prosseguimento quando for [Y/n] ou [S/n]

expect {{
    # -------------- Diálogo do Assinador (diversas variações) --------------
    -re {{Iniciar o Assinador junto com o sistema}} {{
        send "n\\r"
        exp_continue
    }}
    -re {{Digite\\s+N\\s+para\\s+Não\\s+iniciar}} {{
        send "n\\r"
        exp_continue
    }}
    # Caixa " <Sim>    <Não> " (Tab para a direita e Enter)
    -re {{<Sim>\\s+<Não>}} {{
        # garante NÃO: tab até "Não" e enter
        send "\\t\\r"
        exp_continue
    }}

    # -------------- DPKG conffiles (sempre manter local) --------------
    -re {{foi modificado localmente.*\\(Y/I/N/O/D/Z\\).*}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{O ficheiro de configuração.*modificado localmente.*\\(Y/I/N/O/D/Z\\).*}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{Manter a versão atualmente instalada}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{modified configuration file.*\\(Y/I/N/O/D/Z\\).*}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{What do you want to do about modified configuration file}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{keep the local version currently installed}} {{
        send "N\\r"
        exp_continue
    }}

    # -------------- Confirmações genéricas --------------
    -re {{\\(Y/I/N/O/D/Z\\) \\[default=N\\]}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{\\[padrão=N\\]}} {{
        send "N\\r"
        exp_continue
    }}
    -re {{continuar\\? \\[S/n\\]}} {{
        send "S\\r"
        exp_continue
    }}
    -re {{continue\\? \\[Y/n\\]}} {{
        send "Y\\r"
        exp_continue
    }}

    # Segurança: se aparecer menu de opções, tenta "N" e Enter
    timeout {{
        send "N\\r"
        after 300
        send "\\t\\r"
        exp_continue
    }}

    eof
}}
'''
    with open(script_path, "w") as f:
        f.write(content)
    os.chmod(script_path, 0o755)
    return script_path



def handle_assinador_dialog():
    """
    Função específica para lidar com o diálogo de Inicialização Automática do Assinador.
    """
    print("Detectado diálogo de 'Inicialização Automática do Assinador'. Tentando responder...")
    
    try:
        # Método 1: Enviar 'n' diretamente para qualquer processo que possa estar esperando entrada
        subprocess.run("echo 'n' | sudo tee /proc/$(pgrep -f 'whiptail|dialog')/fd/0 > /dev/null", shell=True)
        
        # Método 2: Tentar simular a tecla Tab e Enter usando ANSI escape codes
        os.system("printf '\\t\\r' > /dev/tty")
        time.sleep(0.5)
        
        # Método 3: Tentar simular as teclas direcionais para selecionar "Não" e depois Enter
        os.system("printf '\\033[C\\r' > /dev/tty")  # Direita + Enter
        time.sleep(0.5)
        
        # Método 4: Tentar matar o processo de dialog/whiptail
        subprocess.run("pkill -f 'whiptail|dialog'", shell=True)
        
        # Método 5: Tentar definir a configuração diretamente via debconf
        subprocess.run("echo 'assinador iniciar_automaticamente false' | debconf-set-selections", shell=True)
        
        print("Tentativas de responder ao diálogo concluídas.")
        return True
    except Exception as e:
        print(f"Erro ao tentar responder ao diálogo: {e}")
        return False

def check_and_clear_apt_locks():
    """Verifica e limpa os locks do APT se necessário."""
    print("Verificando se existem locks do sistema de pacotes...")
    locks_cleared = True
    lock_files = [
        "/var/lib/dpkg/lock-frontend",
        "/var/lib/apt/lists/lock",
        "/var/cache/apt/archives/lock",
        "/var/lib/dpkg/lock"
    ]
    
    # Primeiro, identificar processos que estão usando os locks
    try:
        print("Verificando processos que podem estar segurando locks...")
        # Verificar processos que podem estar usando o dpkg ou apt
        ps_output = subprocess.run("ps aux | grep -E 'apt|dpkg|aptitude|synaptic|update-manager' | grep -v grep", 
                                  shell=True, capture_output=True, text=True)
        if ps_output.stdout.strip():
            print("Processos ativos de gerenciamento de pacotes detectados:")
            print(ps_output.stdout)
            
            # Extrair e terminar processos específicos de APT/DPKG
            for line in ps_output.stdout.splitlines():
                try:
                    parts = re.split(r'\s+', line.strip(), maxsplit=10)
                    if len(parts) < 2:
                        continue
                    
                    pid = int(parts[1])
                    proc_name = parts[-1] if len(parts) > 10 else ''
                    
                    # Verificar se é realmente um processo de APT ou DPKG
                    if any(x in proc_name for x in ['apt', 'dpkg', 'aptitude', 'synaptic', 'update-manager']):
                        print(f"Tentando terminar processo {pid}: {proc_name}")
                        # Primeiro tenta terminar normalmente
                        try:
                            subprocess.run(f"kill -15 {pid}", shell=True, check=True, timeout=2)
                            print(f"Enviado sinal TERM para PID {pid}")
                        except:
                            # Se falhar, tenta forçar
                            print(f"Tentando forçar encerramento do PID {pid}")
                            subprocess.run(f"kill -9 {pid}", shell=True)
                except (ValueError, IndexError) as e:
                    print(f"Erro ao processar linha de PS: {e}")
            
            # Aguardar um pouco para os processos encerrarem
            print("Aguardando 5 segundos para processos terminarem...")
            time.sleep(5)
    except Exception as e:
        print(f"Erro ao verificar processos: {e}")
    
    # Verificar especificamente o PID mencionado na mensagem de erro (3400)
    try:
        print("Verificando PID 3400 específico...")
        pid_check = subprocess.run("ps -p 3400", shell=True, capture_output=True, text=True)
        if pid_check.returncode == 0 and "3400" in pid_check.stdout:
            print("PID 3400 ainda está ativo, tentando encerrar...")
            subprocess.run("kill -15 3400", shell=True)
            time.sleep(2)
            # Tentar encerramento forçado se ainda estiver rodando
            subprocess.run("kill -9 3400 2>/dev/null || true", shell=True)
    except Exception as e:
        print(f"Erro ao verificar PID específico: {e}")
    
    # Remover arquivos de lock
    for lock_file in lock_files:
        if os.path.exists(lock_file):
            try:
                print(f"Removendo lock: {lock_file}")
                os.remove(lock_file)
            except Exception as e:
                print(f"Não foi possível remover {lock_file}: {e}")
                locks_cleared = False
    
    # Verificar se há processos de espera de lock
    try:
        fuser_output = subprocess.run("fuser /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock-frontend 2>/dev/null || true", 
                                     shell=True, capture_output=True, text=True)
        if fuser_output.stdout.strip():
            print(f"Ainda há processos usando locks: {fuser_output.stdout}")
            print("Tentando encerrar todos os processos relacionados...")
            subprocess.run("fuser -k /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock-frontend 2>/dev/null || true", 
                          shell=True)
            time.sleep(3)
    except Exception as e:
        print(f"Erro ao verificar fuser: {e}")
    
    # Tentar recuperar estado do dpkg
    try:
        print("Reconfigurando dpkg...")
        subprocess.run("dpkg --configure -a", shell=True)
    except Exception as e:
        print(f"Erro ao reconfigurar dpkg: {e}")
        locks_cleared = False
    
    return locks_cleared

def add_google_keys():
    """
    (REESCRITA) Baixa a chave pública *atual* do Google e cria os repositórios Chrome/Earth
    usando HTTPS e 'signed-by'. Tolera ausência de curl (usa wget como fallback) e
    evita deixar /etc/apt/keyrings/google.gpg vazio se o download falhar.
    """
    print("Adicionando chaves e repositórios do Google...")

    ensure_net_download_tools()

    keyring_dir = '/etc/apt/keyrings'
    os.makedirs(keyring_dir, exist_ok=True)
    google_keyring = os.path.join(keyring_dir, "google.gpg")

    # Se o keyring existir mas estiver muito pequeno, trata como corrompido
    try:
        if os.path.exists(google_keyring) and os.path.getsize(google_keyring) < 1024:
            print("Keyring do Google parece corrompido (muito pequeno). Removendo para recriar...")
            os.remove(google_keyring)
    except Exception:
        pass

    # Baixar chave oficial (bundle atual com chave primária 0xD38B4796 e subchaves rotativas)
    try:
        fetch_and_dearmor = (
            "(command -v curl >/dev/null 2>&1 && "
            " curl -fsSL 'https://dl.google.com/linux/linux_signing_key.pub' "
            " || wget -qO- 'https://dl.google.com/linux/linux_signing_key.pub')"
            " | gpg --dearmor > '/etc/apt/keyrings/google.gpg'"
        )
        subprocess.run(fetch_and_dearmor, shell=True, check=True)
        subprocess.run("chmod 0644 /etc/apt/keyrings/google.gpg", shell=True, check=True)
        print("Keyring do Google instalado/atualizado com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Falha ao instalar keyring do Google: {e}")
        return False

    # Recria listas com HTTPS e signed-by
    try:
        os.makedirs('/etc/apt/sources.list.d', exist_ok=True)
        with open('/etc/apt/sources.list.d/google-chrome.list', 'w') as f:
            f.write("deb [arch=amd64 signed-by=/etc/apt/keyrings/google.gpg] https://dl.google.com/linux/chrome/deb/ stable main\n")
        with open('/etc/apt/sources.list.d/google-earth.list', 'w') as f:
            f.write("deb [arch=amd64 signed-by=/etc/apt/keyrings/google.gpg] https://dl.google.com/linux/earth/deb stable main\n")
        print("Repositórios do Google configurados (HTTPS + signed-by).")
    except Exception as e:
        print(f"Erro ao escrever listas do Google: {e}")
        return False

    # Bypass opcional de proxy para dl.google.com
    try:
        with open('/etc/apt/apt.conf.d/99-google-direct', 'w') as f:
            f.write('Acquire::https::Proxy::dl.google.com "DIRECT";\n')
            f.write('Acquire::http::Proxy::dl.google.com  "DIRECT";\n')
        print("Bypass de proxy para dl.google.com aplicado (DIRECT).")
    except Exception as e:
        print(f"Aviso: não consegui gravar 99-google-direct: {e}")

    # Atualiza listas apenas para validar que a chave foi aceita
    try:
        subprocess.run(
            'apt update -o Acquire::https::Proxy::dl.google.com="DIRECT" '
            '-o Acquire::http::Proxy::dl.google.com="DIRECT"',
            shell=True, check=False
        )
    except Exception:
        pass

    return True


def fix_google_earth_lists():
    """
    (ATUALIZADA) Garante uma única lista do Google Earth com HTTPS e signed-by,
    removendo listas antigas/pro (http, sem chave, etc).
    """
    try:
        keyring = "/etc/apt/keyrings/google.gpg"
        os.makedirs("/etc/apt/sources.list.d", exist_ok=True)

        # Remove arquivos legacy conhecidos
        for legacy in ("/etc/apt/sources.list.d/google-earth-pro.list",
                       "/etc/apt/sources.list.d/google-earth-pro.list.save"):
            if os.path.exists(legacy):
                try:
                    os.remove(legacy)
                    print(f"Removido duplicado: {legacy}")
                except Exception as e:
                    print(f"Falha ao remover {legacy}: {e}")

        # Recria a lista oficial única com HTTPS
        earth_list = "/etc/apt/sources.list.d/google-earth.list"
        line = f"deb [arch=amd64 signed-by={keyring}] https://dl.google.com/linux/earth/deb stable main\n"
        with open(earth_list, "w") as f:
            f.write(line)
        os.chmod(earth_list, 0o644)
        print(f"Padronizado {earth_list} (HTTPS + signed-by).")
    except Exception as e:
        print(f"Erro em fix_google_earth_lists: {e}")


def clean_conflicting_kernels():
    """Remove pacotes de kernel que estão instalados com falha (status 'iF')."""
    print("\n======= LIMPANDO PACOTES DE KERNEL CONFLITANTES =======")
    
    try:
        # Listar todos os pacotes linux-image
        result = subprocess.run("dpkg -l | grep linux-image", shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Nenhum pacote linux-image encontrado.")
            return
        
        kernel_packages = result.stdout.strip().split('\n')
        packages_to_remove = []
        
        for pkg_line in kernel_packages:
            # Verificar se contém 'iF' (instalado com falha)
            pkg_parts = pkg_line.strip().split()
            if len(pkg_parts) >= 2 and pkg_parts[0] == 'iF':
                pkg_name = pkg_parts[1]
                packages_to_remove.append(pkg_name)
        
        if packages_to_remove:
            for pkg in packages_to_remove:
                print(f"Removendo pacote de kernel com falha: {pkg}")
                remove_cmd = f"apt remove --purge -y {pkg}"
                subprocess.run(remove_cmd, shell=True, check=False)
            
            print(f"Removidos {len(packages_to_remove)} pacotes de kernel com falha.")
        else:
            print("Nenhum pacote de kernel com falha encontrado.")
        
        # Verificar kernels instalados após limpeza
        print("\nKernels instalados após limpeza:")
        subprocess.run("dpkg -l | grep linux-image | grep ii", shell=True)
    
    except Exception as e:
        print(f"Erro ao limpar pacotes de kernel com falha: {e}")
    
    print("======= LIMPEZA DE KERNELS CONFLITANTES CONCLUÍDA =======")
   

def free_boot_space(min_free_mb=220):
    """
    Libera espaço em /boot removendo initrds de kernels que NÃO são o atual.
    Retorna True se /boot ficar com pelo menos 'min_free_mb' livres.
    """
    try:
        # espaço livre atual (em MB)
        out = subprocess.check_output("df -Pm /boot | awk 'NR==2{print $4}'", shell=True, text=True).strip()
        free_mb = int(out) if out.isdigit() else 0
        if free_mb >= min_free_mb:
            print(f"/boot OK (livre ~{free_mb} MB).")
            return True

        running = subprocess.check_output("uname -r", shell=True, text=True).strip()
        print(f"/boot com pouco espaço (~{free_mb} MB). Kernel atual: {running}")

        # remove initrds de kernels que não sejam o atual
        initrds = subprocess.check_output("ls -1 /boot/initrd.img-* 2>/dev/null || true", shell=True, text=True).strip().splitlines()
        removed = 0
        for path in initrds:
            ver = path.rsplit("initrd.img-", 1)[-1]
            if ver != running:
                print(f"Removendo initrd do kernel {ver} para abrir espaço...")
                subprocess.run(f"update-initramfs -d -k {ver}", shell=True, check=False)
                removed += 1

        # reavalia espaço
        out = subprocess.check_output("df -Pm /boot | awk 'NR==2{print $4}'", shell=True, text=True).strip()
        free_mb = int(out) if out.isdigit() else 0
        print(f"Após limpeza de initrds ({removed} removidos), /boot livre ~{free_mb} MB.")
        return free_mb >= min_free_mb
    except Exception as e:
        print(f"Aviso em free_boot_space: {e}")
        return False
    
def quarantine_b43_installer():
    """
    Remove e coloca em hold o firmware-b43-installer (e legacy),
    que está quebrando dpkg por checksum/proxy.
    """
    try:
        print("Quarentenando firmware-b43-installer...")
        subprocess.run("apt-get purge -y firmware-b43-installer firmware-b43legacy-installer", shell=True, check=False)
        subprocess.run("apt-mark hold firmware-b43-installer firmware-b43legacy-installer", shell=True, check=False)
        print("firmware-b43(-legacy) removidos/colocados em hold.")
    except Exception as e:
        print(f"Aviso em quarantine_b43_installer: {e}")

def tidy_chrome_off_file():
    """Renomeia .off para .list.disabled para parar o aviso do APT."""
    try:
        subprocess.run(
            "mv -f /etc/apt/sources.list.d/google-chrome.list.off "
            "/etc/apt/sources.list.d/google-chrome.list.disabled 2>/dev/null || true",
            shell=True, check=False
        )
    except Exception as e:
        print(f"Aviso em tidy_chrome_off_file: {e}")



def _parse_version_numbers(s: str):
    """Extrai tupla (major, minor, patch) de uma string de versão."""
    m = re.search(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?', s)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0))

def _is_at_least(cur: tuple, target: tuple):
    """Compara versões (major, minor, patch)."""
    return cur >= target

def get_chrome_version_tuple():
    """Retorna versão do Google Chrome como tupla (major, minor, patch)."""
    try:
        if shutil.which("google-chrome"):
            out = subprocess.check_output(["google-chrome", "--version"], text=True, stderr=subprocess.STDOUT)
        elif shutil.which("google-chrome-stable"):
            out = subprocess.check_output(["google-chrome-stable", "--version"], text=True, stderr=subprocess.STDOUT)
        else:
            return (0, 0, 0)
        # Ex.: "Google Chrome 139.0.XXXX.YYY"
        ver = re.search(r'Chrome\s+([\d\.]+)', out)
        return _parse_version_numbers(ver.group(1)) if ver else (0, 0, 0)
    except Exception:
        return (0, 0, 0)

def get_firefox_version_tuple():
    """Retorna versão do Firefox (prioriza ESR) como tupla."""
    candidates = []
    if shutil.which("firefox-esr"):
        candidates.append("firefox-esr")
    if shutil.which("firefox"):
        candidates.append("firefox")
    for binpath in candidates:
        try:
            out = subprocess.check_output([binpath, "--version"], text=True, stderr=subprocess.STDOUT)
            # Ex.: "Mozilla Firefox 128.3.1esr"
            ver = re.search(r'Firefox\s+([\d\.]+)', out)
            if ver:
                # Remove sufixo 'esr' se vier grudado
                vclean = re.sub(r'esr$', '', ver.group(1))
                return _parse_version_numbers(vclean)
        except Exception:
            continue
    return (0, 0, 0)

def step_upgrade_to(target_ver: int) -> bool:
    """
    Ajusta sources para o codinome do target_ver e roda a tua rotina de upgrade.
    """
    codename = codename_for_version(target_ver)
    if not codename:
        print(f"Versão alvo inválida: {target_ver}")
        return False

    print(f"\n=== Preparando upgrade para Debian {target_ver} ({codename}) ===")
    if not write_canonical_sources(codename):
        return False

    # Em releases antigas, dist-upgrade ajuda; tua rotina já usa upgrade/full-upgrade com auto-resposta.
    # Mantemos seus ganchos (locks, expect, assinador, etc.) dentro de run_upgrade_process().
    ok = run_upgrade_process()
    if not ok:
        print(f"[ERRO] Falha no upgrade para {target_ver} ({codename}).")
        return False

    # Verifica se realmente chegou lá
    cur = get_debian_version()
    print(f"[INFO] Versão após upgrade: {cur}")
    return cur == target_ver


def ensure_debian_stepwise_to_12() -> bool:
    """
    Se estiver no 9, faz 9→10→11→12. Se no 10, faz 10→11→12. Se no 11, faz 11→12.
    Se já no 12, apenas retorna True.
    """
    print("\n=== ensure_debian_stepwise_to_12 ===")

    # <<< garante que o prompt seja 'Sim' antes de qualquer salto
    ensure_auto_restart_services_yes()

    cur = get_debian_version()
    if cur is None:
        print("Não foi possível detectar a versão do Debian.")
        return False

    if cur > 12:
        print("Sistema já acima do Debian 12. Nada a fazer.")
        return True

    for target in (10, 11, 12):
        if cur < target:
            # <<< reforça antes de cada etapa (idempotente e seguro)
            ensure_auto_restart_services_yes()

            if not step_upgrade_to(target):
                # tenta novamente uma vez com limpeza + update
                check_and_clear_apt_locks()
                auto_respond_command("apt update", timeout=600)
                # reforça de novo por garantia
                ensure_auto_restart_services_yes()
                if not step_upgrade_to(target):
                    return False
            cur = get_debian_version() or cur

    return get_debian_version() == 12


def download_chrome_deb_resume(dest: str, tries: int = 8) -> bool:
    """
    Baixa o pacote do Chrome com retomada (-c) e limites que evitam drops
    em links instáveis/filtrados. Retorna True se o .deb final tiver >110MB.
    """
    url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    for i in range(1, tries + 1):
        print(f"Baixando (tentativa {i}/{tries}) {url} com retomada…")
        cmd = (
            f"wget --no-proxy --inet4-only --continue "
            f"--timeout=45 --read-timeout=45 --tries=2 --waitretry=5 --retry-connrefused "
            f"--no-http-keep-alive --limit-rate=300k --progress=dot:giga "
            f"-O '{dest}' '{url}'"
        )
        rc = subprocess.run(cmd, shell=True).returncode
        # Tamanho esperado ~118MB; considera ok >=110MB
        try:
            if rc == 0 and os.path.exists(dest) and os.path.getsize(dest) > 110 * 1024 * 1024:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False

def disable_dl_google_lists():
    """
    Desabilita listas do Chrome/Earth para evitar 'apt update' travar no dl.google.com.
    Retorna um dicionário com o que foi desabilitado para possível reativação.
    """
    changed = {}
    pairs = [
        ("/etc/apt/sources.list.d/google-chrome.list", "/etc/apt/sources.list.d/google-chrome.list.disabled"),
        ("/etc/apt/sources.list.d/google-earth.list",  "/etc/apt/sources.list.d/google-earth.list.disabled"),
        ("/etc/apt/sources.list.d/google-earth-pro.list", "/etc/apt/sources.list.d/google-earth-pro.list.disabled"),
    ]
    for src, dst in pairs:
        try:
            if os.path.exists(src):
                shutil.move(src, dst)
                print(f"Desabilitado: {src} -> {dst}")
                changed[dst] = src   # mapeia inverso para reativação
        except Exception as e:
            print(f"Aviso ao desabilitar {src}: {e}")
    return changed

def enable_dl_google_lists(changed_map: dict):
    """Reativa listas que foram desabilitadas por disable_dl_google_lists()."""
    for disabled, original in (changed_map or {}).items():
        try:
            if os.path.exists(disabled):
                shutil.move(disabled, original)
                print(f"Reativado: {disabled} -> {original}")
        except Exception as e:
            print(f"Aviso ao reativar {disabled}: {e}")


def install_chrome_stable_quick(reenable: bool = False) -> bool:
    """
    Instala RAPIDAMENTE o Chrome estável disponível:
      - desabilita listas do Google (evita travar em 'InRelease')
      - baixa o stable_current_amd64.deb direto (canal estável)
      - instala com dpkg e corrige deps
      - opcionalmente reativa listas no final
    """
    print("\n=== Instalação rápida do Chrome estável (canal stable) ===")
    changed = disable_dl_google_lists()
    env = os.environ.copy(); env["DEBIAN_FRONTEND"] = "noninteractive"

    deb = "/tmp/google-chrome-stable_current_amd64.deb"
    if not _download_chrome_deb_via_resolve(deb, tries_per_ip=2, total_rounds=2):
        print("Falha no download direto do .deb do Chrome (mesmo com resolve).")
        # último recurso: wget -c
        if not download_chrome_deb_resume(deb, tries=4):
            print("Falha também com wget -c.")
            if reenable:
                enable_dl_google_lists(changed)
            return False

    ok = auto_respond_command(
        f"dpkg -i '{deb}' || apt-get -f install -y",
        env=env, timeout=1200, log_path=CHROME_LOG
    )
    if not ok:
        print("dpkg/apt não conseguiu concluir a instalação do Chrome.")
        if reenable:
            enable_dl_google_lists(changed)
        return False

    # Verifica versão instalada (qualquer estável serve)
    cur = get_chrome_version_tuple()
    if cur == (0, 0, 0):
        print("Chrome não foi detectado após a instalação.")
        if reenable:
            enable_dl_google_lists(changed)
        return False

    print(f"[OK] Chrome instalado/atualizado para {cur} (canal estável).")
    if reenable:
        enable_dl_google_lists(changed)
    return True


def ensure_firefox_esr_min_128():
    """
    Garante Firefox ESR com major >= 128 (padrão do Debian 12).
    Instala firefox-esr e força atualização se necessário.
    """
    target = (128, 0, 0)
    tries = 0

    while True:
        cur = get_firefox_version_tuple()
        if _is_at_least(cur, target):
            print(f"[OK] Firefox (ESR) >= 128 já presente (atual: {cur}).")
            return True

        tries += 1
        print(f"[{tries}] Firefox atual {cur}, alvo >= {target}. Instalando/atualizando firefox-esr...")

        check_and_clear_apt_locks()
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"

        # Em Debian 12 o pacote certo é firefox-esr
        auto_respond_command("apt update", env=env, timeout=600)
        # Se tiver 'firefox' genérico instalado que atrapalhe, tenta remover
        auto_respond_command("apt remove -y firefox || true", env=env, timeout=600)
        auto_respond_command("apt install -y --reinstall firefox-esr", env=env, timeout=1200)
        auto_respond_command("apt -y full-upgrade", env=env, timeout=1800)

        time.sleep(3)
        cur = get_firefox_version_tuple()
        if _is_at_least(cur, target):
            print(f"[OK] Firefox atualizado para {cur}.")
            return True

def apply_keep_conffiles_policy():
    """
    Força dpkg/apt a manter SEMPRE os arquivos de configuração locais (conffiles).
    - dpkg: /etc/dpkg/dpkg.cfg.d/90-keep-old
    - apt : /etc/apt/apt.conf.d/90keep-old-conffiles
    """
    try:
        # dpkg: vale inclusive para 'dpkg --configure -a'
        dpkg_dir = "/etc/dpkg/dpkg.cfg.d"
        os.makedirs(dpkg_dir, exist_ok=True)
        dpkg_cfg = os.path.join(dpkg_dir, "90-keep-old")
        with open(dpkg_cfg, "w") as f:
            f.write("# manter sempre configs locais\n")
            f.write("force-confdef\n")
            f.write("force-confold\n")
        os.chmod(dpkg_cfg, 0o644)
        print(f"dpkg cfg aplicado: {dpkg_cfg}")

        # apt: vale para apt/apt-get
        apt_dir = "/etc/apt/apt.conf.d"
        os.makedirs(apt_dir, exist_ok=True)
        apt_cfg = os.path.join(apt_dir, "90keep-old-conffiles")
        with open(apt_cfg, "w") as f:
            f.write('Dpkg::Options {\n')
            f.write('  "--force-confdef";\n')
            f.write('  "--force-confold";\n')
            f.write('};\n')
            f.write('APT::Get::Assume-Yes "true";\n')
        os.chmod(apt_cfg, 0o644)
        print(f"apt cfg aplicado: {apt_cfg}")

        return True
    except Exception as e:
        print(f"Aviso em apply_keep_conffiles_policy: {e}")
        return False

def _get_dlgoogle_ipv4_list(max_ips: int = 8):
    """
    Resolve IPv4 de dl.google.com e devolve lista única, limitada.
    Assim evitamos bater sempre no mesmo IP ruim.
    """
    try:
        out = subprocess.check_output(
            "getent ahostsv4 dl.google.com | awk '{print $1}' | sort -u",
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip().splitlines()
        # ordem estável, mas rotaciona um pouco para não grudar no primeiro
        ips = [ip for ip in out if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip)]
        return ips[:max_ips] if ips else []
    except Exception:
        return []


def _download_chrome_deb_via_resolve(dest: str, tries_per_ip: int = 2, total_rounds: int = 3) -> bool:
    """
    Baixa o .deb do Chrome forçando conexões a *vários* IPs de dl.google.com
    com 'curl --resolve', retomada (-C -) e limites para redes sensíveis.
    Retorna True se o arquivo final tiver tamanho > 110 MB.
    """
    url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    # Garante ferramentas de rede
    ensure_net_download_tools()

    # Lista de IPs candidatos (pega agora e reusa)
    ip_list = _get_dlgoogle_ipv4_list()
    if not ip_list:
        # fallback: vai tentar sem --resolve mesmo
        ip_list = [""]  # uma entrada vazia significa "sem resolve"

    # Opções conservadoras (sem estilo agressivo)
    base_opts = [
        "-fL",                 # falha em HTTP >= 400 e segue redirecionamentos
        "-C", "-",             # retoma download
        "--retry", "2",
        "--retry-delay", "4",
        "--connect-timeout", "20",
        "--max-time", "1200",
        "--http1.1",           # evita alguns middleboxes
        "--tlsv1.2",
        "--speed-time", "40",  # se ficar lento demais por 40s...
        "--speed-limit", "60000",  # ...< ~60 KB/s aborta e tenta de novo
        "--no-progress-meter"
    ]

    rounds_done = 0
    while rounds_done < total_rounds:
        rounds_done += 1
        for ip in ip_list:
            if ip:
                resolve_opt = ["--resolve", f"dl.google.com:443:{ip}"]
                label = f"via {ip}"
            else:
                resolve_opt = []
                label = "sem --resolve"

            for t in range(1, tries_per_ip + 1):
                print(f"Baixando {label} (tentativa {t}/{tries_per_ip})…")
                cmd = ["bash", "-lc",
                       " ".join(["curl"] + base_opts + resolve_opt + ["-o", f"'{dest}'", f"'{url}'"])]
                rc = subprocess.run(cmd).returncode
                try:
                    if os.path.exists(dest) and os.path.getsize(dest) > 110 * 1024 * 1024:
                        return True
                except Exception:
                    pass
                time.sleep(2)

    return False

def install_google_earth_stable_quick(reenable: bool = False) -> bool:
    """
    Instala RAPIDAMENTE o Google Earth (canal stable) sem depender do APT do Google:
      - desabilita as listas do Google (evita travas em InRelease)
      - baixa o .deb direto com retomada
      - instala com dpkg e corrige dependências
      - não reativa as listas por padrão (reenable=False)
    """
    print("\n=== Instalação rápida do Google Earth (stable) ===")
    changed = disable_dl_google_lists()
    env = os.environ.copy(); env["DEBIAN_FRONTEND"] = "noninteractive"

    url = "https://dl.google.com/dl/linux/direct/google-earth-pro-stable_current_amd64.deb"
    deb = "/tmp/google-earth-pro-stable_current_amd64.deb"

    ensure_net_download_tools()

    ok_dl = False
    for i in range(1, 5):
        print(f"Baixando (tentativa {i}/4) {url} …")
        cmd = (
            f"wget --no-proxy --inet4-only --continue "
            f"--timeout=45 --read-timeout=45 --tries=2 --waitretry=5 --retry-connrefused "
            f"--no-http-keep-alive --limit-rate=300k --progress=dot:giga "
            f"-O '{deb}' '{url}'"
        )
        rc = subprocess.run(cmd, shell=True).returncode
        try:
            # Earth ~90–100 MB; considera OK >= 80 MB
            if rc == 0 and os.path.exists(deb) and os.path.getsize(deb) > 80 * 1024 * 1024:
                ok_dl = True
                break
        except Exception:
            pass
        time.sleep(2)

    if not ok_dl:
        print("Falha ao baixar o .deb do Google Earth.")
        if reenable:
            enable_dl_google_lists(changed)
        return False

    ok = auto_respond_command(
        f"dpkg -i '{deb}' || apt-get -f install -y",
        env=env, timeout=1200, log_path=EARTH_LOG
    )

    if shutil.which("google-earth-pro"):
        print("[OK] Google Earth instalado/atualizado (stable).")
    else:
        print("Google Earth não foi detectado após a instalação.")

    if reenable:
        enable_dl_google_lists(changed)
    return ok

def install_assinador_no_autostart() -> bool:
    """
    Instala 'assinador-serpro' sem permitir start/enable automático:
      - usa DEBIAN_FRONTEND=noninteractive e confold
      - cria /usr/sbin/policy-rc.d (exit 101) para bloquear start
      - ao final, remove policy-rc.d e desabilita/para quaisquer units 'assinador*'
    """
    import os, subprocess, stat

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    policy = "/usr/sbin/policy-rc.d"
    created_policy = False

    try:
        # Bloqueia start/stop/restart de serviços durante a instalação
        content = "#!/bin/sh\n# Bloquear start automático durante instalação\nexit 101\n"
        with open(policy, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(policy, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                          stat.S_IRGRP | stat.S_IXGRP |
                          stat.S_IROTH | stat.S_IXOTH)
        created_policy = True

        # Instala preservando conffiles locais e sem prompts
        cmd = [
            "apt-get",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
            "-y", "install", "assinador-serpro",
        ]
        print(f"[INFO] Instalando assinador-serpro sem autostart: {' '.join(cmd)}")
        r = subprocess.run(cmd, env=env)
        if r.returncode != 0:
            print(f"[ERRO] Falha ao instalar assinador-serpro (rc={r.returncode}).")
            return False

    finally:
        # Remove o bloqueio de start automático
        if created_policy:
            try:
                os.remove(policy)
            except Exception:
                pass

    # Garantir que não ficou habilitado/rodando
    hard_disable_cmds = [
        "systemctl daemon-reload || true",
        # nomes comuns
        "systemctl disable --now assinador-serpro.service 2>/dev/null || true",
        "systemctl disable --now assinador-serpro 2>/dev/null || true",
        # varredura por padrão
        "for u in $(systemctl list-unit-files 'assinador*' --no-legend 2>/dev/null | awk '{print $1}'); do "
        "  systemctl disable --now \"$u\" 2>/dev/null || true; "
        "done",
    ]
    for c in hard_disable_cmds:
        subprocess.run(["bash", "-lc", c], env=env)

    print("[OK] Assinador instalado sem autostart e com serviços desabilitados.")
    return True

def try_repair_assinador_serpro() -> bool:
    """
    Purga e recompõe chave/repo do SERPRO e reinstala o pacote,
    garantindo que NÃO inicie automaticamente.
    """
    import os, subprocess, glob

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    print("\n[INFO] Tentando reparar repositório/pacote Assinador SERPRO...")

    # 1) Remover pacote (ignorar erro)
    subprocess.run(["apt-get", "-y", "purge", "assinador-serpro"], env=env)

    # 2) Remover listas antigas relacionadas ao SERPRO
    for path in glob.glob("/etc/apt/sources.list.d/*serpro*.list"):
        try:
            os.remove(path)
            print(f"[INFO] Removido: {path}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[AVISO] Não foi possível remover {path}: {e}")

    # 3) (Re)instalar a chave pública
    url = "https://assinadorserpro.estaleiro.serpro.gov.br/repository/AssinadorSERPROpublic.asc"
    cmd_key = (
        "bash -lc 'set -e; "
        f'if command -v curl >/dev/null; then curl -fsSL \"{url}\"; '
        f'else wget -qO- \"{url}\"; fi '
        "| tee /etc/apt/trusted.gpg.d/AssinadorSERPROpublic.asc >/dev/null'"
    )
    r = subprocess.run(cmd_key, shell=True, env=env)
    if r.returncode != 0:
        print("[ERRO] Falha ao baixar/instalar chave do SERPRO.")
        return False

    # 4) Recriar a lista do repositório (com signed-by)
    try:
        with open("/etc/apt/sources.list.d/assinador-serpro.list", "w", encoding="utf-8") as f:
            f.write(
                "deb [signed-by=/etc/apt/trusted.gpg.d/AssinadorSERPROpublic.asc] "
                "https://assinadorserpro.estaleiro.serpro.gov.br/repository universal stable\n"
            )
    except Exception as e:
        print(f"[ERRO] Não foi possível escrever a lista do repositório do SERPRO: {e}")
        return False

    # 5) apt update (aceitando mudanças de Release Info)
    upd = [
        "apt-get",
        "-o", "Acquire::AllowReleaseInfoChange::Suite=true",
        "-o", "Acquire::AllowReleaseInfoChange::Codename=true",
        "-o", "Acquire::AllowReleaseInfoChange::Label=true",
        "-o", "Acquire::AllowReleaseInfoChange::Origin=true",
        "update",
    ]
    r = subprocess.run(upd, env=env)
    if r.returncode != 0:
        print("[ERRO] apt-get update ainda falhou após reparar SERPRO.")
        return False

    # 6) Reinstalar o pacote SEM AUTOSTART
    if not install_assinador_no_autostart():
        print("[ERRO] Falha ao reinstalar assinador-serpro sem autostart.")
        return False

    print("[OK] Repositório e pacote Assinador SERPRO reparados (sem autostart).")
    return True


def run_quick_update_12() -> bool:
    """
    Caminho rápido para Debian 12:
    - pré-seed do Assinador (autostart=false)
    - aceita mudanças de Release Info
    - apt-get update/upgrade/autoremove via auto_respond_command (enable expect)
    """
    import os, subprocess

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
    env["APT_LISTCHANGES_FRONTEND"] = "none"
    env["DEBIAN_PRIORITY"] = "critical"
    env["TERM"] = "dumb"

    # >>> garante que o Assinador venha com autostart desabilitado
    preconfigure_assinador()
    ensure_auto_restart_services_yes()

    try:
        if "disable_dl_google_lists" in globals():
            disable_dl_google_lists()
    except Exception:
        pass

    try:
        if "allow_releaseinfo_change" in globals():
            allow_releaseinfo_change()
    except Exception:
        pass

    # update (com allow release info) via auto_respond_command
    print("\nExecutando: apt-get update (allow ReleaseInfoChange)")
    ok = auto_respond_command(
        "apt-get -o Acquire::AllowReleaseInfoChange::Suite=true "
        "-o Acquire::AllowReleaseInfoChange::Codename=true "
        "-o Acquire::AllowReleaseInfoChange::Label=true "
        "-o Acquire::AllowReleaseInfoChange::Origin=true "
        "update",
        env=env, timeout=900
    )
    if not ok:
        print("[AVISO] apt-get update falhou. Tentando reparar Assinador SERPRO e repetir...")
        if not try_repair_assinador_serpro():
            print("[ERRO] Reparação do Assinador SERPRO falhou.")
            return False
        ok = auto_respond_command(
            "apt-get -o Acquire::AllowReleaseInfoChange::Suite=true "
            "-o Acquire::AllowReleaseInfoChange::Codename=true "
            "-o Acquire::AllowReleaseInfoChange::Label=true "
            "-o Acquire::AllowReleaseInfoChange::Origin=true "
            "update",
            env=env, timeout=900
        )
        if not ok:
            print("[ERRO] apt-get update ainda falhou.")
            return False

    # upgrade (via auto_respond_command para interceptar diálogos)
    print("\nExecutando: apt-get upgrade -y")
    ok = auto_respond_command(
        "apt-get -o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold -y upgrade",
        env=env, timeout=1800
    )
    if not ok:
        print("[ERRO] Falha no upgrade.")
        return False

    # autoremove (também via auto_respond_command)
    print("\nExecutando: apt-get autoremove --purge -y")
    ok = auto_respond_command("apt-get -y autoremove --purge", env=env, timeout=900)
    if not ok:
        print("[ERRO] Falha no autoremove.")
        return False

    print("\n[OK] Atualização rápida do Debian 12 concluída (com auto-resposta 'Não' para o Assinador).")
    return True


def finalize_python3_stack_post12():
    """
    Repara/configura a pilha Python3 no Debian 12 quando 'python3' ficou
    parcialmente instalado e N pacotes ficaram 'desconfigurados'.
    """
    import os, shutil, subprocess
    print("\n=== Reparando stack Python3 pós-upgrade (Debian 12) ===")
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["NEEDRESTART_MODE"] = "a"

    cmds = [
        "dpkg --configure -a",
        "apt-get -f install -y",
        # base Python 3.11 do bookworm
        "apt-get install -y --reinstall "
        "python3-minimal python3.11-minimal libpython3.11-minimal "
        "libpython3.11-stdlib libpython3.11",
        "apt-get install -y --reinstall python3 python3.11",
        # configura tudo e corrige dependências
        "dpkg --configure -a",
        "apt-get -f install -y",
        # tenta reconfigurar os que comumente ficam na lista de erro
        "apt-get install -y --reinstall python3-websockets python3-pyxattr || true",
        # convergir
        "apt -y full-upgrade",
        "apt-get autoremove --purge -y",
        "apt-get clean",
    ]

    for c in cmds:
        try:
            auto_respond_command(c, env=env, timeout=1200)
        except Exception as e:
            print(f"[WARN] '{c}' falhou: {e}")

    # Plano B: se /usr/bin/python3 sumiu mas 3.11 existe, cria apontador (emergencial)
    try:
        if not shutil.which("python3") and os.path.exists("/usr/bin/python3.11"):
            subprocess.run("ln -sf /usr/bin/python3.11 /usr/bin/python3", shell=True)
            print("[OK] Symlink emergencial /usr/bin/python3 -> python3.11 aplicado.")
    except Exception as e:
        print(f"[WARN] Não consegui aplicar symlink emergencial: {e}")

    # Sanidade
    try:
        out = subprocess.check_output("python3 -V 2>&1 || true", shell=True, text=True).strip()
        print(f"[INFO] python3: {out}")
    except Exception:
        pass

    try:
        rc = subprocess.run("apt-get check", shell=True).returncode
        print("[INFO] apt-get check rc=", rc)
    except Exception:
        pass

    print("=== Fim do reparo da pilha Python3 ===")
    return True



def ensure_utf8_locale_persist():
    try:
        subprocess.run("sed -i 's/^# *pt_BR.UTF-8/pt_BR.UTF-8/' /etc/locale.gen", shell=True)
        with open("/etc/default/locale", "w") as f:
            f.write("LANG=pt_BR.UTF-8\nLC_ALL=pt_BR.UTF-8\n")
        subprocess.run("locale-gen", shell=True)
        subprocess.run("update-locale LANG=pt_BR.UTF-8 LC_ALL=pt_BR.UTF-8", shell=True)
        subprocess.run("localectl set-locale LANG=pt_BR.UTF-8", shell=True)
        print("[OK] Locale UTF-8 garantido (pt_BR.UTF-8).")
    except Exception as e:
        print(f"[AVISO] ensure_utf8_locale_persist: {e}")

def ensure_hostname_hosts_consistency():
    try:
        h = subprocess.check_output("hostname", shell=True, text=True).strip() or "debian"
        if h in ("localhost",):
            subprocess.run("hostnamectl set-hostname debian", shell=True, check=False)
            h = "debian"
        try:
            with open("/etc/hosts") as f:
                hosts = f.read()
        except FileNotFoundError:
            hosts = ""
        if f"127.0.1.1 {h}" not in hosts:
            with open("/etc/hosts", "a") as f:
                f.write(f"127.0.1.1 {h}\n")
            print("[OK] /etc/hosts: 127.0.1.1 -> hostname atualizado.")
    except Exception as e:
        print(f"[AVISO] ensure_hostname_hosts_consistency: {e}")

def ensure_network_online_wait():
    try:
        subprocess.run("systemctl enable --now NetworkManager 2>/dev/null || true", shell=True)
        subprocess.run("systemctl enable --now NetworkManager-wait-online.service 2>/dev/null || true", shell=True)
        print("[OK] NetworkManager + wait-online habilitados.")
    except Exception as e:
        print(f"[AVISO] ensure_network_online_wait: {e}")

def create_hostip_widget_post_upgrade():
    """
    Cria /usr/local/bin/pmjs-hostip.sh e, se houver XFCE, adiciona o plugin genmon no painel
    para mostrar 'hostname: IP' perto do relógio.
    """
    import pwd

    ensure_utf8_locale_persist()
    ensure_hostname_hosts_consistency()
    ensure_network_online_wait()

    # 1) Script que o painel chama para renderizar o texto (serve para qualquer DE)
    script_path = "/usr/local/bin/pmjs-hostip.sh"
    script_body = r"""#!/bin/bash
h="$(hostname)"
ip="$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}')"
if [ -z "$ip" ]; then
  ip="$(ip -4 -br addr show up scope global | awk '{print $3}' | cut -d/ -f1 | head -n1)"
fi
[ -z "$ip" ] && ip="sem IP"
printf '<txt>%s</txt>\n' "$h: $ip"
printf '<tool>Hostname: %s\nIPv4: %s\n%s</tool>\n' "$h" "$ip" "$(date '+%d/%m %H:%M')"
"""
    try:
        with open(script_path, "w") as f:
            f.write(script_body)
        os.chmod(script_path, 0o755)
        print(f"[OK] Criado {script_path}")
    except Exception as e:
        print(f"[AVISO] Não foi possível criar {script_path}: {e}")

    # 2) Se XFCE estiver disponível, preparo autoconfig do genmon pelo login gráfico
    if shutil.which("xfconf-query") and shutil.which("xfce4-panel"):
        # instala o plugin genmon se não existir
        env = os.environ.copy(); env["DEBIAN_FRONTEND"] = "noninteractive"
        subprocess.run("apt-get install -y xfce4-genmon-plugin", shell=True, env=env)

        # descobre o usuário "de verdade" (não root)
        user = os.environ.get("SUDO_USER") or os.environ.get("PKEXEC_UID")
        if not user:
            try:
                user = subprocess.check_output("logname", shell=True, text=True).strip()
            except Exception:
                user = os.environ.get("USER", "root")

        try:
            pw = pwd.getpwnam(user)
            home = pw.pw_dir
        except Exception:
            home = f"/home/{user}"

        setup_sh = "/usr/local/sbin/pmjs-setup-xfce-hostip.sh"
        setup_body = r'''#!/bin/bash
set -e
marker="$HOME/.config/.pmjs_hostip_widget_installed"
if [ -f "$marker" ]; then exit 0; fi

panel="panel-1"
if ! xfconf-query -c xfce4-panel -p "/panels/$panel" >/dev/null 2>&1; then
  first=$(xfconf-query -c xfce4-panel -l | awk -F/ '/^\/panels\/panel-/{print $3; exit}')
  [ -n "$first" ] && panel="$first"
fi

# Próximo plugin-id livre
max=0
while read -r p; do
  id="${p##*plugin-}"; id="${id%%/*}"
  [[ "$id" =~ ^[0-9]+$ ]] && [ "$id" -gt "$max" ] && max="$id"
done < <(xfconf-query -c xfce4-panel -l | grep '^/plugins/plugin-') || true
new=$((max+1))

# Cria plugin genmon
xfconf-query -c xfce4-panel -p "/plugins/plugin-$new/type" -n -t string -s genmon
xfconf-query -c xfce4-panel -p "/plugins/plugin-$new/command" -n -t string -s "/usr/local/bin/pmjs-hostip.sh"
xfconf-query -c xfce4-panel -p "/plugins/plugin-$new/period" -n -t int -s 4
xfconf-query -c xfce4-panel -p "/plugins/plugin-$new/use-markup" -n -t bool -s true

# Anexa aos plugins do painel
mapfile -t ids < <(xfconf-query -c xfce4-panel -p "/panels/$panel/plugin-ids" 2>/dev/null | tr -d '[]' | tr ',' '\n' | sed '/^$/d')
args=()
for id in "${ids[@]}"; do args+=(-t int -s "$id"); done
args+=(-t int -s "$new")
xfconf-query -c xfce4-panel -p "/panels/$panel/plugin-ids" --create --force-array "${args[@]}"

# Reinicia o painel
xfce4-panel -r || true

mkdir -p "$(dirname "$marker")"
date > "$marker"
exit 0
'''
        try:
            with open(setup_sh, "w") as f:
                f.write(setup_body)
            os.chmod(setup_sh, 0o755)

            # Autostart no login gráfico do usuário (garante DISPLAY/DBus prontos)
            autostart_dir = os.path.join(home, ".config", "autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            desktop_path = os.path.join(autostart_dir, "pmjs-hostip-setup.desktop")
            with open(desktop_path, "w") as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name=PMJS Host/IP Widget Setup
Exec={setup_sh}
X-GNOME-Autostart-enabled=true
OnlyShowIn=XFCE;
""")
            import pwd, grp, os as _os
            try:
                pw = pwd.getpwnam(user)
                uid, gid = pw.pw_uid, pw.pw_gid
                _os.chown(autostart_dir, uid, gid)
                _os.chown(desktop_path, uid, gid)
            except Exception:
                pass

            print("[OK] XFCE detectado: widget será criado/ajustado automaticamente no próximo login gráfico.")
        except Exception as e:
            print(f"[AVISO] Não foi possível preparar autoconfig do XFCE: {e}")
    else:
        print("[INFO] XFCE não detectado — use /usr/local/bin/pmjs-hostip.sh com o widget do seu painel (ex.: genmon/Conky).")

def ensure_auto_restart_services_yes() -> bool:
    """
    Faz preseed em Debconf e configura o needrestart para reiniciar serviços
    automaticamente durante upgrades (responde 'Sim' ao prompt).
    """
    try:
        import tempfile, re

        # 1) Preseed do Debconf (templates clássicos usados por libc6/libraries)
        seeds = [
            "libc6 libraries/restart-without-asking boolean true",
            "libc6:amd64 libraries/restart-without-asking boolean true",
            "libraries/restart-without-asking boolean true",
        ]
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("\n".join(seeds) + "\n")
            seed_path = tf.name
        subprocess.run(f"debconf-set-selections {seed_path}", shell=True, check=False)

        # 2) Forçar APT/Dpkg a não parar em conffiles
        os.makedirs("/etc/apt/apt.conf.d", exist_ok=True)
        with open("/etc/apt/apt.conf.d/90auto-restart", "w") as f:
            f.write('Dpkg::Options {"--force-confdef";"--force-confold";};\n')
            f.write('APT::Get::Assume-Yes "true";\n')

        # 3) needrestart: reinício automático ('a' = auto)
        os.makedirs("/etc/needrestart", exist_ok=True)
        cfg = "/etc/needrestart/needrestart.conf"
        desired = "$nrconf{restart} = 'a';\n"
        try:
            if os.path.exists(cfg):
                content = open(cfg, "r", encoding="utf-8", errors="replace").read()
                if re.search(r"\$nrconf\{restart\}\s*=\s*'[^']+';", content):
                    content = re.sub(r"\$nrconf\{restart\}\s*=\s*'[^']+';", desired.strip(), content)
                else:
                    content = content.rstrip() + "\n" + desired
                open(cfg, "w").write(content)
            else:
                open(cfg, "w").write("# auto-configured by updater\n" + desired)
        except Exception:
            pass

        print("[OK] Configurado para reiniciar serviços automaticamente (responder 'Sim').")
        return True
    except Exception as e:
        print(f"[AVISO] ensure_auto_restart_services_yes falhou: {e}")
        return False

# ================== POPUP GUI (MATE) – ZENITY via FIFO (robusto) ==================

import os, re, shlex, subprocess, time, shutil

# estado global do UI
_POP = globals().get("_POP", {
    "env": {},
    "user": None,
    "uid": None,
    "writer": None,
    "pidfile": "/run/pmjs-upgrade-ui.pid",
    "fifo": "/run/pmjs-upgrade-ui.fifo",
    "display": ":0",
    "started": False,
    "use": None,            # "yad" | "zenity"
    "banner": ""
})

def _run(cmd, **kw):
    return subprocess.run(cmd, shell=True, **kw)

def _find_active_gui_session():
    """
    Descobre a sessão gráfica ativa (usuario, uid, display) usando systemd/loginctl.
    Retorna dict {'user','uid','display'} ou None.
    """
    # 1) loginctl (melhor fonte)
    try:
        out = subprocess.check_output(
            "loginctl list-sessions --no-legend", shell=True, text=True, stderr=subprocess.STDOUT
        ).strip().splitlines()
        for line in out:
            parts = re.split(r"\s+", line.strip())
            if not parts:
                continue
            sess_id = parts[0]
            # pega propriedades com nomes estáveis
            show = subprocess.check_output(
                f"loginctl show-session {shlex.quote(sess_id)} "
                "-p Active -p Type -p Display -p Remote -p User -p Name",
                shell=True, text=True, stderr=subprocess.STDOUT
            )
            kv = {}
            for s in show.strip().splitlines():
                if "=" in s:
                    k, v = s.split("=", 1)
                    kv[k] = v
            if kv.get("Active") != "yes":
                continue
            if kv.get("Remote") == "yes":
                continue
            # user "Name" = login, "User" = uid numérico
            user = kv.get("Name") or ""
            uid  = int(kv.get("User") or "0")
            if not user or user == "root" or uid <= 0:
                continue
            disp = kv.get("Display") or ":0"
            # sanity: existe um processo de sessão MATE?
            try:
                _ = subprocess.check_output(
                    f"pgrep -u {shlex.quote(user)} -f '(^|/)mate-session'", shell=True, text=True
                )
            except subprocess.CalledProcessError:
                # tudo bem — ainda assim tentamos
                pass
            return {"user": user, "uid": uid, "display": disp}
    except Exception:
        pass

    # 2) fallback: quem está no VT gráfico
    try:
        who = subprocess.check_output("who | awk 'NR==1{print $1}'", shell=True, text=True).strip()
        if who and who != "root":
            uid = int(subprocess.check_output(f"id -u {shlex.quote(who)}", shell=True, text=True).strip())
            return {"user": who, "uid": uid, "display": ":0"}
    except Exception:
        pass
    return None

def _run_as_user(user, cmd, extra_env=None, detach=False):
    """
    Executa 'cmd' como o usuário gráfico, exportando DISPLAY/DBUS/XDG_RUNTIME_DIR.
    """
    uid = int(subprocess.check_output(f"id -u {shlex.quote(user)}", shell=True, text=True).strip())
    xdg = f"/run/user/{uid}"
    envparts = {
        "DISPLAY": _POP["display"] or ":0",
        "XDG_RUNTIME_DIR": xdg,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={xdg}/bus",
        "GDK_BACKEND": "x11",
    }
    if extra_env:
        envparts.update(extra_env)
    exports = " ".join([f"{k}={shlex.quote(str(v))}" for k, v in envparts.items() if v])

    if detach:
        # setsid + nohup, sem herdar terminal
        wrapped = f"{exports} setsid bash -lc {shlex.quote(cmd)} </dev/null >/dev/null 2>&1 &"
    else:
        wrapped = f"{exports} bash -lc {shlex.quote(cmd)}"

    return _run(f"runuser -u {shlex.quote(user)} -- bash -lc {shlex.quote(wrapped)}")

def start_upgrade_ui_zenity_progress(initial_text=None, title="ATUALIZAÇÃO REMOTA"):
    """
    Abre uma janela zenity --progress grande no DESKTOP DO USUÁRIO (não como root),
    recebendo atualizações via FIFO. Guarda um writer global em _POP["writer"].
    """
    sess = _find_active_gui_session()
    if not sess:
        print("[AVISO] Sessão gráfica não encontrada; popup não será exibido.")
        return False

    _POP["user"] = sess["user"]
    _POP["uid"] = sess["uid"]
    _POP["display"] = sess["display"]

    # banner fixo (com markup)
    _POP["banner"] = 'NÃO DESLIGUE O PC!              Atualização remota em andamento…'

    # prepara diretório e fifo
    fifo = _POP["fifo"]
    try:
        os.makedirs(os.path.dirname(fifo), exist_ok=True)
        if os.path.exists(fifo):
            try:
                os.remove(fifo)
            except Exception:
                pass
        os.mkfifo(fifo, 0o666)
        os.chmod(fifo, 0o666)
    except Exception as e:
        print(f"[AVISO] não consegui criar FIFO: {e}")
        return False

    # texto inicial = banner + (opcional) complemento
    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    extra = _esc(initial_text) if initial_text else None
    initial_markup = _POP["banner"] if not extra else f'{_POP["banner"]}\n{extra}'

    # <<< PREPARA STRINGS ESCAPADAS (sem barras dentro do f-string) >>>
    safe_title = title.replace('"', r'\"')
    safe_text  = initial_markup.replace('"', r'\"')

    cmd = (
        f'echo $$ > {shlex.quote(_POP["pidfile"])}; '
        f'cat {shlex.quote(fifo)} | '
        'zenity --progress --width=900 --height=260 --percentage=0 '
        '--auto-close --auto-kill --no-cancel '
        f'--title="{safe_title}" '
        f'--text="{safe_text}" --window-icon=warning'
    )

    rc = _run_as_user(_POP["user"], cmd, detach=True)
    if rc.returncode != 0:
        print("[AVISO] falha ao iniciar zenity no desktop do usuário.")
        return False

    # conecta ao FIFO (lado escritor)
    import errno, time as _time
    start = _time.time()
    fd = None
    while _time.time() - start < 8.0:
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError as e:
            if e.errno in (errno.ENXIO, errno.ENOENT):
                _time.sleep(0.2)
                continue
            raise
    if fd is None:
        print("[AVISO] não consegui conectar ao FIFO do zenity.")
        return False

    _POP["writer"] = os.fdopen(fd, "w", buffering=1)
    _POP["started"] = True

    # seta 0% (texto já foi definido por --text)
    try:
        _POP["writer"].write("0\n")
        _POP["writer"].flush()
    except Exception:
        pass
    return True

def zenity_progress_set(percent, message=None):
    """
    Atualiza a barra e mantém o BANNER fixo em vermelho + status atual.
    """
    w = _POP.get("writer")
    if not w:
        return False

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    try:
        p = max(0, min(100, int(percent)))
        if message is not None:
            # sempre mostra o banner + a mensagem atual
            combined = f'{_POP.get("banner", "")}\n{_esc(str(message))}'
            w.write("# " + combined + "\n")
        w.write(f"{p}\n")
        w.flush()
        return True
    except Exception as e:
        print(f"[AVISO] falha ao escrever no FIFO do zenity: {e}")
        return False

def end_upgrade_ui_zenity(success=True):
    """
    Fecha a barra e mostra uma caixa final (como o usuário). Limpa FIFO/PID.
    """
    # tenta finalizar progress
    try:
        if _POP.get("writer"):
            try:
                zenity_progress_set(100, "Concluindo…")
            except Exception:
                pass
            try:
                _POP["writer"].close()
            except Exception:
                pass
            _POP["writer"] = None
    except Exception:
        pass

    # janela final (executa como usuário, sem precisar de DISPLAY do root)
    if _POP.get("user"):
        txt = ("Atualização concluída.\n\nReinicie o computador para finalizar."
               if success else
               "Concluído com avisos/erros.\n\nReinicie e verifique os logs.")
        txt_q = txt.replace('"', '\\"')
        _run_as_user(
            _POP["user"],
            f'zenity --info --width=820 --height=260 --window-icon=warning '
            f'--title="ATUALIZAÇÃO REMOTA" --text="{txt_q}"',
            detach=True
        )

    # encerra processo do zenity (best-effort) e limpa
    try:
        if os.path.exists(_POP["pidfile"]):
            try:
                pid = open(_POP["pidfile"]).read().strip()
                if pid.isdigit():
                    _run(f"kill -TERM {pid} 2>/dev/null || true")
            finally:
                try: os.remove(_POP["pidfile"])
                except Exception: pass
    except Exception:
        pass
    try:
        if os.path.exists(_POP["fifo"]):
            os.remove(_POP["fifo"])
    except Exception:
        pass
    _POP["started"] = False

def progress_phase_run_zenity(label, cmd_or_callable, start_pct, end_pct, poll_interval=1.0):
    """
    Executa uma fase e anima porcentagem entre start_pct..end_pct.
    cmd_or_callable: string shell OU função sem args.
    """
    start_pct = int(start_pct); end_pct = max(int(end_pct), start_pct)
    zenity_progress_set(start_pct, label)

    # shell
    if isinstance(cmd_or_callable, str):
        try:
            proc = subprocess.Popen(cmd_or_callable, shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            print(f"[ERRO] iniciar '{label}': {e}")
            zenity_progress_set(start_pct, f"{label} — erro ao iniciar")
            return False

        cur = start_pct
        last = time.time()
        seen = None
        while True:
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None:
                break
            if line:
                m = re.search(r'(\d{1,3})\s*%', line)
                if m:
                    raw = max(0, min(100, int(m.group(1))))
                    mapped = start_pct + (end_pct - start_pct) * raw // 100
                    seen = mapped
                    zenity_progress_set(mapped, label)
            if time.time() - last >= poll_interval:
                last = time.time()
                if seen is None and cur < end_pct - 1:
                    cur += 1
                    zenity_progress_set(cur, label)

        ok = (proc.returncode == 0)
        zenity_progress_set(end_pct, f"{label} — concluído" if ok else f"{label} — falhou")
        return ok

    # função Python
    import threading
    state = {"done": False, "ok": False}
    def runner():
        try:
            r = cmd_or_callable()
            state["ok"] = (r is None or r is True or r == 0)
        except Exception as e:
            print(f"[ERRO] fase '{label}': {e}")
            state["ok"] = False
        finally:
            state["done"] = True

    t = threading.Thread(target=runner, daemon=True); t.start()
    cur = start_pct
    while not state["done"]:
        if cur < end_pct - 1:
            cur += 1
            zenity_progress_set(cur, label)
        time.sleep(poll_interval)

    zenity_progress_set(end_pct, f"{label} — concluído" if state["ok"] else f"{label} — falhou")
    return state["ok"]
# ============================================================================


def main():
    print("=== Script de Atualização do Debian ===")

    # POPUP (grande, com %) – agora via FIFO no desktop do usuário
    ok_ui = start_upgrade_ui_zenity_progress()
    if ok_ui: zenity_progress_set(2, "Detectando versão do Debian…")

    debian_version = get_debian_version()
    if debian_version is None:
        print("Não foi possível determinar a versão do Debian. Abortando.")
        if ok_ui: end_upgrade_ui_zenity(success=False)
        return 1

    if debian_version == 12:
        ensure_auto_restart_services_yes()
        if ok_ui: zenity_progress_set(5, "Atualizando pacotes (Debian 12)…")
        ok = run_quick_update_12()
        if ok:
            if ok_ui: zenity_progress_set(93, "Ajustando widget Host/IP…")
            try: create_hostip_widget_post_upgrade()
            except Exception as e: print(f"[AVISO] widget: {e}")
            if ok_ui:
                zenity_progress_set(100, "Concluído. Reinicie o computador para finalizar.")
                end_upgrade_ui_zenity(success=True)
            print("\nProcesso de atualização concluído (modo rápido para Debian 12).")
            return 0
        else:
            if ok_ui: end_upgrade_ui_zenity(success=False)
            print("\n[ERRO] Atualização rápida falhou no Debian 12.")
            return 1

    # Fluxo completo (< 12)
    if ok_ui: zenity_progress_set(4, "Pré-configurando respostas…")
    preconfigure_assinador()
    apply_keep_conffiles_policy()
    ensure_auto_restart_services_yes()
    check_and_fix_dpkg_config()
    allow_releaseinfo_change()

    if ok_ui: zenity_progress_set(8, "Removendo QGIS quebrado (se houver)…")
    if not purge_qgis_broken():
        if ok_ui: end_upgrade_ui_zenity(success=False); return 1

    if ok_ui: zenity_progress_set(10, "Garantindo chaves (debian-archive-keyring)…")
    if not ensure_debian_archive_keyring():
        if ok_ui: end_upgrade_ui_zenity(success=False); return 1

    if ok_ui: zenity_progress_set(12, "Atualizando para Debian 12…")
    ok = ensure_debian_stepwise_to_12()
    if not ok:
        if ok_ui: end_upgrade_ui_zenity(success=False)
        return 1

    if ok_ui: zenity_progress_set(78, "Higienizando listas…")
    clean_sources_list(); clean_sources_list_d(); ensure_debian_archive_keyring()

    if ok_ui: zenity_progress_set(80, "Firefox ESR ≥ 128…")
    ok_ff = ensure_firefox_esr_min_128()

    if ok_ui: zenity_progress_set(86, "Chrome (stable)…")
    ok_ch = install_chrome_stable_quick(reenable=False)

    if ok_ui: zenity_progress_set(92, "Google Earth…")
    _ = install_google_earth_stable_quick(reenable=False)  # falha não aborta

    if get_debian_version() == 12 and ok_ff and (get_chrome_version_tuple() != (0, 0, 0)):
        if ok_ui: zenity_progress_set(96, "Limpando kernels conflitantes…")
        clean_conflicting_kernels()
        if ok_ui: zenity_progress_set(97, "Atualizando arquivo de versão…")
        update_version_file()
        if ok_ui: zenity_progress_set(98, "Ajustando widget Host/IP…")
        try: create_hostip_widget_post_upgrade()
        except Exception as e: print(f"[AVISO] widget: {e}")
        if ok_ui:
            zenity_progress_set(100, "Concluído. Reinicie o computador para finalizar.")
            end_upgrade_ui_zenity(success=True)
        print("\nProcesso de atualização concluído!")
        return 0

    if ok_ui: end_upgrade_ui_zenity(success=False)
    print("\n[ERRO] Convergência não atingida.")
    return 1


# ==== RODAPÉ ROBUSTO: garante execução e loga qualquer exceção ====
def _debug_banner():
    import datetime, os, sys
    print("\n=== Início auto.py ===", flush=True)
    print(f"Python: {sys.version.split()[0]}  | Pid: {os.getpid()}  | CWD: {os.getcwd()}", flush=True)
    print(f"Hora: {datetime.datetime.now().isoformat(sep=' ', timespec='seconds')}", flush=True)

if __name__ == "__main__":
    import sys, traceback
    try:
        _debug_banner()
        rc = main()
        print(f"=== Fim auto.py (rc={rc}) ===\n", flush=True)
        sys.exit(0 if rc is None else rc)
    except SystemExit as e:
        print(f"[SystemExit] rc={e.code}", flush=True)
        raise
    except Exception:
        print("\n[ERRO] Exceção não capturada:\n", flush=True)
        traceback.print_exc()
        sys.exit(1)