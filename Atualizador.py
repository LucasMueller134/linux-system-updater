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
    """Executa um comando remoto com tratamento de erros e de forma segura."""
    # shlex.quote escapa o comando para que seja interpretado como uma única string segura
    safe_command = shlex.quote(command)
    ssh_command = f"ssh {host} {safe_command}"

    try:
        # subprocess.run é mais moderno e direto para aguardar um comando finalizar
        result = subprocess.run(
            ssh_command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace' # Garante que não haverá falha por caracteres inválidos
        )

        if result.returncode != 0:
            print(f"Erro ao executar comando remoto em {host}:\n{result.stderr}")
            return False

        # Se precisar do stdout, ele está em result.stdout
        return True

    except Exception as e:
        print(f"Erro na conexão remota com {host}: {str(e)}")
        return False


def get_debian_version():
    """Obtém a versão atual do Debian instalada no sistema (9..13)."""
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
            elif version.startswith('13.'):
                return 13
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
    # Desde o 12 e também no 13, incluir non-free-firmware
    components = f"{base_components} non-free-firmware" if codename in ("bookworm", "trixie") else base_components

    signed_by = "signed-by=/usr/share/keyrings/debian-archive-keyring.gpg"

    lines = [
        f"deb [{signed_by}] https://deb.debian.org/debian {codename} {components}",
    ]

    if codename in ("buster", "bullseye"):
        sec = f"deb [{signed_by}] https://security.debian.org/debian-security {codename}/updates {components}"
        upd = f"deb [{signed_by}] https://deb.debian.org/debian {codename}-updates {components}"
    elif codename in ("bookworm", "trixie"):
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


def ensure_debian_archive_keyring() -> bool:
    """
    Reinstala keyring + gnupg + ca-certificates com autorrecuperação.
    Antes de retry: lida com /boot sem espaço e com b43 travando.
    """
    import subprocess

    def _pre_repair():
        try:
            quarantine_b43_installer()
        except Exception:
            pass
        try:
            purge_old_kernels(keep_n=2)
        except Exception:
            pass
        try:
            repair_initramfs_issues(900)
        except Exception:
            pass
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)

    cmd = "apt-get install -y --reinstall ca-certificates gnupg debian-archive-keyring"
    r = subprocess.run(cmd, shell=True)
    if r.returncode == 0:
        return True

    print("Falha ao garantir keyring; tentando reparar e repetir…")
    _pre_repair()
    r = subprocess.run(cmd, shell=True)
    return r.returncode == 0


def codename_for_version(ver: int) -> str:
    mapping = {9: "stretch", 10: "buster", 11: "bullseye", 12: "bookworm", 13: "trixie"}
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
    """
    Verifica e corrige pacotes Python corrompidos ou com dependências quebradas.
    Esta versão é simplificada para reusar a lógica de automação existente.
    """
    print("\n=== Verificando e corrigindo pacotes Python ===")

    # Pacotes essenciais da stack Python no Debian 12/13
    PYTHON_CORE_PACKAGES = [
        "python3-minimal",
        "python3.11-minimal",
        "libpython3.11-stdlib",
        "python3.11",
        "python3"
    ]

    def _run_fix(command, description):
        print(f"\n-> {description}...")
        return auto_respond_command(command, timeout=1200)

    # Passo 1: Verificar o estado do apt. Se estiver OK, não fazemos nada.
    try:
        result = subprocess.run("apt-get check", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("Nenhum problema de dependência encontrado. Pacotes Python parecem OK.")
            return True
        print("Problemas de dependência detectados. Iniciando procedimento de correção.")
    except Exception as e:
        print(f"Erro ao executar 'apt-get check': {e}")
        return False

    # Passo 2: Tentar a correção padrão
    if _run_fix("apt-get --fix-broken install -y", "Tentando corrigir com --fix-broken install"):
        print("Correção com --fix-broken install bem-sucedida.")
        # Verifica novamente. Se agora estiver OK, terminamos.
        if subprocess.run("apt-get check", shell=True).returncode == 0:
            print("Todos os problemas foram resolvidos.")
            return True

    # Passo 3: Se a correção padrão falhou, tentamos uma reinstalação forçada dos pacotes core.
    print("\nA correção padrão não foi suficiente. Tentando reinstalar pacotes Python essenciais.")
    packages_str = " ".join(PYTHON_CORE_PACKAGES)
    if not _run_fix(f"apt-get install --reinstall -y {packages_str}", f"Reinstalando pacotes: {packages_str}"):
        print("Falha ao reinstalar pacotes Python. O problema pode ser mais sério.")
        # Mesmo com falha, tentamos um último --fix-broken
        _run_fix("apt-get --fix-broken install -y", "Última tentativa de correção")

    # Passo 4: Verificação final
    final_check = subprocess.run("apt-get check", shell=True)
    if final_check.returncode == 0:
        print("\nTodos os problemas de pacotes Python foram corrigidos com sucesso.")
        return True
    else:
        print("\n[AVISO] Ainda existem problemas de dependência após todas as tentativas.")
        print("Recomenda-se uma investigação manual com 'apt-get check' e 'dpkg --configure -a'.")
        return False

def run_upgrade_process(interactive=False):
    """
    Core upgrade com respostas automáticas:
    - Quarentena Chrome/QGIS (como antes)
    - Quarentena b43 (evita 404 no postinst)
    - Purga kernels antigos e repara initramfs quando necessário
    - Limpeza de .deb antigo do Chrome em /tmp (evita curl 416)
    """
    qgis_pkgs = ["qgis", "qgis-plugin-grass", "python3-qgis"]

    try:
        if not check_and_install_expect():
            print("ERRO: Não foi possível instalar 'expect'.")
            return False

        tidy_chrome_off_file()

        changed_map = None
        try:
            changed_map = disable_dl_google_lists()
        except TypeError:
            disable_dl_google_lists()

        # Chrome
        subprocess.run("apt-mark hold google-chrome-stable 2>/dev/null || true", shell=True)
        subprocess.run("apt-get remove -y google-chrome-stable 2>/dev/null || true", shell=True)

        # QGIS
        for pkg in qgis_pkgs:
            subprocess.run(f"apt-mark hold {pkg} 2>/dev/null || true", shell=True)
            subprocess.run(f"apt-get remove -y {pkg} 2>/dev/null || true", shell=True)

        # b43
        try:
            quarantine_b43_installer()
        except Exception as e:
            print(f"[AVISO] quarantine_b43_installer: {e}")

        # keyring
        if not ensure_debian_archive_keyring():
            print("ERRO: keyring Debian inválido. Abortando.")
            return False

        if not check_and_clear_apt_locks():
            print("AVISO: locks persistem; seguindo mesmo assim.")

        # ambiente
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
        env["APT_LISTCHANGES_FRONTEND"] = "none"
        env["DEBIAN_PRIORITY"] = "critical"
        env["TERM"] = "dumb"
        env["UCF_FORCE_CONFFOLD"] = "1"
        env["UCF_FORCE_CONFFNEW"] = "0"
        env["UCF_FORCE_CONFFMISS"] = "1"

        # Debconf Assinador
        try:
            with open("/tmp/assinador_selections", "w", encoding="utf-8") as f:
                f.write("assinador iniciar_automaticamente boolean false\n")
            subprocess.run("debconf-set-selections /tmp/assinador_selections", shell=True, check=False)
        except Exception as e:
            print(f"Erro debconf assinador: {e}")

        monitor_and_kill_whiptail()

        # espaço inicial + kernels antigos
        try:
            purge_old_kernels(keep_n=2)
        except Exception:
            pass
        try:
            free_boot_space(900)
        except Exception:
            pass

        print("\nExecutando: apt -y update")
        auto_respond_command(
            "apt "
            "-o Acquire::AllowReleaseInfoChange::Suite=true "
            "-o Acquire::AllowReleaseInfoChange::Codename=true "
            "-o Acquire::AllowReleaseInfoChange::Label=true "
            "-o Acquire::AllowReleaseInfoChange::Origin=true "
            "update",
            env=env, timeout=1500
        )

        print("\nExecutando: apt -y upgrade")
        auto_respond_command("apt -y upgrade", env=env, timeout=2600)

        print("\nExecutando: apt -y full-upgrade")
        if not auto_respond_command("apt -y full-upgrade", env=env, timeout=4400):
            print("full-upgrade falhou; reparando initramfs/boot e repetindo…")
            try:
                purge_old_kernels(keep_n=2)
            except Exception:
                pass
            try:
                repair_initramfs_issues(1000)
            except Exception:
                pass
            subprocess.run("dpkg --configure -a || true", shell=True)
            subprocess.run("apt-get -f install -y || true", shell=True)
            auto_respond_command("apt -y full-upgrade", env=env, timeout=4400)

        print("\nExecutando: apt autoremove -y")
        auto_respond_command("apt autoremove -y", env=env)

        print("\nExecutando: apt clean")
        auto_respond_command("apt clean", env=env)

        # Reabilita repo do Chrome
        try:
            if changed_map is not None:
                enable_dl_google_lists(changed_map)
            else:
                enable_dl_google_lists()
        except TypeError:
            enable_dl_google_lists()
        except Exception as e:
            print(f"Aviso ao reabilitar repos do Chrome: {e}")

        # Evita erro 416 (arquivo parcial antigo)
        try:
            if os.path.exists("/tmp/google-chrome-stable_current_amd64.deb"):
                os.remove("/tmp/google-chrome-stable_current_amd64.deb")
        except Exception:
            pass

        try:
            install_chrome_stable_quick(reenable=True)
        except Exception:
            pass

        for pkg in qgis_pkgs:
            subprocess.run(f"apt-mark unhold {pkg} 2>/dev/null || true", shell=True)

        print("\nProcesso de atualização concluído!")
        return True

    finally:
        subprocess.run("apt-mark unhold google-chrome-stable 2>/dev/null || true", shell=True)
        for pkg in ["qgis", "qgis-plugin-grass", "python3-qgis"]:
            subprocess.run(f"apt-mark unhold {pkg} 2>/dev/null || true", shell=True)


def monitor_and_kill_whiptail():
    """
    Monitora e mata processos whiptail do assinador de forma mais eficiente.
    """
    import threading
    import time

    def background_monitor():
        print("Iniciando monitoramento de processos whiptail...")
        try:
            while True:
                # Verifica processos whiptail e dialog
                whiptail_check = subprocess.run(
                    "ps aux | grep -E '(whiptail|dialog)' | grep -v grep",
                    shell=True, capture_output=True, text=True
                )

                if whiptail_check.stdout.strip():
                    print("Processo whiptail/dialog detectado! Tentando responder...")

                    # Tenta encontrar e responder aos diálogos
                    try:
                        # Envia 'N' para todos os processos terminal
                        subprocess.run("echo 'N' > /dev/pts/0 2>/dev/null || true", shell=True)
                        time.sleep(0.5)
                        # Envia TAB e ENTER
                        subprocess.run("printf '\\t\\r' > /dev/pts/0 2>/dev/null || true", shell=True)
                    except Exception as e:
                        print(f"Erro ao tentar responder: {e}")

                    # Mata processos persistentes
                    subprocess.run("pkill -f 'whiptail' || true", shell=True)
                    subprocess.run("pkill -f 'dialog' || true", shell=True)

                time.sleep(5)  # Verifica a cada 5 segundos
        except Exception as e:
            print(f"Erro no monitoramento: {e}")

    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()

def check_and_resume_stuck_upgrade():
    """
    Verifica se o upgrade está travado e tenta continuar.
    """
    # Verifica processos dpkg/apt travados
    dpkg_check = subprocess.run("ps aux | grep -E '(dpkg|apt)' | grep -v grep",
                               shell=True, capture_output=True, text=True)

    if "configuring" in dpkg_check.stdout.lower():
        print("Upgrade parece estar travado em configuração. Tentando continuar...")

        # Tenta enviar respostas para diálogos travados
        subprocess.run("echo -e 'N\\nN\\nN\\n' > /dev/pts/0 2>/dev/null || true", shell=True)
        time.sleep(2)

        # Tenta reconfigure
        subprocess.run("dpkg --configure -a", shell=True, timeout=300)

        return True
    return False

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

def auto_respond_command(command, env=None, timeout=3600, log_path=None):
    """
    Executa um comando com respostas automáticas via 'expect', de forma segura.
    Esta função deve ser a única responsável por criar e executar scripts expect.
    """
    print(f"\nExecutando com respostas automáticas: {command}")

    # Garante que 'expect' está instalado antes de prosseguir
    if not ensure_expect_installed(env=env):
        print("[AVISO] 'expect' não disponível. Executando comando diretamente, pode travar em prompts.")
        # Fallback para execução direta sem automação de prompts
        return subprocess.run(command, shell=True, env=env, timeout=timeout).returncode == 0

    # Injeta opções para forçar a manutenção de arquivos de configuração
    safe_command = command
    if command.lstrip().startswith(('apt', 'apt-get')) and "Dpkg::Options" not in command:
        inject = ' -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" '
        parts = command.split()
        safe_command = parts[0] + inject + " ".join(parts[1:])

    # Escapa o comando final para ser seguramente embutido no script 'expect'
    escaped_cmd_for_bash = shlex.quote(safe_command)
    
    # Ambiente padrão para não-interatividade
    final_env = os.environ.copy()
    if env:
        final_env.update(env)
    
    defaults = {
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN": "true",
        "APT_LISTCHANGES_FRONTEND": "none",
        "UCF_FORCE_CONFFOLD": "1" # Manter sempre a versão local do conffile
    }
    for key, value in defaults.items():
        final_env.setdefault(key, value)

    script_content = f"""
#!/usr/bin/expect -f
# Codificação do sistema para lidar com acentos nos prompts
encoding system utf-8
set timeout {timeout}
log_user 1

# Usa 'spawn bash -c' para garantir que o comando completo seja executado corretamente
spawn bash -c {escaped_cmd_for_bash}

# Respostas automáticas para prompts comuns em português e inglês
expect {{
    # Confirmação de continuação
    -re "Do you want to continue\\?.*"      {{ send "Y\\r"; exp_continue }}
    -re "Deseja continuar\\?.*"             {{ send "S\\r"; exp_continue }}

    # Manutenção de arquivos de configuração (conffiles)
    -re "install the package maintainer's version" {{ send "N\\r"; exp_continue }}
    -re "instalar a versão do mantenedor do pacote" {{ send "N\\r"; exp_continue }}
    -re "keep the local version currently installed" {{ send "Y\\r"; exp_continue }}
    -re "manter a versão local atualmente instalada" {{ send "S\\r"; exp_continue }}
    -re "What do you want to do about modified configuration file" {{ send "keep"; exp_continue }}

    # Reinício de serviços
    -re "Restart services during package upgrades" {{ send "Yes\\r"; exp_continue }}
    -re "Reiniciar serviços durante atualizações"   {{ send "Sim\\r"; exp_continue }}
    
    # Prompt do Assinador
    -re "Iniciar o Assinador junto com o sistema" {{ send "N\\r"; exp_continue }}

    # Fim da execução
    eof
}}

# Captura o código de saída do processo para retornar ao Python
catch wait result
exit [lindex $result 3]
"""
    try:
        # Usar um arquivo temporário nomeado para o script
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exp', encoding='utf-8') as f:
            f.write(script_content)
            expect_script_path = f.name
        
        os.chmod(expect_script_path, 0o755)

        proc = subprocess.Popen(f"expect {shlex.quote(expect_script_path)}", shell=True, env=final_env)
        proc.wait(timeout=timeout + 60) # Adiciona uma margem ao timeout
        return proc.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"Timeout atingido após {timeout}s para o comando: {command}")
        if 'proc' in locals() and proc.poll() is None:
            proc.kill()
        return False
    except Exception as e:
        print(f"Erro inesperado ao executar comando com 'expect': {e}")
        return False
    finally:
        if 'expect_script_path' in locals() and os.path.exists(expect_script_path):
            os.remove(expect_script_path)


def run_robust_upgrade() -> bool:
    """
    (VERSÃO CORRIGIDA) Executa um processo de atualização completo de forma robusta e não-interativa.
    Remove as opções redundantes de Dpkg::Options que causavam o erro.
    """
    print("\n=== INICIANDO PROCESSO DE ATUALIZAÇÃO ROBUSTO (v2) ===")

    # --- Preparação ---
    quarantine_b43_installer()
    purge_old_kernels(keep_n=2)
    free_boot_space(900)
    check_and_clear_apt_locks()

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    
    # --- Configuração Não-Interativa via Arquivo Temporário ---
    dpkg_config_content = "force-confold\nforce-confdef\n"
    config_dir = tempfile.mkdtemp()
    config_file_path = os.path.join(config_dir, "99-auto-upgrade-no-prompt")
    
    with open(config_file_path, 'w') as f:
        f.write(dpkg_config_content)

    # Construímos as opções do APT para usar nossa configuração e desabilitar e-mails.
    # AS OPÇÕES PROBLEMÁTICAS FORAM REMOVIDAS DAQUI.
    apt_options = [
        '-o', f'Dir::Etc::parts={config_dir}',
        '-o', 'APT::List-Changes::Send-Emails=false'
    ]

    try:
        # --- Execução ---
        # 1. Atualizar a lista de pacotes
        print("\n[FASE 1/4] Executando 'apt update'...")
        update_cmd = ["apt", "update"] + apt_options
        # Adicionamos --allow-releaseinfo-change para evitar erros em upgrades de versão
        subprocess.run(update_cmd + ["--allow-releaseinfo-change"], env=env, check=True)

        # 2. Executar a atualização principal
        print("\n[FASE 2/4] Executando 'apt -y full-upgrade'...")
        upgrade_cmd = ["apt", "-y", "full-upgrade"] + apt_options
        subprocess.run(upgrade_cmd, env=env, check=True)

        # 3. Remover pacotes desnecessários
        print("\n[FASE 3/4] Executando 'apt -y autoremove'...")
        autoremove_cmd = ["apt", "-y", "--purge", "autoremove"] + apt_options
        subprocess.run(autoremove_cmd, env=env, check=True)

        # 4. Limpar o cache
        print("\n[FASE 4/4] Executando 'apt clean'...")
        clean_cmd = ["apt", "clean"]
        subprocess.run(clean_cmd, env=env, check=True)
        
        print("\n✅ Processo de atualização concluído com sucesso!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERRO: Ocorreu um erro durante a fase de atualização.")
        print(f"Comando que falhou: {' '.join(e.cmd)}")
        print(f"Código de saída: {e.returncode}")
        print("Tentando executar 'dpkg --configure -a' e 'apt --fix-broken install' para recuperação...")
        subprocess.run(["dpkg", "--configure", "-a"], env=env)
        subprocess.run(["apt", "--fix-broken", "install", "-y"] + apt_options, env=env)
        return False
    except Exception as e:
        print(f"\n❌ ERRO INESPERADO: {e}")
        return False
    finally:
        # --- Limpeza ---
        if os.path.exists(config_dir):
            shutil.rmtree(config_dir)
        print("Limpeza finalizada.")

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

def free_boot_space(min_free_mb: int = 600) -> bool:
    """
    Libera espaço em /boot removendo initrd/vmlinuz/config/System.map de
    versões antigas (mantém kernel em uso e os 2 mais recentes).
    """
    import os, glob, subprocess

    boot = "/boot"

    def _free_mb() -> int:
        try:
            s = os.statvfs(boot)
            return int((s.f_bavail * s.f_frsize) / (1024 * 1024))
        except Exception:
            return 0

    free_before = _free_mb()
    print(f"/boot livre ~{free_before} MB.")

    if free_before >= min_free_mb:
        return True

    # coleta versões a partir dos arquivos em /boot
    by_ver = {}
    for pat in ("initrd.img-*", "vmlinuz-*", "System.map-*", "config-*"):
        for p in glob.glob(os.path.join(boot, pat)):
            ver = os.path.basename(p).split("initrd.img-")[-1]
            ver = os.path.basename(p).split("vmlinuz-")[-1]
            ver = os.path.basename(p).split("System.map-")[-1]
            ver = os.path.basename(p).split("config-")[-1]
            try:
                mtime = os.path.getmtime(p)
            except Exception:
                mtime = 0
            by_ver.setdefault(ver, []).append((mtime, p))

    # versão em execução
    try:
        running = subprocess.check_output("uname -r", shell=True, text=True).strip()
    except Exception:
        running = ""

    # ordena versões por recência (mtime máximo)
    ver_sorted = sorted(by_ver.items(), key=lambda kv: max(x[0] for x in kv[1]), reverse=True)
    keep = set()
    if running:
        keep.add(running)
    keep.update([v for v, _ in ver_sorted[:2]])  # mantém 2 mais recentes

    removed = 0
    for ver, files in reversed(ver_sorted):  # antigos primeiro
        if ver in keep:
            continue
        for _, p in files:
            try:
                if os.path.isfile(p):
                    print(f"[free_boot_space] removendo {p}")
                    os.remove(p)
                    removed += 1
            except Exception as e:
                print(f"[free_boot_space] falha ao remover {p}: {e}")
        if _free_mb() >= min_free_mb:
            break

    # atualiza grub (best-effort)
    try:
        subprocess.run("update-grub || true", shell=True)
    except Exception:
        pass

    free_after = _free_mb()
    print(f"/boot livre após limpeza ~{free_after} MB. (removidos {removed} arquivos)")
    return free_after >= min_free_mb


def quarantine_b43_installer():
    """
    Quarentena do firmware-b43-installer:
    - Se NÃO houver Broadcom conhecida OU se o pacote estiver travando, purga e põe hold.
    """
    import subprocess

    def _has_broadcom() -> bool:
        try:
            # tenta detectar via lspci/lsmod/dmesg (qualquer evidência)
            if subprocess.run("command -v lspci >/dev/null 2>&1", shell=True).returncode == 0:
                if subprocess.run("lspci -nn | grep -i 'Broadcom' | grep -E '\\[14e4:'", shell=True).returncode == 0:
                    return True
            if subprocess.run("lsmod | grep -E '^b43|brcmsmac|wl\\b'", shell=True).returncode == 0:
                return True
            if subprocess.run("dmesg | grep -i 'bcm43\\|Broadcom Wireless'", shell=True).returncode == 0:
                return True
        except Exception:
            pass
        return False

    need_quarantine = not _has_broadcom()
    if not need_quarantine:
        # ainda assim, se o pacote estiver em estado quebrado, vamos tirá-lo do caminho
        need_quarantine = (subprocess.run("dpkg -s firmware-b43-installer >/dev/null 2>&1", shell=True).returncode == 0 and
                           subprocess.run("grep -q 'reinstreq\\|not-configured' /var/lib/dpkg/status 2>/dev/null", shell=True).returncode == 0)

    if need_quarantine:
        print("[b43] Quarentenando firmware-b43-installer (sem Broadcom ou travando)…")
        subprocess.run("apt-get -y remove --purge firmware-b43-installer", shell=True)
        subprocess.run("dpkg -r --force-remove-reinstreq firmware-b43-installer || true", shell=True)
        subprocess.run("dpkg --purge --force-all firmware-b43-installer || true", shell=True)
        subprocess.run("apt-mark hold firmware-b43-installer 2>/dev/null || true", shell=True)


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
    (VERSÃO 3 - ROBUSTA PARA SALTO DE VERSÃO)
    Executa o procedimento correto e delicado para um salto de versão de SO,
    incluindo a instalação do novo keyring de forma não-autenticada
    para depois poder rodar a atualização completa de forma segura.
    """
    codename = codename_for_version(target_ver)
    if not codename:
        print(f"Versão alvo inválida: {target_ver}")
        return False

    print(f"\n=== INICIANDO SALTO DE VERSÃO PARA DEBIAN {target_ver} ({codename}) ===")

    # --- Configuração do Ambiente e DPBKG ---
    # Usamos o mesmo método do run_robust_upgrade para evitar prompts de conffiles
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    
    dpkg_config_content = "force-confold\nforce-confdef\n"
    config_dir = tempfile.mkdtemp()
    config_file_path = os.path.join(config_dir, "99-auto-upgrade-no-prompt")
    with open(config_file_path, 'w') as f:
        f.write(dpkg_config_content)

    apt_options = [
        '-o', f'Dir::Etc::parts={config_dir}',
        '-o', 'APT::List-Changes::Send-Emails=false',
        '-y' # Sempre assume "Sim" para as perguntas do apt
    ]

    try:
        # 1. Altera o sources.list para a nova versão
        if not write_canonical_sources(codename):
            return False # Falha ao escrever sources

        # 2. apt update (NÃO AUTENTICADO)
        # É ESSENCIAL rodar o update permitindo que ele falhe na validação GPG.
        # Usamos --allow-insecure-repositories e --allow-releaseinfo-change.
        print("\n[FASE 1/5] Executando apt update (permitindo não-autenticado)...")
        cmd_update_insecure = ["apt", "update", 
                               "--allow-insecure-repositories", 
                               "--allow-releaseinfo-change"]
        subprocess.run(cmd_update_insecure, env=env, check=True)
        print("Update inicial concluído (para encontrar o novo keyring).")

        # 3. Instala o novo Keyring (NÃO AUTENTICADO)
        # Agora que o apt conhece os pacotes do bookworm, instalamos o novo keyring.
        # Isso dará ao apt as chaves para confiar no repositório.
        print("\n[FASE 2/5] Instalando novo debian-archive-keyring (permitindo não-autenticado)...")
        cmd_install_keyring = ["apt", "install", "debian-archive-keyring"] + apt_options + ["--allow-unauthenticated"]
        subprocess.run(cmd_install_keyring, env=env, check=True)
        print("Novo keyring instalado.")

        # 4. apt update (SEGURO)
        # Agora que temos o keyring, rodamos o update novamente. Desta vez, ele será
        # validado com sucesso e será seguro.
        print("\n[FASE 3/5] Executando apt update (modo seguro)...")
        cmd_update_secure = ["apt", "update", "--allow-releaseinfo-change"]
        subprocess.run(cmd_update_secure, env=env, check=True)
        print("Update seguro concluído.")

        # 5. A Atualização Principal (Finalmente)
        # Com o sistema pronto e confiando nos repositórios, fazemos o upgrade.
        # Isso irá resolver o estado quebrado de libc6/libc-bin.
        print("\n[FASE 4/5] Executando apt full-upgrade (o salto de versão)...")
        cmd_full_upgrade = ["apt", "full-upgrade"] + apt_options
        subprocess.run(cmd_full_upgrade, env=env, check=True)
        print("Salto de versão completo.")

        # 6. Limpeza
        print("\n[FASE 5/5] Executando apt autoremove para limpeza...")
        cmd_autoremove = ["apt", "autoremove", "--purge"] + apt_options
        subprocess.run(cmd_autoremove, env=env, check=True)

        print(f"✅ Upgrade para Debian {target_ver} ({codename}) concluído com sucesso.")
        
        # Verifica se realmente chegou lá
        cur = get_debian_version()
        print(f"[INFO] Versão após upgrade: {cur}")
        return cur == target_ver

    except Exception as e:
        print(f"\n❌ ERRO CRÍTICO DURANTE O SALTO DE VERSÃO: {e}")
        print("Tentando executar 'dpkg --configure -a' e 'apt --fix-broken install' para recuperação...")
        try:
            subprocess.run(["dpkg", "--configure", "-a"], env=env)
            subprocess.run(["apt", "--fix-broken", "install"] + apt_options, env=env)
        except Exception as e2:
            print(f"Comandos de recuperação também falharam: {e2}")
        return False
    finally:
        # Garante que o diretório de config temporário seja sempre limpo
        if os.path.exists(config_dir):
            shutil.rmtree(config_dir)

def ensure_debian_stepwise_to_13() -> bool:
    """
    (VERSÃO 2 - SIMPLIFICADA)
    Garante que o sistema chegue ao Debian 13, executando os saltos de versão
    necessários um a um, usando a nova e robusta função 'step_upgrade_to'.
    """
    print("\n=== Iniciando verificação de upgrade passo a passo para o Debian 13 ===")

    # Garante que as respostas automáticas para reinício de serviços estejam ativas
    ensure_auto_restart_services_yes()

    cur = get_debian_version()
    if cur is None:
        print("Não foi possível detectar a versão do Debian. Abortando.")
        return False

    if cur >= 13:
        print("Sistema já está no Debian 13 ou superior. Pulando saltos de versão.")
        return True

    # Loop para os saltos de versão
    for target in (12, 13):
        cur = get_debian_version() or cur # Atualiza a versão atual a cada loop
        
        if cur < target:
            # Chama a nossa nova função de salto de versão robusta
            if not step_upgrade_to(target):
                print(f"\n[ERRO FATAL] Falha no passo de atualização para a versão {target}. Abortando.")
                return False

    final_ver = get_debian_version()
    if final_ver == 13:
        print("✅ Upgrade passo a passo para Debian 13 concluído.")
        return True
    else:
        print(f"ERRO: Upgrade finalizado, mas a versão final detectada é {final_ver} (esperado: 13).")
        return False

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

        # Em Debian 13 o pacote certo é firefox-esr
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
            # usar a forma canônica; -o na linha de comando continua funcionando
            f.write('DPkg::Options {\n')
            f.write('  "--force-confdef";\n')
            f.write('  "--force-confold";\n')
            f.write('};\n')
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

def wait_for_apt_lock(timeout=900, poll=2):
    """
    Aguarda liberação dos locks do APT/DPKG por até `timeout` seg.
    Evita concorrência entre apt/dpkg/unattended-upgrades.
    """
    import os, time, subprocess
    locks = [
        "/var/lib/dpkg/lock",
        "/var/lib/dpkg/lock-frontend",
        "/var/lib/apt/lists/lock",
        "/var/cache/apt/archives/lock",
    ]
    start = time.time()
    while True:
        busy = False
        for lk in locks:
            if os.path.exists(lk):
                if subprocess.run(f"fuser {lk} >/dev/null 2>&1", shell=True).returncode == 0:
                    busy = True
                    break
        if not busy:
            return True
        if time.time() - start > timeout:
            print("[ERRO] Timeout aguardando liberação dos locks APT/DPKG.")
            return False
        time.sleep(poll)

def ensure_expect_installed(env=None) -> bool:
    """
    Garante a instalação do 'expect' (usado pelo auto-responder).
    Retorna True se disponível (instalado ou já presente), False caso contrário.
    """
    import shutil, subprocess, os
    if shutil.which("expect"):
        return True
    if env is None:
        env = os.environ.copy()
    if not wait_for_apt_lock():
        return False
    subprocess.run("apt-get -y update", shell=True, env=env)  # melhor esforço
    if not wait_for_apt_lock():
        return False
    rc = subprocess.run("apt-get -y install expect", shell=True, env=env).returncode
    if rc != 0:
        print("[AVISO] 'expect' não pôde ser instalado; executando sem auto-resposta.")
        return False
    return True

def dedupe_serpro_sources():
    """
    Remove entradas duplicadas do SERPRO em /etc/apt/sources.list
    e mantém apenas /etc/apt/sources.list.d/assinador-serpro.list.
    """
    import os
    mainsrc = "/etc/apt/sources.list"
    try:
        if os.path.exists(mainsrc):
            with open(mainsrc, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            new_lines = []
            changed = False
            for ln in lines:
                if "assinadorserpro.estaleiro.serpro.gov.br" in ln:
                    print("[INFO] Removendo linha duplicada do SERPRO em /etc/apt/sources.list")
                    changed = True
                    continue
                new_lines.append(ln)
            if changed:
                if not wait_for_apt_lock():
                    return
                with open(mainsrc, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
    except Exception as e:
        print(f"[AVISO] Não foi possível deduplicar /etc/apt/sources.list: {e}")

def try_repair_assinador_serpro() -> bool:
    """
    Purga e recompõe chave/repo do SERPRO e reinstala o pacote,
    garantindo que NÃO inicie automaticamente.
    """

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    print("\n[INFO] Tentando reparar repositório/pacote Assinador SERPRO...")

    # 0) Evita concorrência
    if not wait_for_apt_lock():
        return False

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

    # 2.1) Deduplicar fonte no sources.list
    dedupe_serpro_sources()

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

    # 4) Recriar a lista do repositório (padrão: stable main)
    try:
        with open("/etc/apt/sources.list.d/assinador-serpro.list", "w", encoding="utf-8") as f:
            f.write(
                "deb [signed-by=/etc/apt/trusted.gpg.d/AssinadorSERPROpublic.asc] "
                "https://assinadorserpro.estaleiro.serpro.gov.br/repository stable main\n"
            )
    except Exception as e:
        print(f"[ERRO] Não foi possível escrever a lista do repositório do SERPRO: {e}")
        return False

    # 5) apt update (aceitando mudanças de Release Info)
    if not wait_for_apt_lock():
        return False
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

    # 6) Reinstalar o pacote SEM AUTOSTART (manter configs)
    if not wait_for_apt_lock():
        return False
    rc = subprocess.run(
        ["apt-get", "-o", "Dpkg::Options::=--force-confdef",
         "-o", "Dpkg::Options::=--force-confold",
         "-y", "install", "assinador-serpro"],
        env=env
    ).returncode
    if rc != 0:
        print("[ERRO] Falha ao reinstalar assinador-serpro.")
        return False

    # 7) Evitar autostart (caso o pacote crie serviço)
    for svc in ("assinador", "assinador-serpro", "serpro-assinador"):
        subprocess.run(f"systemctl disable --now {svc}", shell=True)
        subprocess.run(f"systemctl mask {svc}", shell=True)

    print("[OK] Repositório e pacote Assinador SERPRO reparados (sem autostart).")
    return True

def run_quick_update_13() -> bool:
    """
    Caminho rápido (usado também no Debian 13):
    - força manter conffiles locais (dpkg/apt + env)
    - quarentena do firmware-b43-installer
    - purga kernels antigos e repara initramfs se preciso
    - apt update / upgrade / autoremove / clean, com retries
    """
    import shlex, subprocess, time, os

    # Política de conffiles
    try:
        apply_keep_conffiles_policy()
    except Exception as e:
        print(f"[AVISO] apply_keep_conffiles_policy: {e}")

    # Quarentena b43 + purge de kernels antigos
    try:
        quarantine_b43_installer()
    except Exception as e:
        print(f"[AVISO] quarantine_b43_installer: {e}")
    try:
        purge_old_kernels(keep_n=2)
    except Exception as e:
        print(f"[AVISO] purge_old_kernels: {e}")

    # Garante espaço antes
    try:
        free_boot_space(800)
    except Exception:
        pass

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
    env["APT_LISTCHANGES_FRONTEND"] = "none"
    env["DEBIAN_PRIORITY"] = "critical"
    env["TERM"] = "dumb"
    env["UCF_FORCE_CONFFOLD"] = "1"
    env["UCF_FORCE_CONFFNEW"] = "0"
    env["UCF_FORCE_CONFFMISS"] = "1"

    def _run(cmd: str, timeout: int) -> bool:
        print(f"\nExecutando (subprocess): {cmd}")
        try:
            with subprocess.Popen(
                shlex.split(cmd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            ) as p:
                start = time.time()
                for line in p.stdout:
                    print(line, end="")
                    if time.time() - start > timeout:
                        print(f"[ERRO] Timeout em: {cmd}")
                        p.kill()
                        return False
            return p.returncode == 0
        except Exception as e:
            print(f"[ERRO] Subprocesso falhou: {e}")
            return False

    # update
    update_cmd = (
        "apt "
        "-o Acquire::AllowReleaseInfoChange::Suite=true "
        "-o Acquire::AllowReleaseInfoChange::Codename=true "
        "-o Acquire::AllowReleaseInfoChange::Label=true "
        "-o Acquire::AllowReleaseInfoChange::Origin=true "
        "update"
    )
    if not _run(update_cmd, timeout=900):
        print("[ERRO] apt update falhou.")
        return False

    # upgrade
    upgrade_cmd = (
        "apt "
        "-o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold "
        "upgrade -y"
    )
    if not _run(upgrade_cmd, timeout=3200):
        print("[AVISO] upgrade falhou; tentando reparar initramfs/boot e repetir…")
        try:
            repair_initramfs_issues(1000)
        except Exception:
            pass
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)
        if not auto_respond_command(upgrade_cmd, env=env, timeout=3200):
            print("[ERRO] Falha no upgrade (auto responder).")
            return False

    # autoremove
    if not _run("apt autoremove --purge -y", timeout=900):
        print("[AVISO] autoremove falhou; tentando via auto responder…")
        if not auto_respond_command("apt autoremove --purge -y", env=env, timeout=900):
            print("[ERRO] autoremove falhou.")
            return False

    # clean
    if not _run("apt clean", timeout=600):
        print("[AVISO] clean falhou; tentando via auto responder…")
        if not auto_respond_command("apt clean", env=env, timeout=600):
            print("[ERRO] clean falhou.")
            return False

    # passada final
    try:
        repair_initramfs_issues(900)
    except Exception:
        pass
    subprocess.run("dpkg --configure -a || true", shell=True)
    subprocess.run("apt-get -f install -y || true", shell=True)

    print("\n[OK] Atualização concluída (modo rápido, mantendo configs locais).")
    return True

    def _run(cmd: str, timeout: int) -> bool:
        print(f"\nExecutando (subprocess): {cmd}")
        try:
            with subprocess.Popen(
                shlex.split(cmd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            ) as p:
                start = time.time()
                for line in p.stdout:
                    print(line, end="")
                    if time.time() - start > timeout:
                        print(f"[ERRO] Timeout em: {cmd}")
                        p.kill()
                        return False
            return p.returncode == 0
        except Exception as e:
            print(f"[ERRO] Subprocesso falhou: {e}")
            return False

    # 1) apt update com AllowReleaseInfoChange
    update_cmd = (
        "apt "
        "-o Acquire::AllowReleaseInfoChange::Suite=true "
        "-o Acquire::AllowReleaseInfoChange::Codename=true "
        "-o Acquire::AllowReleaseInfoChange::Label=true "
        "-o Acquire::AllowReleaseInfoChange::Origin=true "
        "update"
    )
    if not _run(update_cmd, timeout=900):
        print("[ERRO] apt update falhou.")
        return False

    # 2) upgrade -y
    upgrade_cmd = (
        "apt "
        "-o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold "
        "upgrade -y"
    )
    if not _run(upgrade_cmd, timeout=3000):
        print("[AVISO] upgrade falhou; tentando corrigir espaço/dpkg e repetir…")
        try:
            free_boot_space(800)
        except Exception:
            pass
        subprocess.run("dpkg --configure -a || true", shell=True)
        subprocess.run("apt-get -f install -y || true", shell=True)
        subprocess.run("apt-get -y remove --purge apt-listchanges 2>/dev/null || true", shell=True)
        if not auto_respond_command(upgrade_cmd, env=env, timeout=3000):
            print("[ERRO] Falha no upgrade (auto responder).")
            return False

    # 3) autoremove
    if not _run("apt autoremove --purge -y", timeout=900):
        print("[AVISO] autoremove falhou; tentando via auto responder…")
        if not auto_respond_command("apt autoremove --purge -y", env=env, timeout=900):
            print("[ERRO] autoremove falhou.")
            return False

    # 4) clean
    if not _run("apt clean", timeout=600):
        print("[AVISO] clean falhou; tentando via auto responder…")
        if not auto_respond_command("apt clean", env=env, timeout=600):
            print("[ERRO] clean falhou.")
            return False

    # 5) Última passada de reparo
    try:
        free_boot_space(600)
    except Exception:
        pass
    subprocess.run("dpkg --configure -a || true", shell=True)
    subprocess.run("apt-get -f install -y || true", shell=True)

    print("\n[OK] Atualização concluída (modo rápido, mantendo configs locais).")
    return True



def finalize_python3_stack_post13():
    """
    Repara/configura a pilha Python3 no Debian 13 quando 'python3' ficou
    parcialmente instalado e N pacotes ficaram 'desconfigurados'.
    """
    import os, shutil, subprocess
    print("\n=== Reparando stack Python3 pós-upgrade (Debian 13) ===")
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

def _ensure_hostip_tray_dependencies():
    pkgs = [
        "python3-gi",
        "gir1.2-gtk-3.0",
        "gir1.2-ayatanaappindicator3-0.1",
        "libayatana-appindicator3-1",
        "gir1.2-appindicator3-0.1",  # fallback
        "network-manager-gnome"      # nm-connection-editor (opcional)
    ]
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    _run_quiet("apt-get update -o Acquire::Retries=3 || true", env=env)
    _run_quiet("apt-get install -y --no-install-recommends " + " ".join(pkgs), env=env)

def _write_hostip_tray_script(path):
    content = r'''#!/usr/bin/env python3
import os, sys, subprocess, socket
from gi import require_version
require_version('Gtk', '3.0')
try:
    require_version('AyatanaAppIndicator3', '0.1')
except Exception:
    try:
        require_version('AppIndicator3', '0.1')
    except Exception:
        pass
from gi.repository import Gtk, GLib
try:
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
except Exception:
    from gi.repository import AppIndicator3 as AppIndicator  # fallback

APP_ID = "hostip.tray.pmjs"
ICON_NAME = "network-workgroup"
UPDATE_SEC = 10

def _run(cmd):
    return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def get_hostname():
    try: return socket.gethostname()
    except Exception: return "sem-hostname"

def get_ips_by_interface():
    out = _run("ip -o -4 addr show scope global").stdout.strip().splitlines()
    ips = {}
    for line in out:
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            iface = parts[1]; ipv4 = parts[3].split("/")[0]
            ips.setdefault(iface, []).append(ipv4)
    return ips

def get_primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return None

class HostIPTray:
    def __init__(self):
        self.ind = AppIndicator.Indicator.new(APP_ID, ICON_NAME, AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu()
        self.hostname_item = Gtk.MenuItem(label="Hostname: …"); self.hostname_item.set_sensitive(False); self.menu.append(self.hostname_item)
        self.sep1 = Gtk.SeparatorMenuItem(); self.menu.append(self.sep1)
        self.iface_items = []
        self.sep2 = Gtk.SeparatorMenuItem(); self.menu.append(self.sep2)
        self.copy_item = Gtk.MenuItem(label="Copiar Host/IP"); self.copy_item.connect("activate", self.copy_to_clipboard); self.menu.append(self.copy_item)
        self.netcfg_item = Gtk.MenuItem(label="Abrir Configurações de Rede"); self.netcfg_item.connect("activate", self.open_nm_editor); self.menu.append(self.netcfg_item)
        self.quit_item = Gtk.MenuItem(label="Sair"); self.quit_item.connect("activate", self.quit); self.menu.append(self.quit_item)
        self.menu.show_all(); self.ind.set_menu(self.menu)
        GLib.idle_add(self.update); GLib.timeout_add_seconds(UPDATE_SEC, self.update)

    def set_label_if_supported(self, text):
        try:
            self.ind.set_title(text)
            self.ind.set_label(text, "")
        except Exception:
            pass

    def update(self, *_):
        hostname = get_hostname(); ips = get_ips_by_interface(); prim = get_primary_ip()
        title = hostname + (f" · {prim}" if prim else "")
        self.set_label_if_supported(title)
        self.hostname_item.set_label(f"Hostname: {hostname}")
        for it in self.iface_items: self.menu.remove(it)
        self.iface_items = []
        if not ips:
            it = Gtk.MenuItem(label="Sem IP global"); it.set_sensitive(False); self.menu.insert(it, 2); self.iface_items.append(it)
        else:
            pos = 2
            for iface, addrs in ips.items():
                it = Gtk.MenuItem(label=f"{iface}: {', '.join(addrs)}"); it.set_sensitive(False); self.menu.insert(it, pos)
                self.iface_items.append(it); pos += 1
        self.menu.show_all(); return True

    def copy_to_clipboard(self, _):
        text = f"{get_hostname()} {get_primary_ip() or 'sem-IP'}"
        try:
            from gi.repository import Gdk
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
        except Exception:
            _run(f"printf '%s' \"{text}\" | xclip -selection clipboard >/dev/null 2>&1 || true")

    def open_nm_editor(self, _):
        for cmd in ["nm-connection-editor &", "nm-connection-editor --show &"]:
            if _run(cmd).returncode == 0: break

    def quit(self, _): Gtk.main_quit()

if __name__ == "__main__":
    HostIPTray(); Gtk.main()
'''
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def _write_autostart_desktop(path, script_path):
    content = f'''[Desktop Entry]
Type=Application
Name=Host/IP Tray
Comment=Mostra hostname e IP na bandeja
Exec=python3 "{script_path}"
Icon=network-workgroup
Terminal=false
X-GNOME-Autostart-enabled=true
X-MATE-Autostart-enabled=true
X-Cinnamon-Autostart-enabled=true
OnlyShowIn=GNOME;MATE;Cinnamon;XFCE;LXDE;LXQt;Unity;X-GNOME;
'''
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def _run_quiet(cmd, env=None):
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, check=False)
    except Exception:
        pass

def _run_detached(cmd):
    try:
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setpgrp)
    except Exception:
        pass

def _make_executable(path):
    try:
        os.chmod(path, (os.stat(path).st_mode | 0o111))
    except Exception as e:
        print(f"[AVISO] chmod exec falhou em {path}: {e}")

def _write_autostart_desktop(path, script_path):
    content = f'''[Desktop Entry]
Type=Application
Name=Host/IP Tray
Comment=Mostra hostname e IP na bandeja
Exec=python3 "{script_path}"
Icon=network-workgroup
Terminal=false
X-GNOME-Autostart-enabled=true
X-MATE-Autostart-enabled=true
X-Cinnamon-Autostart-enabled=true
'''
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def _spawn_tray_in_active_gui_session(script_path: str):
    """
    Localiza a sessão gráfica ativa via loginctl e executa o tray como o USUÁRIO dessa sessão,
    com DISPLAY e DBUS corretos. Funciona em Xorg; em Wayland costuma bastar o DBUS.
    """
    sess_info = _detect_active_gui_session()
    if not sess_info:
        # Sem sessão gráfica detectada agora: o autostart cuidará no próximo login
        return

    user, uid, display, wayland_display = sess_info

    xdg_runtime = f"/run/user/{uid}"
    dbus_addr = f"unix:path={xdg_runtime}/bus"

    env_parts = [f"XDG_RUNTIME_DIR={xdg_runtime}", f"DBUS_SESSION_BUS_ADDRESS={dbus_addr}"]
    if display:
        env_parts.append(f"DISPLAY={display}")
    if wayland_display:
        env_parts.append(f"WAYLAND_DISPLAY={wayland_display}")

    env_str = " ".join(env_parts)

    # runuser é preferível a sudo em scripts não interativos
    cmd = (
        f"runuser -l {user} -c \"{env_str} setsid -f python3 '{script_path}' >/dev/null 2>&1 &\""
    )
    _run_quiet(cmd)

def _detect_active_gui_session():
    """
    Retorna (user, uid, DISPLAY, WAYLAND_DISPLAY) da sessão gráfica ativa, ou None.
    """
    try:
        out = subprocess.check_output("loginctl list-sessions --no-legend", shell=True, text=True).strip().splitlines()
    except Exception:
        out = []

    best = None
    for line in out:
        # Ex: "3  est126350 seat0  ..."
        parts = line.split()
        if not parts:
            continue
        sid = parts[0]
        try:
            show = subprocess.check_output(f"loginctl show-session {sid}", shell=True, text=True)
        except Exception:
            continue
        info = {}
        for row in show.splitlines():
            if "=" in row:
                k, v = row.split("=", 1)
                info[k.strip()] = v.strip()

        if info.get("Active") != "yes":
            continue
        # Preferimos sessões locais e gráficas
        if info.get("Remote") == "yes":
            continue
        if info.get("Class") not in ("user", "greeter"):
            continue

        user = info.get("Name") or info.get("User")
        if not user:
            continue
        try:
            import pwd
            uid = pwd.getpwnam(user).pw_uid
        except Exception:
            continue

        display = info.get("Display") or os.environ.get("DISPLAY") or ":0"
        # Heurística p/ Wayland
        wayland_display = None
        try:
            # Se existir um socket wayland no XDG_RUNTIME_DIR do user, usa-o
            xdg_runtime = f"/run/user/{uid}"
            for cand in os.listdir(xdg_runtime):
                if cand.startswith("wayland-"):
                    wayland_display = cand
                    break
        except Exception:
            pass

        best = (user, uid, display, wayland_display)
        break

    return best

def _write_autostart_desktop_global(path, script_path):
    """
    Cria/atualiza o autostart GLOBAL para o tray Host/IP.
    Ex.: path = '/etc/xdg/autostart/hostip-tray.desktop'
    """
    # Garante que o diretório exista
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass

    content = f"""[Desktop Entry]
Type=Application
Name=Host/IP Tray
Name[pt_BR]=Host/IP Tray
Comment=Mostra hostname e IP na bandeja do sistema
Exec=python3 "{script_path}"
Icon=network-workgroup
Terminal=false
NoDisplay=false
Hidden=false
X-GNOME-Autostart-enabled=true
X-MATE-Autostart-enabled=true
X-Cinnamon-Autostart-enabled=true
X-LXQt-Need-Tray=true
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    # Ajusta permissão padrão de .desktop
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass

def _spawn_tray_for_user(username: str, script_path: str):
    """
    Sobe o tray agora na sessão gráfica ativa do usuário informado.
    Usa loginctl para achar DISPLAY/DBUS e executa via runuser.
    Se não houver sessão gráfica ativa, o autostart cuidará no próximo login.
    """
    import pwd, os, subprocess

    def _detect_user_session_env(user: str):
        # Procura uma sessão ativa do usuário
        try:
            sessions = subprocess.check_output("loginctl list-sessions --no-legend", shell=True, text=True).strip().splitlines()
        except Exception:
            sessions = []
        for line in sessions:
            parts = line.split()
            if not parts:
                continue
            sid = parts[0]
            try:
                show = subprocess.check_output(f"loginctl show-session {sid}", shell=True, text=True)
            except Exception:
                continue
            info = dict(x.split("=", 1) for x in show.splitlines() if "=" in x)
            if info.get("Active") != "yes":
                continue
            if info.get("Remote") == "yes":
                continue
            name = info.get("Name") or info.get("User")
            if name != user:
                continue
            display = info.get("Display") or ":0"
            # Wayland heurística
            try:
                uid = pwd.getpwnam(user).pw_uid
                xdg = f"/run/user/{uid}"
                wayland = next((f for f in os.listdir(xdg) if f.startswith("wayland-")), None)
            except Exception:
                wayland = None
            return display, wayland
        return None, None

    pw = pwd.getpwnam(username)
    uid = pw.pw_uid
    xdg_runtime = f"/run/user/{uid}"
    dbus_addr = f"unix:path={xdg_runtime}/bus"

    display, wayland_display = _detect_user_session_env(username)
    env_parts = [f"XDG_RUNTIME_DIR={xdg_runtime}", f"DBUS_SESSION_BUS_ADDRESS={dbus_addr}"]
    if display:
        env_parts.append(f"DISPLAY={display}")
    if wayland_display:
        env_parts.append(f"WAYLAND_DISPLAY={wayland_display}")
    env_str = " ".join(env_parts)

    cmd = f"runuser -l {username} -c \"{env_str} setsid -f python3 '{script_path}' >/dev/null 2>&1 &\""
    _run_quiet(cmd)

def create_hostip_widget_post_upgrade():
    """
    (v2) Reinstala o tray Host/IP e garante:
      - deps instaladas (GTK+Ayatana);
      - script em /usr/local/bin/hostip_tray.py;
      - autostart global /etc/xdg/autostart/hostip-tray.desktop;
      - spawn imediato na SESSÃO GRÁFICA ativa do usuário logado (não o root).
    """
    _ensure_hostip_tray_dependencies()

    script_path = "/usr/local/bin/hostip_tray.py"
    _write_hostip_tray_script(script_path)
    _make_executable(script_path)

    # Autostart GLOBAL (para todos os usuários)
    _write_autostart_desktop_global("/etc/xdg/autostart/hostip-tray.desktop", script_path)

    # Autostart também no usuário atual (se não-root e $HOME acessível)
    try:
        home = os.path.expanduser("~")
        if home and os.path.isdir(home) and os.geteuid() != 0:
            user_autostart_dir = os.path.join(home, ".config", "autostart")
            os.makedirs(user_autostart_dir, exist_ok=True)
            _write_autostart_desktop(os.path.join(user_autostart_dir, "hostip-tray.desktop"), script_path)
    except Exception:
        pass

    # Mata instâncias antigas (qualquer usuário)
    _run_quiet("pkill -f 'hostip_tray.py' || true")

    # Tenta subir AGORA na sessão gráfica ativa (usuário logado ao desktop).
    _spawn_tray_in_active_gui_session(script_path)

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

def quarantine_b43_installer():
    """
    Quarentena do firmware-b43-installer (evita falha 404 no postinst).
    - Se não houver Broadcom detectada, remove e põe hold.
    - Se o pacote estiver meio-configurado, força remoção.
    """
    import subprocess, shlex

    # Detecta Broadcom (lspci pode não existir em todos os hosts)
    has_broadcom = False
    try:
        r = subprocess.run("command -v lspci >/dev/null 2>&1", shell=True)
        if r.returncode == 0:
            r = subprocess.run("lspci -nn | grep -i 'Broadcom' | grep -E '\\[14e4:'", shell=True)
            has_broadcom = (r.returncode == 0)
    except Exception:
        has_broadcom = False

    # Se não tem Broadcom, remove para não quebrar upgrades
    try:
        # status do pacote
        st = subprocess.run("dpkg -s firmware-b43-installer >/dev/null 2>&1", shell=True)
        if st.returncode == 0 and not has_broadcom:
            # tenta purge normal
            subprocess.run("apt-get -y remove --purge firmware-b43-installer", shell=True)
            # se ainda estiver travado, força remoção
            subprocess.run("dpkg -r --force-remove-reinstreq firmware-b43-installer || true", shell=True)
            subprocess.run("dpkg --purge --force-all firmware-b43-installer || true", shell=True)
            # impede reinstalação automática
            subprocess.run("apt-mark hold firmware-b43-installer 2>/dev/null || true", shell=True)
    except Exception:
        pass

def purge_old_kernels(keep_n: int = 2) -> None:
    """
    Remove kernels antigos (pacotes e artefatos em /boot), preservando:
    - o kernel em execução (uname -r)
    - os 'keep_n' mais recentes encontrados em /usr/lib/modules

    Evita mexer no meta-pacote linux-image-amd64 (mas pode ficar 'unconfigured' até finalizar).
    """
    import os, subprocess, glob, shlex, tempfile

    # versões conhecidas pelo sistema
    try:
        mods = [os.path.basename(p) for p in glob.glob("/usr/lib/modules/*") if os.path.isdir(p)]
    except Exception:
        mods = []

    if not mods:
        return

    # ordena por 'sort -V' para respeitar semântica de versão
    try:
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            for v in mods:
                tf.write(v + "\n")
            tf.flush()
            out = subprocess.check_output(f"sort -V {shlex.quote(tf.name)}", shell=True, text=True).splitlines()
        versions = [v.strip() for v in out if v.strip()]
    except Exception:
        versions = sorted(mods)

    # determina conjunto a manter
    try:
        running = subprocess.check_output("uname -r", shell=True, text=True).strip()
    except Exception:
        running = ""

    keep = set()
    if running:
        keep.add(running)
    keep.update(versions[-keep_n:])  # os 'keep_n' mais novos

    # versões para remover
    to_remove = [v for v in versions if v not in keep]

    for ver in to_remove:
        pkg = f"linux-image-{ver}"
        hdr = f"linux-headers-{ver}"
        # tenta purgar pacotes
        subprocess.run(f"apt-get -y purge {pkg} {hdr}", shell=True)
        subprocess.run(f"dpkg -r --force-remove-reinstreq {pkg} {hdr} || true", shell=True)
        subprocess.run(f"dpkg --purge --force-all {pkg} {hdr} || true", shell=True)
        # remove artefatos de /boot dessa versão
        for pat in (f"/boot/initrd.img-{ver}", f"/boot/vmlinuz-{ver}", f"/boot/System.map-{ver}", f"/boot/config-{ver}"):
            try:
                if os.path.exists(pat):
                    print(f"[purge_old_kernels] removendo {pat}")
                    os.remove(pat)
            except Exception as e:
                print(f"[purge_old_kernels] falha ao remover {pat}: {e}")

    # atualiza grub (não fatal)
    try:
        subprocess.run("update-grub || true", shell=True)
    except Exception:
        pass

def repair_initramfs_issues(min_free_mb: int = 900) -> None:
    """
    Tenta resolver falhas de update-initramfs:
    - libera espaço em /boot
    - remove initrd antigos e recria para cada versão em /usr/lib/modules
    - fallback de compressão (gzip) caso falhe
    """
    import os, glob, subprocess

    try:
        free_boot_space(min_free_mb)
    except Exception:
        pass

    # versões detectadas
    versions = [os.path.basename(p) for p in glob.glob("/usr/lib/modules/*") if os.path.isdir(p)]
    if not versions:
        return

    # remove initrd antigos para liberar espaço
    for ver in versions:
        try:
            subprocess.run(f"update-initramfs -d -k {ver} || true", shell=True)
        except Exception:
            pass

    try:
        free_boot_space(min_free_mb)
    except Exception:
        pass

    # recria initrd para cada versão; se falhar, tenta com gzip
    for ver in versions:
        rc = subprocess.run(f"update-initramfs -c -k {ver}", shell=True).returncode
        if rc != 0:
            print(f"[repair_initramfs_issues] Falhou com compressão padrão; tentando gzip para {ver}…")
            env = os.environ.copy()
            env["INITRAMFS_COMPRESSION"] = "gzip"  # fallback
            subprocess.run(f"update-initramfs -c -k {ver}", shell=True, env=env)


import shlex

def preconfigure_grub_pc():
    """
    (VERSÃO 2 - CORRIGIDA)
    Detecta o disco raiz do sistema (lidando com partições e BTRFS) 
    e pré-configura o debconf para o grub-pc.
    """
    print("\n[CONFIG] Verificando e pré-configurando o GRUB para evitar prompts...")
    try:
        # 1. Descobre a PARTIÇÃO raiz. Ex: /dev/sda3
        part_result = subprocess.run(
            "findmnt -n -o SOURCE /", 
            shell=True, check=True, capture_output=True, text=True
        )
        # Limpa subvolumes BTRFS se existirem. Ex: /dev/sda3[/@rootfs] -> /dev/sda3
        root_partition_path = part_result.stdout.strip().split('[')[0] 

        # 2. Descobre o DISCO PAI (PKNAME - Parent Kernel Name) dessa partição.
        # Este comando pergunta ao lsblk "Qual é o disco principal (PKNAME) de /dev/sda3?"
        # A resposta será "sda".
        disk_result = subprocess.run(
            f"lsblk -no PKNAME {shlex.quote(root_partition_path)}",
            shell=True, check=True, capture_output=True, text=True
        )
        root_disk_name = disk_result.stdout.strip() # Ex: "sda"

        if not root_disk_name:
            # Se não houver PKNAME (ex: para /dev/vda, que é o próprio disco), usa o basename
            root_disk_name = os.path.basename(root_partition_path)
            # Remove dígitos no final se for uma partição (ex: vda1 -> vda)
            root_disk_name = re.sub(r'\d+$', '', root_disk_name)

        # 3. Constrói o caminho completo do dispositivo de disco
        root_disk_device = f"/dev/{root_disk_name}" # Ex: "/dev/sda"
        
        print(f"Partição raiz: {root_partition_path}, Disco de boot inferido: {root_disk_device}")

        # 4. Cria as configurações para o debconf
        debconf_config = f"""
grub-pc grub-pc/install_devices string {root_disk_device}
grub-pc grub-pc/install_devices_empty boolean false
"""
        
        # 5. Aplica as configurações
        process = subprocess.Popen(['debconf-set-selections'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=debconf_config)

        if process.returncode == 0:
            print(f"✅ GRUB pré-configurado para instalar em '{root_disk_device}'.")
        else:
            print(f"[ERRO] Falha ao pré-configurar o GRUB via debconf (código: {process.returncode}).")

    except Exception as e:
        print(f"[AVISO] Falha ao autodetectar disco do GRUB. A atualização pode falhar ou pedir prompts: {e}")

# ============================================================================

def main():
    """
    Função principal que orquestra todo o processo de atualização do Debian.
    """
    print("=== Script de Atualização do Debian ===")

    # 1. Inicia a interface gráfica para feedback ao usuário
    ok_ui = start_upgrade_ui_zenity_progress()
    if ok_ui:
        zenity_progress_set(2, "Detectando versão do Debian…")

    # ================================================================= #
    # ADIÇÃO IMPORTANTE AQUI                                            #
    # Pré-configura o GRUB antes de qualquer outra coisa para evitar erros. #
    # ================================================================= #
    preconfigure_grub_pc()

    ret = 1  # Código de saída padrão (1 = erro, 0 = sucesso)
    try:
        # 2. Verifica a versão atual do sistema
        debian_version = get_debian_version()
        if debian_version is None:
            print("Não foi possível determinar a versão do Debian. Abortando.")
            if ok_ui: end_upgrade_ui_zenity(success=False)
            return 1

        # 3. Executa o upgrade do sistema operacional base
        ok_os_upgrade = False
        if debian_version < 13:
            print(f"Sistema em Debian {debian_version}. Iniciando processo de upgrade para a versão 13...")
            if ok_ui:
                zenity_progress_set(10, f"Atualizando de Debian {debian_version} -> 13. Isso pode levar muito tempo...")
            
            ok_os_upgrade = ensure_debian_stepwise_to_13()
            if not ok_os_upgrade:
                print("\n[ERRO FATAL] Falha ao atualizar o sistema para a base do Debian 13.")
        else:
            print(f"Sistema em Debian {debian_version}. Executando atualização de pacotes...")
            if ok_ui:
                zenity_progress_set(10, f"Atualizando pacotes no Debian {debian_version}...")
            
            ok_os_upgrade = run_robust_upgrade()

        if not ok_os_upgrade:
            print("\n[ERRO FATAL] A atualização do sistema operacional base falhou. Abortando.")
            if ok_ui: end_upgrade_ui_zenity(success=False)
            return 1

        print("\n✅ Upgrade do sistema operacional base concluído com sucesso.")

        # 4. Executa tarefas pós-upgrade
        print("\nIniciando tarefas pós-upgrade...")
        if ok_ui:
            zenity_progress_set(75, "Executando tarefas pós-upgrade...")

        # ... (resto da sua função main continua igual) ...

        if ok_ui: zenity_progress_set(78, "Higienizando listas de repositórios…")
        clean_sources_list()
        clean_sources_list_d()
        ensure_debian_archive_keyring()

        if ok_ui: zenity_progress_set(82, "Garantindo Firefox ESR ≥ 128…")
        ensure_firefox_esr_min_128()

        if ok_ui: zenity_progress_set(88, "Instalando Google Chrome (stable)…")
        install_chrome_stable_quick(reenable=False)

        if ok_ui: zenity_progress_set(94, "Instalando Google Earth…")
        install_google_earth_stable_quick(reenable=False)

        if ok_ui: zenity_progress_set(98, "Ajustando widget Host/IP…")
        create_hostip_widget_post_upgrade()

        print("\nProcesso de atualização totalmente concluído!")
        ret = 0 

    except Exception as e:
        import traceback
        print("\n[ERRO INESPERADO] Uma exceção não tratada ocorreu no processo principal:")
        traceback.print_exc()
        ret = 1

    finally:
        # 5. Finaliza a interface gráfica
        if ok_ui:
            if ret == 0:
                zenity_progress_set(100, "Concluído com sucesso! É recomendado reiniciar o computador.")
                end_upgrade_ui_zenity(success=True)
            else:
                zenity_progress_set(100, "Processo concluído com erros. Verifique os logs no terminal.")
                end_upgrade_ui_zenity(success=False)
        
        print(f"\nScript finalizado com código de saída: {ret}")
        return ret

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
