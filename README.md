Atualizador.py:
#  Atualizador Automático Debian (Demo)

Este repositório apresenta uma **versão demonstrativa** de um projeto desenvolvido por mim durante meu estágio na **Prefeitura de Jaraguá do Sul**.  
O código real em produção não pode ser publicado por motivos de **segurança e confidencialidade**, mas este exemplo mostra como automatizo o processo de atualização em sistemas Linux/Debian.

---

##  O que este script faz
- Atualiza automaticamente pacotes em sistemas **Debian/Ubuntu**;
- Executa comandos como `apt update`, `apt upgrade` e `apt dist-upgrade` de forma não interativa;
- Trata erros comuns durante o processo de atualização;
- Gera **logs detalhados** para auditoria;
- Pode ser integrado com automações maiores (ex.: scanner de rede que envia o `Atualizador.py` para máquinas desatualizadas).

---

##  Pré-requisitos
- Sistema baseado em **Debian/Ubuntu**;
- Python 3.8+ instalado;
- Permissões administrativas (root ou sudo).

---

##  Como usar
Clone este repositório e execute o script em uma máquina Debian:




Computadores.py

#  Scanner de Rede Linux + Envio do Atualizador (DEMO / Vitrine)

Este repositório apresenta **um dos projetos que desenvolvi na Prefeitura de Jaraguá do Sul**.  
Por **segurança e confidencialidade**, o sistema completo usado em produção **não é publicado**.  
Aqui você encontra uma **versão demonstrativa** que preserva o fluxo principal, removendo apenas informações sensíveis.

## O que este projeto faz
- Varre redes `192.168.x.x` para identificar máquinas Linux acessíveis por **SSH**;
- Coleta versões de **Debian**, **Chrome/Chromium** e **Firefox/ESR**;
- Gera relatórios (`ip-*.txt`, `RESUMO_GERAL_LINUX_MACHINES.txt`, `FINAL_ATUALIZAR.txt` e `.csv`);
- **Opcionalmente**, envia um `Atualizador.py` (payload) para **IPs específicos** definidos por você e executa remotamente.

 O objetivo desta vitrine é demonstrar minha experiência prática em **automação com Python**, **infraestrutura Linux** e **operações remotas seguras**.

## Segurança / Sigilo
- Removi **usuário, senha, IPs e caminhos internos** do código.  
- As credenciais e IPs de destino agora são passados por **variáveis de ambiente**:
  - `SSH_USER` e `SSH_PASS`  
  - `TARGET_IPS` (ex.: `192.168.8.24,192.168.8.50`)  
  - `PAYLOAD_DIR` (padrão `./payload`), `REMOTE_DIR` (padrão `/tmp/Atualizacao_automatica`)
- Removido trecho que escrevia em `/etc/hosts`.

## Pré-requisitos
- Python 3.9+
- `paramiko`:
  ```bash
  pip install paramiko
