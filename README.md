<a href="https://www.fiap.com.br/">
<img src="img/fiap.png" width="140" height="50">
</a> <br>

<a href="https://www.instagram.com/fiapoficial/">
<img src="img/ig.png">
</a>
<a href="https://www.youtube.com/@FiapBrasil">
<img src="img/yt.png">
</a>

# ScanMatrix-Pro v3.0


<br>

# Portuguese

## Descrição

ScanMatrix-Pro é uma ferramenta interativa de varredura de rede e análise de fingerprint. Utiliza o scanner Nmap para fornecer varreduras de portas detalhadas e análises de serviços em execução em servidores. Ideal para profissionais de segurança e administradores de rede.

- Editor Utilizado: <a href="https://code.visualstudio.com/"> Visual Studio Code</a>.

- [Video Prático](https://youtu.be/km3sJ0UuA_Y)


- <a href="https://www.canva.com/design/DAFsTMwdLGM/by-TbKnWTFWG01jTlOgCRA/view?utm_content=DAFsTMwdLGM&utm_campaign=designshare&utm_medium=link&utm_source=publishsharelink"> Slides
  </a><br>

## Funcionalidades

- Varreduras TCP SYN
- Varreduras TCP Connect
- Varreduras UDP
- Varreduras Agressivas
- Varreduras Customizadas
- Análises de Fingerprint (Fiware, PhpMyAdmin)

## Requisitos

- Python 3.x
- [Nmap](https://pypi.org/project/python-nmap/)
- Permissões de administrador

## Ambiente de testes

<img src="img/image.png">

## Instalação

```bash
git clone https://github.com/seu_usuario/ScanMatrix-Pro.git
cd ScanMatrix-Pro
```
<!-- pip install -r requirements.txt -->

## Uso

Execute o script com privilégios de administrador para todas as funcionalidades:

```bash
sudo ./scanmatrixpro.py
```

Siga as instruções no terminal.

## Explicação das Ferramentas Utilizadas

### Biblioteca `time`

A biblioteca `time` em Python fornece várias funções relacionadas ao tempo. É usada no projeto principalmente para adicionar atrasos entre as varreduras, garantindo que o script não sobrecarregue a rede ou o servidor alvo.

```python
import time
time.sleep(3)  # Pausa a execução por 3 segundos
```

### Biblioteca `nmap`

A biblioteca `python-nmap` é uma interface em Python para a ferramenta de varredura de porta Nmap. Ela permite que você execute varreduras Nmap diretamente do Python, tornando mais fácil integrar as funcionalidades do Nmap em aplicações Python.

```python
import nmap
nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443')
```

### Biblioteca `xml.etree.ElementTree`

A biblioteca `xml.etree.ElementTree` é usada para analisar e criar dados XML. No contexto deste projeto, é provavelmente utilizada para analisar os dados XML retornados pelo Nmap.

```python
import xml.etree.ElementTree as ET
tree = ET.parse('nmap_output.xml')
root = tree.getroot()
```

# Explicação do código

## Importações e Configurações Iniciais

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import xml.etree.ElementTree
import time
```

### Explicação

1. `#!/usr/bin/python3`: Esta é uma shebang que define o interpretador Python a ser usado. Neste caso, ele especifica o Python 3.
2. `# -*- coding: utf-8 -*-`: Isso define a codificação de caracteres do arquivo para UTF-8.
3. `import nmap`: Importa a biblioteca `nmap` para escanear portas.
4. `import xml.etree.ElementTree`: Importa a biblioteca `xml.etree.ElementTree` para lidar com arquivos XML.
5. `import time`: Importa a biblioteca `time` para manipulações relacionadas ao tempo.

---

## Classe de Cores

```python
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
```

### Explicação

A classe `Colors` define constantes para diferentes códigos de escape ANSI, que podem ser usados para colorir o texto do terminal. Cada constante armazena uma string que representa um código de escape específico.

---

## Função Line

```python
def line():
	print("========================================================================")
```

### Explicação

A função `line()` imprime uma linha de sinais de igual (`=`) no console. Isso pode ser usado para separar diferentes seções de saída no terminal.


## Explicação do `nmap_scan()`


```python
def nmap_scan(argument, scan_type_name):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
```

Nesta parte, a função pede ao usuário para fornecer um endereço de host. Ele usa a classe `Colors` para a saída colorida.

```python
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
```

Se o usuário não fornecer um endereço de host, ele será definido como "0.0.0.0" por padrão.

```python
		range = input(Colors.BLUE + "Provide a valid Range or Port/Ports | Example: 1-1024 \n" + Colors.ENDC + ': ')
		if range == '':
			range = "1-1024"
		print(Colors.WARNING + f"Range: {range}" + Colors.ENDC)
		line()
```

Esta seção pede ao usuário para fornecer uma faixa de portas ou portas específicas para a varredura. Se nenhum valor for fornecido, o padrão será "1-1024".

```python
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
```

Esta seção pede ao usuário se ele deseja salvar os resultados em um arquivo externo. 

```python
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, range, arguments=argument)
		time.sleep(3)
```

Esta parte final da função inicia a varredura usando a biblioteca `nmap`. Ela usa os endereços de host e a faixa de portas fornecidos. Também há uma espera de 3 segundos, provavelmente para garantir que a varredura tenha tempo para começar.

## Configuração e Inputs do Usuário

```python
def nmap_scan(argument, scan_type_name):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		range = input(Colors.BLUE + "Provide a valid Range or Port/Ports | Example: 1-1024 \n" + Colors.ENDC + ': ')
		if range == '':
			range = "1-1024"
		print(Colors.WARNING + f"Range: {range}" + Colors.ENDC)
		line()
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, range, arguments=argument)
		time.sleep(3)
```

### Descrição

- Esta seção do código é responsável por coletar os parâmetros de entrada do usuário.
  - `host_address`: O endereço IP do host a ser escaneado.
  - `range`: A faixa de portas a serem escaneadas.
  - `save_in_file`: Um booleano que determina se os resultados devem ser salvos em um arquivo ou não.
- `nm.scan()`: Esta linha inicia o scan nmap usando as informações fornecidas.

---

## Processamento e Saída da Varredura

```python
for host in nm.all_hosts():
	if nm[host].state() == "down":
		print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
	else:
		if save_in_file:
			with open('scan_report.txt', 'w') as report:
				report.write("========================================================================\n")
				report.write(f"Nmap version: {nm.nmap_version()}\n")
				report.write(f"Scan type: {scan_type_name}\n")
				report.write(f"Host: {host} | {nm[host].hostname()}\n")
				report.write(f"State: {nm[host].state()}\n")
				report.write("========================================================================\n")
		print(Colors.HEADER + "Nmap version: " + Colors.ENDC + f"{nm.nmap_version()}")
		print(Colors.HEADER + "Scan type: " + Colors.ENDC + scan_type_name)
		print(Colors.HEADER + 'Host: ' + Colors.ENDC + f'{host} | {nm[host].hostname()}')
		print(Colors.HEADER + 'State: ' + Colors.ENDC + f'{nm[host].state()}')
		for proto in nm[host].all_protocols():
			line()
			print(f'Protocol : {proto}')	
			lport = nm[host][proto].keys()
			for port in lport:
				state = nm[host][proto][port]['state']
				service_name = nm[host][proto][port]['name']
				if save_in_file:
					with open('scan_report.txt', 'a') as report:
						report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
				print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
						  Colors.GREEN + f'State : {state}\t\t' + 
						  Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
	except xml.etree.ElementTree.ParseError:
		print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
	except nmap.PortScannerError:
		print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
```

### Descrição

- Este loop percorre todos os hosts que foram escaneados.
  - Se o estado do host for "down", ele exibe uma mensagem de erro.
  - Se o estado do host for "up", ele processa e imprime detalhes como versão do Nmap, tipo de varredura, host, estado, protocolo, portas, e o estado das portas.
- Além disso, se `save_in_file` for verdadeiro, ele salva esses detalhes em um arquivo chamado `scan_report.txt`.
- O código também lida com exceções específicas que podem ocorrer durante a execução.

---

## Função `fingerprint_scan(argument)`

```python
def fingerprint_scan(argument):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address | Recommended: 0.0.0.0\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
```

Neste bloco, a função `fingerprint_scan` é definida. Ele começa solicitando um endereço de host válido do usuário. Se o usuário não fornecer um endereço, o padrão será `0.0.0.0`. Em seguida, ele exibe o endereço do host fornecido ou o padrão.

```python
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
```

Nesta seção, o script pergunta ao usuário se ele deseja salvar os resultados em um arquivo externo. Se o usuário responder com "Y" ou "YES", a variável `save_in_file` será definida como `True`.

```python
		# fiware fingerprint
		fiware_range = "1026, 1883, 4041, 8666, 9001, 27017"
		fiware_ports = ["1026", "1883", "4041", "8666", "9001", "27017"]
		fiware_status = []
		# phpmyadmin fingerprint
		phpmyadmin_range = "80, 443, 3306"
		phpmyadmin_ports = ["80", "443", "3306"]
		phpmyadmin_status = []
```

Nesta parte, duas diferentes "impressões digitais" são definidas. Uma para o Fiware e outra para o phpMyAdmin. Cada impressão digital tem um conjunto de portas que serão verificadas durante o scan.

```python
		# fiware scan
		nm.scan(host_address, fiware_range, arguments=argument)
		time.sleep(3)
```

Por fim, esta seção inicia um scan para o conjunto de portas definido para Fiware usando a função `nm.scan()`. O código também aguarda 3 segundos (`time.sleep(3)`) antes de prosseguir, provavelmente para dar tempo ao scan de ser concluído.

```python
for host in nm.all_hosts():
	if nm[host].state() == "down":
		print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
		line()
	else:
```

Este bloco itera através de todos os hosts retornados pelo scan. Se o estado do host estiver como "down", ele imprimirá uma mensagem de erro e chamará a função `line()` para adicionar uma linha divisória. Caso contrário, ele segue para a análise mais detalhada do host.

```python
		if save_in_file:
			with open('fingerprint_report.txt', 'w') as report:
				report.write("========================================================================\n")
				report.write("* Fingerprint Analysis *\n")
				report.write("========================================================================\n")
		print(Colors.HEADER + "* Fingerprint Analysis *" + Colors.ENDC)
```

Aqui, se a opção `save_in_file` estiver ativa, ele abre (ou cria) um arquivo chamado `fingerprint_report.txt` e escreve os cabeçalhos da análise de impressões digitais.

```python
		for proto in nm[host].all_protocols():
			line()
			print(f'Protocol : {proto}')
			lport = nm[host][proto].keys()
			for port in lport:
				state = nm[host][proto][port]['state']
				service_name = nm[host][proto][port]['name']
```

Esse loop aninhado percorre todos os protocolos do host e, dentro de cada protocolo, percorre todas as portas para recuperar seu estado e nome do serviço.

```python
				if save_in_file:
					with open('fingerprint_report.txt', 'a') as report:
						report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
				print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
						Colors.GREEN + f'State : {state}\t\t' + 
						Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
```

Aqui, o estado e nome do serviço de cada porta são escritos tanto no arquivo `fingerprint_report.txt` (se a opção `save_in_file` estiver ativada) como impressos na saída padrão.

```python
				if not port in fiware_ports and state == "open":
					fiware_status.append(1)
				else:
					fiware_status.append(0)
```

Por último, este bloco verifica se a porta em questão não está na lista `fiware_ports` e se o estado da porta está "aberto". Se ambas as condições forem verdadeiras, ele adiciona `1` à lista `fiware_status`. Caso contrário, adiciona `0`.


```python
if not 0 in fiware_status:
	line()
	print("[!] " + Colors.WARNING + '"Fiware" Detected on server' + Colors.ENDC)
	if save_in_file:
		with open('fingerprint_report.txt', 'a') as report:
			report.write("========================================================================\n")
			report.write('[!] "Fiware" Detected on server\n')
			report.write("========================================================================\n")
else:
	line()
	print("[!] " + Colors.FAIL + '"Fiware" Undetected' + Colors.ENDC)
	with open('fingerprint_report.txt', 'a') as report:
		report.write("========================================================================\n")
		report.write('[!] "Fiware" Undetected\n')
		report.write("========================================================================\n")
line()
```

Neste bloco, o programa verifica se algum `0` está presente na lista `fiware_status`. Isso é importante porque `1` foi adicionado à lista quando uma porta não estava na lista `fiware_ports` e estava aberta. Portanto, se a lista não contiver `0`, isso sugere que todas as portas relevantes para o "Fiware" estão abertas e ativas.

- **Se "Fiware" for detectado**: 
	- Uma linha é impressa para separação visual.
	- Uma mensagem de alerta é exibida.
	- Se a opção `save_in_file` estiver ativada, a detecção de "Fiware" também será registrada no arquivo `fingerprint_report.txt`.

- **Se "Fiware" não for detectado**:
	- Uma linha é impressa para separação visual.
	- Uma mensagem de falha é exibida.
	- A informação também é escrita no arquivo `fingerprint_report.txt`, independentemente da opção `save_in_file`.

O último comando `line()` imprime uma linha divisória para tornar a saída mais fácil de ler.

## phpmyadmin scan

```python
nm.scan(host_address, phpmyadmin_range, arguments=argument)
time.sleep(3)
for host in nm.all_hosts():
    if nm[host].state() == "down":
        print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
        line()
    else:
        for proto in nm[host].all_protocols():
            print(f'Protocol : {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                if save_in_file:
                    with open('fingerprint_report.txt', 'a') as report:
                        report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
                state = nm[host][proto][port]['state']
                service_name = nm[host][proto][port]['name']
                print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
                          Colors.GREEN + f'State : {state}\t\t' + 
                          Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
                if not port in phpmyadmin_ports and state == "open":
                    phpmyadmin_status.append(1)
                else:
                    phpmyadmin_status.append(0)
        if not 0 in phpmyadmin_status:
            line()
            print("[!] " + Colors.WARNING + '"PhpMyAdmin" Can be on server' + Colors.ENDC)
            if save_in_file:
                with open('fingerprint_report.txt', 'a') as report:
                    report.write("========================================================================\n")
                    report.write('[!] "PhpMyAdmin" Can be on server\n')
                    report.write("========================================================================\n")
        else:
            line()
            print("[!] " + Colors.FAIL + '"PhpMyAdmin" Undetected' + Colors.ENDC)
            with open('fingerprint_report.txt', 'a') as report:
                report.write("========================================================================\n")
                report.write('[!] "PhpMyAdmin" Undetected\n')
                report.write("========================================================================\n")
line()
```

### Explicação:

Este bloco de código realiza uma varredura para detectar a presença do PhpMyAdmin em hosts específicos. Aqui estão os detalhes:

- `nm.scan(host_address, phpmyadmin_range, arguments=argument)`: Esta linha inicia uma varredura usando o objeto `nm` (instância da classe `nmap.PortScanner()`) para procurar o PhpMyAdmin no intervalo de endereços `phpmyadmin_range` com os argumentos `argument`.
- `time.sleep(3)`: Aguarda por 3 segundos antes de continuar com a próxima parte do código.
- `for host in nm.all_hosts():`: Um loop itera por todos os hosts encontrados na varredura.
- Verifica-se o estado do host. Se estiver "down", exibe uma mensagem de erro. Caso contrário, prossegue com a análise dos protocolos e portas.
- `for proto in nm[host].all_protocols():`: Itera pelos protocolos disponíveis no host.
- Para cada protocolo, é iterada a lista de portas `lport` e as informações são coletadas. Se `save_in_file` estiver ativo, as informações são registradas em um arquivo 'fingerprint_report.txt'.
- As variáveis `state` e `service_name` são definidas com base nas informações coletadas.
- As informações da porta, estado e nome do serviço são impressas, com cores destacadas para melhor legibilidade.
- Verifica-se se a porta não está na lista de portas PhpMyAdmin (`phpmyadmin_ports`) e se o estado da porta é "open". Se ambas as condições forem verdadeiras, é adicionado um valor "1" à lista `phpmyadmin_status`, indicando que o PhpMyAdmin pode estar presente.
- Caso contrário, é adicionado um valor "0" à lista `phpmyadmin_status`.
- Após analisar todas as portas, verifica-se se a lista `phpmyadmin_status` não contém o valor "0". Se for o caso, exibe-se uma mensagem indicando que o PhpMyAdmin pode estar presente.
- Caso contrário, exibe-se uma mensagem indicando que o PhpMyAdmin não foi detectado.
- O bloco de código é encerrado com a função `line()` para separar visualmente os resultados.


## Cabeçalho e saudação

```python
nm = nmap.PortScanner()

print(Colors.HEADER + "  ____                      __  __         _          _              ____               " + Colors.ENDC)
print(Colors.HEADER + " / ___|   ___  __ _  _ __  |  \/  |  __ _ | |_  _ __ (_)__  __      |  _ \  _ __  ___   " + Colors.ENDC)
print(Colors.HEADER + " \___ \  / __|/ _` || '_ \ | |\/| | / _` || __|| '__|| |\ \/ /_____ | |_) || '__|/ _ \  " + Colors.ENDC)
print(Colors.HEADER + "  ___) || (__| (_| || | | || |  | || (_| || |_ | |   | | >  <|_____||  __/ | |  | (_) | " + Colors.ENDC)
print(Colors.HEADER + " |____/  \___|\__,_||_| |_||_|  |_| \__,_| \__||_|   |_|/_/\_\      |_|    |_|   \___/  \n" + Colors.ENDC)
print(Colors.FAIL + "                                                      ScanMatrix-Pro v3.0 - by Renan D. " + Colors.ENDC)
```

### Explicação:

Este bloco de código define o cabeçalho do programa e exibe uma saudação ao usuário.

1. `nm = nmap.PortScanner()`: Cria uma instância da classe `nmap.PortScanner()` que será usada para executar varreduras.
2. `print()` é usado para exibir o cabeçalho e a saudação. A formatação com `Colors.HEADER`, `Colors.ENDC` e `Colors.FAIL` é usada para dar estilo aos textos.
3. O cabeçalho é exibido com texto estilizado que forma um logotipo ou título do programa, juntamente com a versão (v3.0) e o autor (Renan D.).


## Loop de seleção de tipo de varredura

```python
while True:
    try:
        type_scan = int(input(Colors.BLUE + "Select a option:" + Colors.ENDC + "\n[1] TCP SYN scan\n[2] TCP connect scan\n[3] UDP scan\n[4] Aggressive scan\n[5] Custom scan\n[6] Fingerprint Analysis\n[7] Exit\n: "))
        line()
        # TCP SYN scan
        if type_scan == 1:
            try:
                nmap_scan('-sS', 'TCP SYN scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # TCP connect scan
        elif type_scan == 2:
            try:
                nmap_scan('-sT', 'TCP connect scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # UDP scan
        elif type_scan == 3:
            try:
                nmap_scan('-sU', 'UDP scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Aggressive scan
        elif type_scan == 4:
            try:
                nmap_scan('-A', 'Aggressive scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Custom Scan
        elif type_scan == 5:
            try:
                custom_arguments = input(Colors.BLUE + "Provide a valid Arguments | Example: --open -sS" + Colors.ENDC + "\n: ")
                print(Colors.WARNING + f"Arguments: {custom_arguments}" + Colors.ENDC)
                line()
                nmap_scan(custom_arguments, 'Custom Scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Fingerprint Detect
        elif type_scan == 6:
            fingerprint_scan("")
        # Exit
        elif type_scan == 7:
            print(Colors.HEADER + 'Until later :D')
            exit()
        # Error
        else:
            print(Colors.FAIL + "Non-existent option | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
            line()
    except ValueError:
        line()
        print(Colors.FAIL + "Value error | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
        line()
```

### Explicação:

Este bloco de código implementa um loop que permite ao usuário selecionar o tipo de varredura a ser executado. Aqui está a explicação detalhada:

- Um loop `while True:` é usado para manter o programa em execução até que o usuário decida sair.
- O usuário é solicitado a selecionar uma opção usando `input()`. A entrada é convertida em um número inteiro com `int()`.
- Após a seleção, uma linha em branco é impressa para separar visualmente as saídas.
- A estrutura `if` verifica qual opção foi escolhida e executa o bloco de código correspondente:
   - Se `type_scan` for igual a 1, é iniciada uma varredura TCP SYN usando `nmap_scan('-sS', 'TCP SYN scan')`.
   - Se `type_scan` for igual a 2, é iniciada uma varredura TCP connect usando `nmap_scan('-sT', 'TCP connect scan')`.
   - Se `type_scan` for igual a 3, é iniciada uma varredura UDP usando `nmap_scan('-sU', 'UDP scan')`.
   - Se `type_scan` for igual a 4, é iniciada uma varredura agressiva usando `nmap_scan('-A', 'Aggressive scan')`.
   - Se `type_scan` for igual a 5, o usuário pode fornecer argumentos personalizados para a varredura. Os argumentos são coletados usando `input()`. Os argumentos fornecidos são impressos e, em seguida, a função `nmap_scan()` é chamada com os argumentos personalizados.
   - Se `type_scan` for igual a 6, é realizada a detecção de impressão digital usando `fingerprint_scan("")`.
   - Se `type_scan` for igual a 7, a mensagem "Until later :D" é impressa e o programa é encerrado com `exit()`.
   - Se `type_scan` não corresponder a nenhuma opção, uma mensagem de erro é exibida.
- Se ocorrer um erro de `ValueError` (entrada inválida), uma mensagem de erro é exibida.

<br>

# English

## Description

ScanMatrix-Pro is an interactive network scanning and fingerprint analysis tool. It utilizes the Nmap scanner to provide detailed port scans and analyses of running services on servers. Ideal for security professionals and network administrators.

- Used Editor: [Visual Studio Code](https://code.visualstudio.com/).

- [Video Practical](https://youtu.be/km3sJ0UuA_Y).

- [Slides](https://www.canva.com/design/DAFsTMwdLGM/by-TbKnWTFWG01jTlOgCRA/view?utm_content=DAFsTMwdLGM&utm_campaign=designshare&utm_medium=link&utm_source=publishsharelink)<br>

## Features

- TCP SYN Scans
- TCP Connect Scans
- UDP Scans
- Aggressive Scans
- Custom Scans
- Fingerprint Analysis (Fiware, PhpMyAdmin)

## Requirements

- Python 3.x
- [Nmap](https://pypi.org/project/python-nmap/)
- Administrator permissions for some scans


## Test environment

<img src="img/image.png">

## Installation

```bash
git clone https://github.com/seu_usuario/ScanMatrix-Pro.git
cd ScanMatrix-Pro
```
<!-- pip install -r requirements.txt -->


## Usage

Run the script with administrator privileges for all functionalities:

```bash
sudo ./scanmatrixpro.py
```

Follow the instructions in the terminal.

## Explanation of Used Tools

### Library `time`

The `time` library in Python provides various functions related to time. It is primarily used in the project to add delays between scans, ensuring that the script does not overwhelm the network or the target server.

```python
import time
time.sleep(3)
```

### Library `nmap`

The `python-nmap` library is a Python interface for the Nmap port scanning tool. It allows you to run Nmap scans directly from Python, making it easier to integrate Nmap's functionalities into Python applications.

```python
import nmap
nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443')
```

### Library `xml.etree.ElementTree`

The `xml.etree.ElementTree` library is used for parsing and creating XML data. In the context of this project, it's likely used to parse the XML data returned by Nmap.

```python
import xml.etree.ElementTree as ET
tree = ET.parse('nmap_output.xml')
root = tree.getroot()
```

# Explanation of the Code

## Imports and Initial Configurations

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import xml.etree.ElementTree
import time
```

### Explanation

1. `#!/usr/bin/python3`: This is a shebang that specifies the Python interpreter to be used. In this case, it specifies Python 3.
2. `# -*- coding: utf-8 -*-`: This sets the character encoding of the file to UTF-8.
3. `import nmap`: Imports the `nmap` library for port scanning.
4. `import xml.etree.ElementTree`: Imports the `xml.etree.ElementTree` library for handling XML files.
5. `import time`: Imports the `time` library for time-related manipulations.

---

## Color Class

```python
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
```

### Explanation

The `Colors` class defines constants for different ANSI escape codes, which can be used to colorize terminal text. Each constant stores a string that represents a specific escape code.

---

## Line Function

```python
def line():
	print("========================================================================")
```

### Explanation

The `line()` function prints a line of equal signs (`=`) in the console. This can be used to separate different sections of output in the terminal.

# Explanation of the `nmap_scan()` 

```python
def nmap_scan(argument, scan_type_name):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
```
In this part, the function asks the user to provide a host address. It utilizes the `Colors` class for colored output.

```python
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
```

If the user doesn't provide a host address, it will be set to "0.0.0.0" by default.

```python
		range = input(Colors.BLUE + "Provide a valid Range or Port/Ports | Example: 1-1024 \n" + Colors.ENDC + ': ')
		if range == '':
			range = "1-1024"
		print(Colors.WARNING + f"Range: {range}" + Colors.ENDC)
		line()
```

This section prompts the user to provide a range of ports or specific ports for scanning. If no value is provided, the default will be "1-1024".

```python
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
```

This section asks the user if they want to save the results to an external file.

```python
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, range, arguments=argument)
		time.sleep(3)
```

This final part of the function initiates the scan using the `nmap` library. It uses the provided host address and port range. The 3-second delay is likely there to ensure that the scan has enough time to start.

## User Configuration and Inputs

```python
def nmap_scan(argument, scan_type_name):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		range = input(Colors.BLUE + "Provide a valid Range or Port/Ports | Example: 1-1024 \n" + Colors.ENDC + ': ')
		if range == '':
			range = "1-1024"
		print(Colors.WARNING + f"Range: {range}" + Colors.ENDC)
		line()
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, range, arguments=argument)
		time.sleep(3)
```

### Description

- This section of the code is responsible for collecting the user's input parameters.
  - `host_address`: The IP address of the host to be scanned.
  - `range`: The range of ports to be scanned.
  - `save_in_file`: A boolean that determines whether the results should be saved to a file or not.
- `nm.scan()`: This line initiates the nmap scan using the provided information.

---

## Scanning Processing and Output

```python
for host in nm.all_hosts():
	if nm[host].state() == "down":
		print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
	else:
		if save_in_file:
			with open('scan_report.txt', 'w') as report:
				report.write("========================================================================\n")
				report.write(f"Nmap version: {nm.nmap_version()}\n")
				report.write(f"Scan type: {scan_type_name}\n")
				report.write(f"Host: {host} | {nm[host].hostname()}\n")
				report.write(f"State: {nm[host].state()}\n")
				report.write("========================================================================\n")
		print(Colors.HEADER + "Nmap version: " + Colors.ENDC + f"{nm.nmap_version()}")
		print(Colors.HEADER + "Scan type: " + Colors.ENDC + scan_type_name)
		print(Colors.HEADER + 'Host: ' + Colors.ENDC + f'{host} | {nm[host].hostname()}')
		print(Colors.HEADER + 'State: ' + Colors.ENDC + f'{nm[host].state()}')
		for proto in nm[host].all_protocols():
			line()
			print(f'Protocol : {proto}')	
			lport = nm[host][proto].keys()
			for port in lport:
				state = nm[host][proto][port]['state']
				service_name = nm[host][proto][port]['name']
				if save_in_file:
					with open('scan_report.txt', 'a') as report:
						report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
				print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
						  Colors.GREEN + f'State : {state}\t\t' + 
						  Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
	except xml.etree.ElementTree.ParseError:
		print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
	except nmap.PortScannerError:
		print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
```

### Description

- This loop iterates through all the hosts that were scanned.
  - If the host's state is "down," it displays an error message.
  - If the host's state is "up," it processes and prints details such as Nmap version, scan type, host, state, protocol, ports, and port states.
- Additionally, if `save_in_file` is true, it saves these details to a file named `scan_report.txt`.
- The code also handles specific exceptions that might occur during execution.

---

## `fingerprint_scan(argument)` Function

```python
def fingerprint_scan(argument):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address | Recommended: 0.0.0.0\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
```

In this block, the `fingerprint_scan` function is defined. It starts by requesting a valid host address from the user. If the user doesn't provide an address, the default will be `0.0.0.0`. Then, it displays the provided or default host address.

```python
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
```

In this section, the script asks the user if they want to save the results to an external file. If the user responds with "Y" or "YES", the `save_in_file` variable will be set to `True`.

```python
		# fiware fingerprint
		fiware_range = "1026, 1883, 4041, 8666, 9001, 27017"
		fiware_ports = ["1026", "1883", "4041", "8666", "9001", "27017"]
		fiware_status = []
		# phpmyadmin fingerprint
		phpmyadmin_range = "80, 443, 3306"
		phpmyadmin_ports = ["80", "443", "3306"]
		phpmyadmin_status = []
```

In this part, two different "fingerprints" are defined, one for Fiware and another for phpMyAdmin. Each fingerprint has a set of ports that will be checked during the scan.

```python
		# fiware scan
		nm.scan(host_address, fiware_range, arguments=argument)
		time.sleep(3)
```

Finally, this section initiates a scan for the set of ports defined for Fiware using the `nm.scan()` function. The code also waits for 3 seconds (`time.sleep(3)`) before proceeding, likely to give the scan enough time to complete.

```python
for host in nm.all_hosts():
	if nm[host].state() == "down":
		print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
		line()
	else:
```

This block iterates through all the hosts returned by the scan. If the host's state is "down", it will print an error message and call the `line()` function to add a divider line. Otherwise, it proceeds to the more detailed analysis of the host.

```python
		if save_in_file:
			with open('fingerprint_report.txt', 'w') as report:
				report.write("========================================================================\n")
				report.write("* Fingerprint Analysis *\n")
				report.write("========================================================================\n")
		print(Colors.HEADER + "* Fingerprint Analysis *" + Colors.ENDC)
```

Here, if the `save_in_file` option is active, it opens (or creates) a file named `fingerprint_report.txt` and writes the headers for the fingerprint analysis.

```python
		for proto in nm[host].all_protocols():
			line()
			print(f'Protocol : {proto}')
			lport = nm[host][proto].keys()
			for port in lport:
				state = nm[host][proto][port]['state']
				service_name = nm[host][proto][port]['name']
```

This nested loop iterates through all the protocols of the host, and within each protocol, it iterates through all the ports to retrieve their state and service name.

```python
				if save_in_file:
					with open('fingerprint_report.txt', 'a') as report:
						report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
				print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
						Colors.GREEN + f'State : {state}\t\t' + 
						Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
```

Here, the state and service name of each port are written to both the `fingerprint_report.txt` file (if the `save_in_file` option is active) and printed to the standard output.

```python
				if not port in fiware_ports and state == "open":
					fiware_status.append(1)
				else:
					fiware_status.append(0)
```

Lastly, this block checks if the current port is not in the fiware_ports list and if the port's state is "open". If both conditions are true, it appends 1 to the fiware_status list. Otherwise, it appends 0.

```python
if not 0 in fiware_status:
	line()
	print("[!] " + Colors.WARNING + '"Fiware" Detected on server' + Colors.ENDC)
	if save_in_file:
		with open('fingerprint_report.txt', 'a') as report:
			report.write("========================================================================\n")
			report.write('[!] "Fiware" Detected on server\n')
			report.write("========================================================================\n")
else:
	line()
	print("[!] " + Colors.FAIL + '"Fiware" Undetected' + Colors.ENDC)
	with open('fingerprint_report.txt', 'a') as report:
		report.write("========================================================================\n")
		report.write('[!] "Fiware" Undetected\n')
		report.write("========================================================================\n")
line()
```

In this block, the program checks if any `0` is present in the `fiware_status` list. This is important because `1` was added to the list when a port was not in the `fiware_ports` list and was open. Therefore, if the list doesn't contain any `0`, it suggests that all relevant ports for "Fiware" are open and active.

- **If "Fiware" is detected**:
	- A line is printed for visual separation.
	- An alert message is displayed.
	- If the `save_in_file` option is active, the "Fiware" detection is also recorded in the `fingerprint_report.txt` file.

- **If "Fiware" is not detected**:
	- A line is printed for visual separation.
	- A failure message is displayed.
	- The information is also written to the `fingerprint_report.txt` file, regardless of the `save_in_file` option.

The last `line()` command prints a divider line to make the output more readable.

## phpMyAdmin Scan

```python
nm.scan(host_address, phpmyadmin_range, arguments=argument)
time.sleep(3)
for host in nm.all_hosts():
    if nm[host].state() == "down":
        print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
        line()
    else:
        for proto in nm[host].all_protocols():
            print(f'Protocol : {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                if save_in_file:
                    with open('fingerprint_report.txt', 'a') as report:
                        report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
                state = nm[host][proto][port]['state']
                service_name = nm[host][proto][port]['name']
                print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
                          Colors.GREEN + f'State : {state}\t\t' + 
                          Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
                if not port in phpmyadmin_ports and state == "open":
                    phpmyadmin_status.append(1)
                else:
                    phpmyadmin_status.append(0)
        if not 0 in phpmyadmin_status:
            line()
            print("[!] " + Colors.WARNING + '"PhpMyAdmin" Can be on server' + Colors.ENDC)
            if save_in_file:
                with open('fingerprint_report.txt', 'a') as report:
                    report.write("========================================================================\n")
                    report.write('[!] "PhpMyAdmin" Can be on server\n')
                    report.write("========================================================================\n")
        else:
            line()
            print("[!] " + Colors.FAIL + '"PhpMyAdmin" Undetected' + Colors.ENDC)
            with open('fingerprint_report.txt', 'a') as report:
                report.write("========================================================================\n")
                report.write('[!] "PhpMyAdmin" Undetected\n')
                report.write("========================================================================\n")
line()
```

### Explanation:

This code block performs a scan to detect the presence of phpMyAdmin on specific hosts. Here are the details:

- `nm.scan(host_address, phpmyadmin_range, arguments=argument)`: This line initiates a scan using the `nm` object (an instance of the `nmap.PortScanner()` class) to look for phpMyAdmin in the `phpmyadmin_range` address range with the `argument` arguments.
- `time.sleep(3)`: Waits for 3 seconds before proceeding to the next part of the code.
- `for host in nm.all_hosts():`: A loop iterates through all the hosts found in the scan.
- The host's state is checked. If it's "down," an error message is displayed. Otherwise, it proceeds to analyze the protocols and ports.
- `for proto in nm[host].all_protocols():`: Iterates through the available protocols on the host.
- For each protocol, the list of ports `lport` is iterated, and information is collected. If `save_in_file` is active, the information is recorded in a 'fingerprint_report.txt' file.
- The `state` and `service_name` variables are set based on the collected information.
- Port information, state, and service name are printed, with highlighted colors for better readability.
- It's checked whether the port is not in the phpMyAdmin ports list (`phpmyadmin_ports`) and whether the port's state is "open." If both conditions are true, a value "1" is added to the `phpmyadmin_status` list, indicating that phpMyAdmin might be present.
- Otherwise, a value "0" is added to the `phpmyadmin_status` list.
- After analyzing all ports, it's checked whether the `phpmyadmin_status` list does not contain the value "0." If so, a message is displayed indicating that phpMyAdmin might be present.
- Otherwise, a message is displayed indicating that phpMyAdmin was not detected.
- The code block is concluded with the `line()` function for visual separation of the results.


## Header and Greeting

```python
nm = nmap.PortScanner()

print(Colors.HEADER + "  ____                      __  __         _          _              ____               " + Colors.ENDC)
print(Colors.HEADER + " / ___|   ___  __ _  _ __  |  \/  |  __ _ | |_  _ __ (_)__  __      |  _ \  _ __  ___   " + Colors.ENDC)
print(Colors.HEADER + " \___ \  / __|/ _` || '_ \ | |\/| | / _` || __|| '__|| |\ \/ /_____ | |_) || '__|/ _ \  " + Colors.ENDC)
print(Colors.HEADER + "  ___) || (__| (_| || | | || |  | || (_| || |_ | |   | | >  <|_____||  __/ | |  | (_) | " + Colors.ENDC)
print(Colors.HEADER + " |____/  \___|\__,_||_| |_||_|  |_| \__,_| \__||_|   |_|/_/\_\      |_|    |_|   \___/  \n" + Colors.ENDC)
print(Colors.FAIL + "                                                      ScanMatrix-Pro v3.0 - by Renan D. " + Colors.ENDC)
```

### Explanation:

This code block defines the program header and displays a greeting to the user.

1. `nm = nmap.PortScanner()`: Creates an instance of the `nmap.PortScanner()` class that will be used to perform scans.
2. `print()` is used to display the header and greeting. Formatting with `Colors.HEADER`, `Colors.ENDC`, and `Colors.FAIL` is used to style the text.
3. The header is displayed with stylized text that forms a program logo or title, along with the version (v3.0) and the author (Renan D.).

## Scan Type Selection Loop

```python
while True:
    try:
        type_scan = int(input(Colors.BLUE + "Select a option:" + Colors.ENDC + "\n[1] TCP SYN scan\n[2] TCP connect scan\n[3] UDP scan\n[4] Aggressive scan\n[5] Custom scan\n[6] Fingerprint Analysis\n[7] Exit\n: "))
        line()
        # TCP SYN scan
        if type_scan == 1:
            try:
                nmap_scan('-sS', 'TCP SYN scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # TCP connect scan
        elif type_scan == 2:
            try:
                nmap_scan('-sT', 'TCP connect scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # UDP scan
        elif type_scan == 3:
            try:
                nmap_scan('-sU', 'UDP scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Aggressive scan
        elif type_scan == 4:
            try:
                nmap_scan('-A', 'Aggressive scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Custom Scan
        elif type_scan == 5:
            try:
                custom_arguments = input(Colors.BLUE + "Provide a valid Arguments | Example: --open -sS" + Colors.ENDC + "\n: ")
                print(Colors.WARNING + f"Arguments: {custom_arguments}" + Colors.ENDC)
                line()
                nmap_scan(custom_arguments, 'Custom Scan')
            except:
                print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
        # Fingerprint Detect
        elif type_scan == 6:
            fingerprint_scan("")
        # Exit
        elif type_scan == 7:
            print(Colors.HEADER + 'Until later :D')
            exit()
        # Error
        else:
            print(Colors.FAIL + "Non-existent option | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
            line()
    except ValueError:
        line()
        print(Colors.FAIL + "Value error | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
        line()
```

### Explanation:

This code block implements a loop that allows the user to select the type of scan to be executed. Here's the detailed explanation:

- A `while True:` loop is used to keep the program running until the user decides to exit.
- The user is prompted to select an option using `input()`. The input is converted to an integer using `int()`.
- After the selection, a blank line is printed to visually separate the outputs.
- The `if` structure checks which option was chosen and executes the corresponding code block:
   - If `type_scan` is equal to 1, a TCP SYN scan is initiated using `nmap_scan('-sS', 'TCP SYN scan')`.
   - If `type_scan` is equal to 2, a TCP connect scan is initiated using `nmap_scan('-sT', 'TCP connect scan')`.
   - If `type_scan` is equal to 3, a UDP scan is initiated using `nmap_scan('-sU', 'UDP scan')`.
   - If `type_scan` is equal to 4, an aggressive scan is initiated using `nmap_scan('-A', 'Aggressive scan')`.
   - If `type_scan` is equal to 5, the user can provide custom arguments for the scan. The arguments are collected using `input()`. The provided arguments are printed, and then the `nmap_scan()` function is called with the custom arguments.
   - If `type_scan` is equal to 6, fingerprint detection is performed using `fingerprint_scan("")`.
   - If `type_scan` is equal to 7, the message "Until later :D" is printed, and the program is terminated using `exit()`.
   - If `type_scan` doesn't match any option, an error message is displayed.
- If a `ValueError` occurs (invalid input), an error message is displayed.

# Contributors

<a href="https://github.com/Aykie"> Júlia Barboza Brunelli</a>, <a href="https://github.com/NCalegariS"> Nicholas Calegari</a> e <a href="https://github.com/WHrez1ns"> Renan Dias</a>
<br>
**RM: 98558, 93912 e 99258.**
