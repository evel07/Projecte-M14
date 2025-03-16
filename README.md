# Projecte-M14
# Index
- Preparació
  - [Anàlisi de riscos](#anàlisi-de-riscos)
- Fase de reconeixement
  - [Consulta API Shodan amb Python](#eina-api-de-shodan)
  - [The Harvester Python](#the-harvester)
  - [Més OSINT](#més-osint----infoga)

- Auditoria de serveis
  - [Escaneig](#escanneig)
  - [SSH](#ssh-audit)
  - [Enumeració](#enumeració)
- Funcionalitats afegides
  - [Bot Telegram amb Python](#bot-de-telegram)
  - [Crear un contenidor Docker](#contenidor-docker)

# Preparació
## Anàlisi de Riscos
En aquest apartat realitzem un anàlisi dels següents elements: actius, amenaces, delimitació, probabilitat, impacte i risc. Això ens ajudarà a saber els objectius i les prioritats de la nostra auditoria, per a cada empresa.

### Document d'Anàlisi de Riscos

Aquest document definirà els registres, prioritats i classificacions de les iniciatives:

- Identificador: identifica cada cas.
- Títol: acció.
- Cost: el cost a assumir per l’empresa (Baix, Mitjà, Alt).
- Prioritat: necessitat de realitzar la tasca (Baix, Mitjà, Alt).

[Enllaç al document d'anàlisi de riscos](https://docs.google.com/spreadsheets/d/1dkS1hjHjmgNUccRZiNJE737dglgypASPBg6EmL8X3DU/edit?usp=sharing)

# Aplicaió
La nostra aplicació funciona amb un client interactiu des d’una interfície gràfica, on es mostra un primer menú amb les tres part del projecte i dintre de cada una les diferents eines que podem executar:
![foto](/captures/foto1.png)
![foto](/captures/foto2.png)
![foto](/captures/foto3.png)
![foto](/captures/foto4.png)

# Fase de Reconeixement
## Shodan
El primer que hem de fer es impiortar l'eina de shodan. 

![foto](captures/import_shodan.png)

L'script te una funció principal on importem la nostra api de shodan que la hem obtingut una vegada ens hem registrat a la web.
![foto](captures/api.png)
![foto](captures/codi_api.png)

#### Funció per a Shodan
El que fem amb aquesta funció es busca informació d'una adreça IP utilitzant l'API de Shodan, mostra els resultats en un widget de text i gestiona possibles errors que puguin produir-se durant la crida a l'API.
![foto](captures/codi_shodan.png)

### Comprovació de funcionalitat de Shodan
![foto](captures/shodan.png)


## The Harvester
#### Codi
![foto](captures/codi_theHarvester.png)

### Comprovació de funcionalitat de TheHarvester
![foto](captures/theHarvester_terminal.png)
![foto](captures/theHarvester_codi.png)


## OSINT
Per a l'aparta de OSINT natros hem utilitzat les eines de WHOIS, DNS i NSLOOKUP

#### Codi per a WHOIS
Busquem la informació WHOIS d'un domini específic utilitzant el comandament whois, mostrem els resultats en un widget de text i gestionem possibles errors que puguin produir-se durant l'execució del comandament.
![foto](captures/codi_whois.png)

#### Codi per a DNS
Busquem la informació DNS d'un domini específic utilitzant el comandament dig, mostrem els resultats en un widget de text i gestiona possibles error.
![foto](captures/codi_dns.png)

#### Codi per a NSLOOKUP
Busquem la informació dels serveis de noms (NS) d'un domini específic utilitzant el comandament nslookup, mostrem els resultats en un widget de text i gestiona possibles error.
![foto](captures/codi_nslookup.png)


### Comprovació de funcionalitat de OSINT
![foto](captures/osint.png)

#### WHOIS
![foto](captures/whois.png)

#### DNS
![foto](captures/dns.png)

#### NSLOOKUP
![foto](captures/nslookup.png)



# Auditoria de Serveis
## Escaneig
### Comprovació de funcionalitat d'escaieng


## SSH Audit
El primer que fem es accedir a l'enllaç de GitHub que hi ha al moodle i descarregem el zip d'SSH Audit
![foto](captures/ssh-audit.png)

Una vegda descarregat i descomprimit mourem el fitxer ssh-audit.py a la carpeta de on tenim el codi del projecte.
![foto](captures/ssh1.png) 
