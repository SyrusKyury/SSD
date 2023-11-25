# Secure System Design

Questo progetto è stato sviluppato come parte del corso di "Secure System Design" presso l'Università XYZ. L'obiettivo del progetto è implementare un sistema sicuro utilizzando un'architettura Docker con componenti come Nginx, Keycloak, MariaDB e FastAPI.

## Descrizione del Progetto

Il progetto consiste in un'applicazione web sicura che utilizza un'architettura container Docker per fornire un ambiente isolato e facilmente replicabile. Ecco una panoramica dei componenti principali:

- **Nginx**: Web server utilizzato per gestire le richieste HTTP e HTTPS e servire il frontend dell'applicazione.
- **Keycloak**: Sistema di gestione delle identità e degli accessi per garantire autenticazione sicura e autorizzazione.
- **MariaDB**: Database relazionale per la persistenza dei dati dell'applicazione.
- **FastAPI**: Framework web per la creazione rapida di API RESTful sicure.

## Prerequisiti

Assicurati di avere installato Docker e Docker Compose sul tuo sistema prima di eseguire l'applicazione. Puoi scaricare Docker [qui](https://www.docker.com/get-started) e Docker Compose [qui](https://docs.docker.com/compose/install/).

## Istruzioni per l'Uso

1. Clona il repository sul tuo sistema locale:

   ```bash
   git clone https://github.com/SyrusKyury/SSD.git)https://github.com/SyrusKyury/SSD.git
   cd repository

2. Avvia lo stack di container utilizzando Docker Compose:
   ```bash
   docker compose up -d

3. Accedi all'applicazione attraverso il tuo browser all'indirizzo http://localhost
   

## Configurazione

### Nginx

Il file di configurazione di Nginx si trova in `./nginx/site.conf`. Questo file controlla le impostazioni del server web Nginx, inclusi i percorsi dei file, le impostazioni SSL e altro ancora. Personalizza questo file in base alle esigenze del tuo progetto.

### Keycloak

Le informazioni di configurazione per Keycloak sono specificate nel file `./docker-compose.yml`. Puoi modificare questo file per configurare il realm, i client e altri parametri di Keycloak in base ai requisiti del tuo sistema di gestione delle identità.

### MariaDB

Le credenziali del database MariaDB e altre configurazioni sono specificate nel file `./docker-compose.yml`. Assicurati di mantenere al sicuro le credenziali del database e personalizza eventuali altre impostazioni in base alle tue esigenze.

### FastAPI

Il codice sorgente di FastAPI è situato nella directory `./fapi`. Modifica il codice sorgente di FastAPI in base alle tue esigenze di backend. Puoi aggiungere nuove route, gestire le dipendenze e personalizzare la logica dell'applicazione.

## Contributi

Siamo aperti a contributi e miglioramenti. Sentiti libero di aprire una nuova issue o inviare una pull request.

## Licenza

Questo progetto è distribuito con licenza MIT. Per ulteriori dettagli, consulta il file [LICENSE](./LICENSE).
