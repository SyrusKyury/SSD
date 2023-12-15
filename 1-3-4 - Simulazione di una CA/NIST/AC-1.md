# Documento di Controllo AC-1 (Policy and Procedures) del NIST per l'Applicazione REST API con Certificati PKCS#10

## Controllo AC-1: Controllo di Accesso - Policy and Procedures

### Introduzione:

Il presente documento stabilisce le politiche e le procedure di controllo di accesso (AC-1) in conformità con le linee guida del National Institute of Standards and Technology (NIST) per l'applicazione REST API specificata. La CA in questione gestisce tre rotte (/get_certificate, /download_certificate, /sign), di cui due sono pubbliche e una è accessibile solo dai Trusted Clients. I Trusted Clients sono autorizzati a inviare richieste di certificato verificate in formato PKCS#10, che saranno successivamente firmate dal server.

---

## 1. Definizioni:

- **REST API:** Un'interfaccia di programmazione delle applicazioni basata su architettura REST per consentire la comunicazione tra client e server tramite richieste e risposte HTTPS.

- **PKCS#10:** Uno standard del Public Key Cryptography Standards che definisce il formato delle richieste di certificato.

- **Trusted Clients:** Entità autorizzate a interagire con la rotta /sign dell'API e inviare richieste di certificato verificate.

---

## 2. Politiche di Accesso:

### a. Rotte Pubbliche:

- Le rotte pubbliche (/get_certificate, /download_certificate) sono accessibili a tutti gli utenti senza autenticazione.
- Le richieste su queste rotte sono soggette a controlli di sicurezza, inclusi limiti di frequenza e verifica del formato.

### b. Rotta Riservata (Solo per Trusted Clients):

- L'accesso alla rotta /sign è limitato ai Trusted Clients.
- L'autenticazione dei Trusted Clients avviene attraverso un meccanismo di scambio di token sicuro.
- Le richieste devono essere in formato PKCS#10.

---

## 3. Procedure di Accesso:

### a. Rotte Pubbliche:

- Gli utenti possono accedere liberamente alle rotte pubbliche.
- Le richieste sono sottoposte a controlli di sicurezza per prevenire attacchi comuni, inclusi injection.

### b. Rotta Riservata (Solo per Trusted Clients):

- I Trusted Clients devono autenticarsi utilizzando token di accesso.
- Le richieste devono contenere un certificato PKCS#10 valido e verificato.
- La CA verifica l'autenticità e la validità delle richieste e risponde di conseguenza.
- Le comunicazioni tra i Trusted Clients e la CA sono crittografate per garantire la confidenzialità delle informazioni (HTTPS).

---

## 4. Gestione dei Certificati:

### a. Firma dei Certificati:

- La CA firma digitalmente i certificati PKCS#10 inviati dai Trusted Clients solo se la richiesta è valida e conforme alle politiche definite.
- I certificati firmati sono rilasciati in una directory pubblicamente accessibile e sono soggetti a periodi di validità appropriati.

### b. Revoca dei Certificati:

- Il server deve implementare un meccanismo per revocare i certificati in caso di compromissione o revoca autorizzativa.

---

## Conclusione:

Il presente documento stabilisce le politiche e le procedure di controllo di accesso (AC-1) per l'applicazione REST API, garantendo un adeguato livello di sicurezza e autenticazione. L'implementazione di queste misure contribuirà a proteggere l'integrità e la riservatezza delle informazioni scambiate tra i clienti e il server. Le revisioni periodiche e la gestione adeguata dei certificati sono essenziali per mantenere un ambiente sicuro e conforme agli standard di sicurezza.
