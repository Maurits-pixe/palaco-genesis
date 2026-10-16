# D-013 — Server-side tijdsgebonden mutaties

**Status: contract met lokale alpha-referentie in `services/bastion-core/`.**
Deze implementatie is een commandologboek met één gedeelde operatoridentiteit,
geen algemeen autorisatie-, shell- of gedistribueerd uitvoeringsplatform.

## Contract

> D-013 vereist dat een mutatie alleen wordt toegepast als de server-side tijd
> binnen het geldigheidsvenster van het toestemmingsticket valt bij de
> definitieve servercontrole, atomair gekoppeld aan de mutatie.

Een ticket moet ten minste een geverifieerde uitgever, subject, toegestane
actie/resource, unieke identificatie en geldigheidsvenster bevatten.
Een client mag deze gegevens niet zelf tot gezag verheffen.
Het venster is halfopen: `not_before <= server_now < expires_at`.
Op de exacte vervaltijd wordt de actie dus geweigerd.

## Transactionele uitvoering

1. Authenticeer de aanvrager en verifieer de authenticiteit van het ticket.
2. Open de database-transactie en verkrijg de benodigde locks of equivalente
   serialisatie vóór de definitieve controle.
3. Controleer subject, scope, revocatie en replaystatus tegen gezaghebbende
   servergegevens. Lees de vertrouwde servertijd opnieuw na eventuele wachttijd.
4. Weiger bij ongeldigheid of onbetrouwbare tijd. Een clienttijdstip of het
   moment van ontvangst is nooit voldoende bewijs van geldigheid.
5. Voer bij geldigheid de mutatie, ticketverbruik/idempotentieregistratie en het
   auditrecord atomair uit. Iedere fout veroorzaakt rollback.
6. Bevestig het resultaat pas na commit; publiceer geen succes-event vooraf.

Als toestemming gedurende het wachten op een lock verloopt, wordt niets
opgeslagen. Een netwerkretry mag dezelfde mutatie niet opnieuw uitvoeren.
Transactieretries moeten ook alle autorisatie- en tijdscontroles herhalen.

## Grenzen van de garantie

Dit contract gebruikt het definitieve servercontrolepunt als beslismoment.
Een check gevolgd door een gewone databasecommit bewijst **niet** dat de
fysieke commit vóór `expires_at` plaatsvindt. Een strengere garantie
"geen commit na verval" vereist een afzonderlijk commit-time-mechanisme en
bijbehorend bewijs. Claim die garantie niet op basis van alleen een tijdscheck.

Kloksynchronisatie, foutmarges en gedrag bij kloksprongen moeten expliciet
worden gespecificeerd; bij onzekerheid wordt geweigerd. Tijd creëert geen
autoriteit. Bestaande ERA-008/009-specificaties gebruiken voor commit- en
revocatieraces atomaire registryvolgorde, niet enkel wandkloktijd.

## Vereiste conformiteitstests

- Vóór `not_before`, exact op `not_before`, vlak vóór en exact op `expires_at`.
- Verlopen toestemming na lockwachttijd of bij een transactieretry.
- Onjuist subject/scope, vervalste of ingetrokken tickets en onbetrouwbare tijd.
- Dubbele en gelijktijdige aanvragen met hetzelfde ticket.
- Rollback bij opslagfouten, zonder gedeeltelijke mutatie of succes-event.

De servicetests controleren deze lokale grenzen en foutpaden. Ze bewijzen geen
gecertificeerde tijd of volledige ERA-conformiteit.

## Lokale API

Alle `/v1/*`-routes vereisen het server-side ingestelde `BASTION_TOKEN` als
Bearer-token. De bezitter kan tickets uitgeven én gebruiken; tickets zijn
daarom geen onafhankelijke tweede toestemming of multi-user governance.

| Verzoek | Betekenis |
| --- | --- |
| `POST /v1/tickets` met `command`, `ttl_ms` | Maak een server-side ticket voor exact deze commandotekst |
| `POST /v1/commands` met `ticket_id`, `command` | Controleer en verbruik het ticket transactioneel |
| `GET /v1/commands` | Lees maximaal de laatste 100 commandorecords |
| `DELETE /v1/tickets/{id}` | Trek een ticket in |

Een ticket krijgt een willekeurige ID en een servervenster van maximaal
60 seconden. Tickets bevatten geen door de client te wijzigen gezagsclaims.
`BEGIN IMMEDIATE` verkrijgt de SQLite-schrijfgrens voordat de tijd opnieuw
wordt gelezen; controle, verbruik, commandorecord en auditrecord horen bij
dezelfde transactie. Replay of hergebruik produceert geen tweede record.
Een Socket.io-event `command:committed` volgt uitsluitend na commit.

Dit logboek voert **nooit** commando's als proces of shellopdracht uit.
De lokale klok blijft een operationele aanname; kloksynchronisatie en
onzekerheidsbewijs voor echte gedistribueerde uitvoering zijn niet geleverd.
