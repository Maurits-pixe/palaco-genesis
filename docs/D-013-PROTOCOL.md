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
| `GET /v1/tickets/{id}` | Lees ticketstatus en eventueel het reeds gecommitte record |
| `DELETE /v1/tickets/{id}` | Trek een ticket in |

De BASTION-interface gebruikt deze DELETE-route via **Ticket intrekken**.
Alleen een antwoord met status 200 en `revoked: true` bevestigt de intrekking.
Een netwerkfout bewijst niet dat het ticket is ingetrokken of nog actief is:
de interface blokkeert lokaal verder gebruik en bewaart het ID voor een
handmatige nieuwe intrekpoging. De server blijft beslissend. Intrekking
verwijdert geen eerder gecommit commandorecord en vervangt geen rollback.

### Statuscontrole na een onzekere uitkomst

De statusroute vereist dezelfde Bearer-authenticatie en controleert de
server-side identiteit/scope van het ticket. Onbekende of niet-passende tickets
geven 404; een onbetrouwbare klok of onbeschikbare opslag geeft 503, geen
optimistische status. De controle leest tijd en opslag binnen de bestaande
geserialiseerde transactie en bewaart de tijdgrens. Ze schrijft geen commando
en zendt geen succes-event uit.

Het antwoord bevat `id`, `command`, `not_before`, `expires_at`, `checked_at`,
`status`, `revoked` en `record`. Alle tijdstippen zijn gehele epochmilliseconden.
De status wordt in deze volgorde bepaald:

1. `committed`: het ticket is verbruikt; `record` bevat `id`, `command` en
   `committed_at`. Een latere intrekking verandert het historische resultaat
   niet; `revoked` kan dan ook `true` zijn.
2. `revoked`: ingetrokken zonder commit; `record` is `null`.
3. `expired`: `checked_at >= expires_at`; `record` is `null`.
4. `pending`: `checked_at < not_before`; `record` is `null`.
5. `active`: binnen het halfopen tijdvenster; `record` is `null`.

Een verbruikt ticket zonder bijbehorend commandorecord wordt niet als succes
gepresenteerd. Het gecommitte record wordt rechtstreeks via het ticket gezocht,
niet alleen in de laatste 100 logboekregels. Deze controle werkt dus ook na
een serviceherstart zolang dezelfde database en operatorconfiguratie behouden
blijven.

De UI bewaart het laatst ingezonden ID uitsluitend in geheugen en biedt een
handmatige ID-opvraag. Ze valideert het antwoord voordat het wordt getoond.
Een historisch gecommit record verschijnt in het statusresultaat, niet als
nieuwe logboekregel; recente regels worden door opvragen niet verdrongen.
Alleen een terminale status (`committed`, `revoked`, `expired`) van hetzelfde
ticket kan een onzekere lokale intrekking afsluiten. `active`, `pending`,
404 en netwerkfouten geven geen nieuwe toestemming. Er volgt nooit een
automatische commit of retry.

Een ticket krijgt een willekeurige ID en een servervenster van maximaal
60 seconden. Tickets bevatten geen door de client te wijzigen gezagsclaims.
`BEGIN IMMEDIATE` verkrijgt de SQLite-schrijfgrens voordat de tijd opnieuw
wordt gelezen; controle, verbruik, commandorecord en auditrecord horen bij
dezelfde transactie. Replay of hergebruik produceert geen tweede record.
Een Socket.io-event `command:committed` volgt uitsluitend na commit.

Een schrijftransactie bewaart daarnaast de laatst geaccepteerde servertijd.
De bedrijfswijzigingen staan binnen een savepoint, zodat weigering of rollback
de geldige tijdwaarneming niet wist. Ook na een herstart wordt een teruglopende
klok geweigerd. Mislukt het duurzaam opslaan van deze tijdgrens, dan worden
verdere mutaties geblokkeerd en meldt `/health` onbeschikbaarheid. Herstel
opslag en controleer de klok voordat je de service opnieuw start.

Dit logboek voert **nooit** commando's als proces of shellopdracht uit.
De lokale klok blijft een operationele aanname; kloksynchronisatie en
onzekerheidsbewijs voor echte gedistribueerde uitvoering zijn niet geleverd.
