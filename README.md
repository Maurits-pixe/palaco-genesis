# 🏛️ PALACO-CITADEL

**Een ecosysteem voor cryptografie en commandovoering, gebouwd op PALACO Genesis.**

Deze monorepo bevat de bestaande Rust-workspace van PALACO Genesis en een
**lokale alpha** van NEO, AETHER en BASTION met drie Vue-interfaces.
De services draaien uitsluitend op loopback en gebruiken expliciet ingestelde
credentials. Dit is geen productieplatform, gecertificeerd klokmechanisme of
volledig multi-user autorisatiesysteem.

## 🏗️ Architectuur

- **👁️ NEO:** Vue-launcher die modulemanifests controleert via
  `/.well-known/palaco-app.json`, servicebeschikbaarheid via `/health` controleert
  en alleen vooraf geconfigureerde UI-links opent.
  Dit bewijst geen cryptografische code-integriteit.
- **🔐 AETHER:** Rust-service met `ring` voor AES-256-GCM en `rusqlite`
  voor versleutelde records; een Vue-interface kan records opslaan en ophalen.
- **🛡️ BASTION:** Node.js/Socket.io-commandologboek met SQLite,
  server-side toestemmingstickets en transactionele tijdscontroles.
  Commando's zijn uitsluitend tekstrecords: er wordt **geen shellcode uitgevoerd**.

Zie [architectuur](docs/ARCHITECTURE.md),
[D-013](docs/D-013-PROTOCOL.md) en de bestaande
[repository-bootstraproadmap](docs/pri-045-github-repository-bootstrap.md).

## 🚀 Quick Start

### Bestaande Rust-workspace

Installeer Rust via rustup; `rust-toolchain.toml` bepaalt de toolchain.

```bash
git clone https://github.com/Maurits-pixe/palaco-genesis.git
cd palaco-genesis
cargo build --workspace
cargo test --workspace
```

### Lokale NEO / AETHER / BASTION

Vereisten: Rust stable via rustup, Node.js **22.13+** (ondersteunde LTS),
npm en Bash **4.3+**. Node's ingebouwde SQLite-API kan een experimental warning
geven. Installeer de Node-dependencies vanuit de repositoryroot:

```bash
for project in services/bastion-core apps/neo-launcher apps/aether-frontend apps/bastion-frontend; do
  npm ci --prefix "$project"
done
```

Stel voor lokaal testen afzonderlijke willekeurige tokens en een encryptiesleutel
in. Tokens moeten 32–4096 afdrukbare ASCII-tekens zonder spaties bevatten.
Onderstaand voorbeeld genereert waarden in je shell, niet in Git:

```bash
export AETHER_TOKEN="$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")"
export BASTION_TOKEN="$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")"
export AETHER_KEY_HEX="$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")"
./scripts/start-all.sh
```

**Bewaar `AETHER_KEY_HEX` veilig buiten Git voor hergebruik**: bestaande records
kunnen na een herstart alleen met dezelfde sleutel worden ontsleuteld.
Genereer niet telkens een nieuwe sleutel voor een bestaande database.
De `.env.example`-bestanden beschrijven de serviceconfiguratie, maar worden
niet automatisch geladen. Exporteer de waarden in de shell die de services start.

| Onderdeel | Lokaal adres |
| --- | --- |
| NEO | http://127.0.0.1:5173 |
| AETHER UI / API | http://127.0.0.1:5174 / http://127.0.0.1:8787 |
| BASTION UI / API | http://127.0.0.1:5175 / http://127.0.0.1:8788 |

Open NEO en controleer de twee modules voordat je hun interfaces opent.
Met **Controleer alle modules** start je beide controles tegelijk; de
afzonderlijke controleknoppen blijven beschikbaar. Een fout bij één module
blokkeert de geslaagde controle van de andere niet. Tijdens een lopende
controle is de gezamenlijke knop uitgeschakeld om dubbele verzoeken te
voorkomen. Het overzicht telt alleen modules met een momenteel bruikbare
startlink; verlopen controles tellen niet mee. NEO controleert niet
automatisch opnieuw en opent geen interfaces zonder jouw klik.
Met **Wis controles** verwijder je alle lokale controleresultaten en
startgoedkeuringen, ook tijdens een lopende controle. Lopende verzoeken
worden lokaal geannuleerd; vertraagde antwoorden activeren geen links
opnieuw. Je kunt daarna direct een nieuwe controle starten.
Wissen stopt geen services, sluit geen reeds geopende tabbladen en trekt
geen server-side tickets of toestemming in.
Bij `pagehide` wist NEO dezelfde controles, ook wanneer de browser de pagina
in de terug-/vooruitcache bewaart. Na terugnavigeren controleer je de modules
handmatig opnieuw; oude antwoorden herstellen geen startlinks. Alleen van
tabblad wisselen wist niets. Browsers leveren `pagehide` niet gegarandeerd,
bijvoorbeeld bij een procescrash; de bestaande geldigheidscontrole blijft
onafhankelijk daarvan gelden.
NEO activeert een link alleen na een passend manifest én een gezond
`/health`-antwoord van dezelfde geconfigureerde backend. Bij onbeschikbaarheid,
een ongeldig antwoord of een timeout blijft de link uitgeschakeld. De controle
is maximaal 60 seconden bruikbaar en is een momentopname, geen doorlopende
bewaking of garantie dat de frontend bereikbaar is. Een nieuwe controle
vervangt de vorige goedkeuring; NEO vraagt hiervoor geen servicetokens.
Voer het bijbehorende servicetoken in de betreffende UI in; de UI bewaart het
niet in browseropslag. AETHER versleutelt een tekstrecord en levert een ID
waarmee je het kunt teruglezen. Het laatst **bevestigd opgeslagen** record-ID
blijft apart zichtbaar wanneer je een ander ID invoert. Met **Lees laatst
opgeslagen record** lees je dat bevestigde record handmatig terug, zonder
opnieuw iets op te slaan. Dit is geen volledige historie: na een onzekere
opslag blijft eventueel het vorige bevestigde ID staan. Een ontbrekend
serverantwoord kan hiermee niet worden gereconstrueerd.
Het bewaarde ID staat alleen in sessiegeheugen en verdwijnt bij
tokenwijziging, sessiewissen of herladen.
Bij gelezen inhoud staat het ID uit het ontvangen record. Voer je een ander
record-ID in, dan verdwijnen de vorige gelezen inhoud en leesmelding en wordt
een eventueel lopend leesverzoek lokaal geannuleerd. Alleen omringende spaties
wijzigen telt niet als een ander ID. Er wordt niets automatisch opgehaald of
uit de database verwijderd; token, invoertekst en laatst bevestigd opgeslagen
ID blijven behouden.
Met **Wis gelezen inhoud** verwijder je alleen het leesresultaat en de
bijbehorende melding; token, record-ID's en nog niet opgeslagen invoertekst
blijven behouden. Een lopend leesverzoek wordt lokaal geannuleerd en zijn
vertraagde antwoord wordt genegeerd. Tijdens opslaan is deze knop
uitgeschakeld. Om de inhoud opnieuw te zien moet je het record weer ophalen.
Dit verwijdert geen serverrecords en garandeert geen veilige overschrijving
van browsergeheugen.
Met **Wis sessie en tekst** kun je ook tijdens
een lopend AETHER-verzoek direct token, tekst en resultaten uit de interface
wissen. Vertraagde antwoorden uit die sessie worden niet opnieuw getoond.
Dit stopt alleen het lokale wachten: een al verstuurd opslagverzoek kan
server-side toch zijn uitgevoerd, zonder dat je het record-ID hebt ontvangen.
Wissen verwijdert geen opgeslagen records. Dien een onzekere opslag niet
automatisch opnieuw in; een nieuwe inzending kan een tweede record maken.
Wanneer de browser bij het verlaten van de AETHER-pagina `pagehide` meldt,
wordt dezelfde volledige sessiewissing uitgevoerd, ook bij opname in de
terug-/vooruitcache. Na terugnavigeren moet je het token opnieuw invoeren en
zelf een actie starten; er worden geen verzoeken automatisch herhaald.
Alleen van tabblad wisselen wist de sessie niet. Browsers melden `pagehide`
niet gegarandeerd bij bijvoorbeeld een procescrash: dit is geen garantie
op veilige geheugenwissing of server-side annulering van een opslagverzoek.
De AETHER-interface accepteert succesvolle antwoorden alleen als
`application/json` met een passend recordformaat. Het lezen stopt bij meer
dan 128 KiB antwoorddata, ook zonder betrouwbare `Content-Length`; de
uitgelezen tekst mag maximaal 16 KiB UTF-8 bevatten. De antwoordlimiet biedt
ruimte voor JSON-escaping van die tekst. De standaardtimeout van 8 seconden
geldt voor het volledige ophalen en lezen van het antwoord, niet alleen
voor het ontvangen van de headers. Een afgewezen antwoord bewijst niet dat
een opslagverzoek server-side is teruggedraaid.

BASTION geeft eerst een kortlevend ticket uit;
pas de afzonderlijke commitactie schrijft het commando in het logboek.
Bij uitgifte controleert de interface dat het ticket-ID maximaal 128
tekens bevat en de tijdstippen niet-negatieve, veilige gehele
epochmilliseconden zijn die als datum kunnen worden weergegeven.
Het geldigheidsvenster moet exact de aangevraagde duur hebben.
Afwijkende antwoorden worden niet als lokaal ticket bewaard; er volgt
geen automatische nieuwe aanvraag. Dit vervangt de server-side
geldigheidscontrole niet en veronderstelt geen gelijklopende clientklok.
Bij een commitbevestiging controleert de interface ook de exacte
commandotekst, het record-ID en de numerieke vastleggingstijd:
`not_before <= committed_at < expires_at` van het ingezonden ticket.
Een geldig antwoord mag na ticketverloop aankomen; het ontvangsttijdstip
is niet de server-side beslissingstijd. Een afwijkend antwoord betekent
geen rollback: controleer de ticketstatus en dien niet automatisch opnieuw in.
Met **Ticket intrekken** kun je het huidige ticket server-side ongeldig maken.
De interface bevestigt dit alleen na een geldig serverantwoord. Bij een
onzekere netwerkuitkomst blijft het ticket zichtbaar voor een nieuwe
intrekpoging; vastleggen en nieuwe tickets aanvragen zijn dan lokaal geblokkeerd.
Met **Controleer huidig ticket** vul je het ID van het lokaal bewaarde
ticket in en vraag je direct de status op, ook bij een onzekere intrekking
of een verlopen ticket. Dit is uitsluitend een handmatige leesactie:
een actieve of wachtende status heft de blokkering niet op en vraagt geen
nieuwe toestemming aan.
Een sessie wissen of invoer wijzigen is geen server-side intrekking.
Intrekken maakt eerder vastgelegde commando's niet ongedaan.
Gebruik **Status controleren** met het ticket-ID als een inzending geen
duidelijk antwoord gaf. De interface onthoudt het laatst ingezonden ID in het
sessiegeheugen; je kunt ook handmatig een ID invoeren.
Met **Controleer laatste inzending** vraag je direct de status van dat
bewaarde ID op, ook wanneer het lokale ticket na de inzendpoging al is
verwijderd. Deze knop dient niets opnieuw in en herstelt geen toestemming.
De knop controleert uitsluitend de laatste inzending in de huidige sessie;
oudere ID's kun je handmatig invoeren. De server rapporteert
of het ticket wacht, actief, verlopen, ingetrokken of al gecommit is en levert
bij een commit het bijbehorende record, ook buiten de laatste 100 logboekregels.
Dit historische resultaat staat apart en verdringt geen recente logboekregels.
Naast de servercontroletijd toont de uitkomst wanneer de interface het
antwoord lokaal heeft ontvangen. Dit ontvangsttijdstip hoort uitsluitend bij
de zichtbare uitkomst en verdwijnt bij wissen of een nieuwe statuscontrole,
ook als die controle mislukt. Andere acties en realtime-events vernieuwen het
niet. Bij een ongeldige lokale klokwaarde is geen ontvangsttijdstip beschikbaar.
Dit is geen server- of audittijd, garantie op actuele status of nieuwe
toestemming; vraag voor een nieuwe momentopname de status handmatig op.
Ook bij statusantwoorden moeten alle tijdstippen, inclusief de eventuele
committijd, niet-negatieve veilige gehele epochmilliseconden zijn die als
JavaScript-datum kunnen worden weergegeven. Een ongeldig antwoord wordt
afgewezen en heft geen lokale ticketblokkering op. Deze formaatcontrole
vergelijkt de servertijdstippen niet met de lokale klok.
Een statuscontrole dient nooit opnieuw een commando in. Een actieve status is
slechts een momentopname, geen nieuwe toestemming. Alleen een bevestigde
terminale status van hetzelfde ticket kan een onzekere intrekking lokaal
afsluiten. Hiervoor moeten ticket-ID, commando en beide grenzen van het
geldigheidsvenster overeenkomen met het lokaal bewaarde ticket. Een op
zichzelf geldig statusresultaat met een afwijkend venster blijft als
historische uitkomst zichtbaar, maar verwijdert het lokale ticket of de
onzekerheidsblokkering niet. Ontbrekende of ongeldige lokale venstergrenzen
geven evenmin aanleiding tot reconciliatie. Sessie wissen of herladen
verwijdert de lokaal bewaarde ID's.
Bij een statusuitkomst met hetzelfde ticket-ID maar een afwijkend commando
of geldigheidsvenster toont BASTION een waarschuwing. Deze verklaart waarom
de uitkomst het lokale ticket en een eventuele onzekerheidsblokkering niet
wijzigt; de waarschuwing voert zelf geen actie uit. Een bewuste opvraag van
een ander ticket-ID krijgt deze vergelijkingswaarschuwing niet.
Met **Wis ticketuitkomst** verwijder je alleen het lokale statusresultaat en
de bijbehorende statusmelding. Een lopend statusverzoek wordt lokaal
geannuleerd; late antwoorden wijzigen daarna geen resultaat of ticketstaat.
Token, ingevoerde en laatst ingezonden ticket-ID's, commando, tickets,
eventuele blokkering bij onzekere intrekking, logboek en realtimeverbinding
blijven behouden. Een al verwerkte statusreconciliatie wordt niet teruggedraaid.
Tijdens andere verzoeken is deze knop uitgeschakeld. Dit trekt geen ticket in,
herstelt geen toestemming en start geen nieuwe controle; vraag de status
handmatig opnieuw op om een uitkomst weer te bekijken.
Als je het ticket-ID voor een statuscontrole wijzigt, wordt de oude lokale
uitkomst met bijbehorende statusmelding gewist. Een lopende statuscontrole
voor het vorige ID wordt lokaal geannuleerd; late antwoorden wijzigen geen
ticketstaat. Er volgt geen automatische controle. Tickets, een eventuele
onzekerheidsblokkering en reeds verwerkte reconciliatie blijven ongemoeid.
Het statusresultaat toont altijd zijn eigen ontvangen ticket-ID. ID's worden
exact verwerkt: omringende spaties blijven ongeldige invoer.
**Wis sessie** blijft ook tijdens een lopend BASTION-verzoek beschikbaar:
token, commando, tickets, statusresultaten en logboek verdwijnen direct uit
de interface. De realtimeverbinding wordt verbroken en lopende HTTP-verzoeken
worden lokaal geannuleerd. Vertraagde antwoorden herstellen de gewiste
sessie niet. Dit trekt geen server-side ticket in en draait geen mutatie
terug; een al verstuurd verzoek kan alsnog worden verwerkt.
Kopieer het ticket-ID vóór het wissen als je een onzekere uitkomst later
handmatig wilt controleren. Wissen verwijdert ook de lokale blokkering
bij een onzekere intrekking, maar bewijst niet dat het ticket is ingetrokken.
Dien een onzekere inzending niet automatisch opnieuw in.
Bij `pagehide` voert BASTION dezelfde lokale sessiewissing uit, ook wanneer
de browser de pagina in de terug-/vooruitcache bewaart. Dit verbreekt realtime
en wist ook lokaal bewaarde ticket-ID's; bewaar zo nodig vooraf het ID voor
een latere handmatige statuscontrole. Terugnavigeren herstelt geen toestemming
of verbinding: voer het token opnieuw in en start acties zelf. Alleen een
ander tabblad openen wist niets. De browser garandeert `pagehide` niet bij
bijvoorbeeld een procescrash. Dit is geen veilige geheugenwissing, server-side
ticketintrekking of terugdraaiing van een al verstuurde mutatie.
De BASTION-interface kan met hetzelfde token verbinden voor realtime-events;
vernieuw het logboek na een verbindingsonderbreking.
Tijdens **Logboek vernieuwen** blijven eerder geladen records zichtbaar.
Bij een mislukte verversing toont de interface een waarschuwing dat de
zichtbare gegevens mogelijk verouderd zijn; er volgt geen automatische
herhaling. Een geslaagde verversing vervangt de oude lijst door de nieuwe
serversnapshot, aangevuld met realtime-records die tijdens die verversing
binnenkwamen. Oude records buiten die snapshot worden niet teruggezet.
Een logboekantwoord met dubbele record-ID's wordt volledig afgewezen, ook
als de dubbele records dezelfde inhoud hebben. De eerdere lijst en het
laatste geslaagde ontvangsttijdstip blijven dan staan, met de waarschuwing
voor een mislukte verversing. Dit verandert niet hoe afzonderlijke
realtime-events met een al bekend ID worden samengevoegd.
Het logboek toont ook wanneer de laatste geslaagde verversing lokaal is
ontvangen. Dat tijdstip blijft staan tijdens vernieuwen en bij een fout;
realtime-events en afzonderlijke commits werken het niet bij.
Dit is de lokale klok, geen server- of audittijd en geen garantie dat het
logboek nog actueel is.
Sessiewissen en het resetten van de realtimeverbinding blijven de lokale
logboekgegevens en dit ontvangsttijdstip wissen.
Met **Zoek in geladen logboek** filter je lokaal op commandotekst of
record-ID, zonder onderscheid tussen hoofdletters en kleine letters.
De zoektekst is letterlijk, geen reguliere expressie; spaties aan begin
en einde worden genegeerd. De teller toont zichtbare versus geladen records.
Alleen de maximaal 100 momenteel geladen records worden doorzocht, niet
de volledige database of ticket-ID's. Het filter verandert de records en
hun volgorde niet en blijft actief bij vernieuwen en realtime-updates.
Zoeken veroorzaakt geen extra API-verzoeken. De zoektekst blijft uitsluitend
in sessiegeheugen en verdwijnt bij sessiewissen, tokenwijziging of herladen.
Voor HTTP-antwoorden accepteert de BASTION-interface alleen JSON-objecten
met `application/json` en maximaal 1 MiB antwoorddata, onafhankelijk van
`Content-Length`. Dat biedt ruimte voor 100 logboekrecords met maximaal
1024 UTF-16-tekeneenheden per commando, ook met JSON-escaping.
De standaardtimeout van 8 seconden omvat zowel het ophalen als het lezen
van het antwoord. Deze HTTP-limiet geldt niet voor Socket.IO-events.
Een timeout of afgewezen antwoord draait een server-side mutatie niet
terug; controleer bij een onzekere inzending de ticketstatus en dien niet
automatisch opnieuw in.

Het startscript controleert manifests, Node-versie, credentials en geïnstalleerde
Node-dependencies vóór het starten en gebruikt restrictieve bestandsrechten.
De eerste AETHER-start compileert de service. Bij stoppen van een proces worden
de andere procesgroepen ook beëindigd. Ctrl+C stopt de lokale stack.

Je kunt elk project ook afzonderlijk starten met `npm run dev` in zijn map,
of `cargo run --locked` in `services/aether-engine/`. Gebruik bij los starten
een restrictieve umask, bijvoorbeeld `umask 077`. De API's hebben publieke
`/health`- en manifestendpoints; `/v1/*` vereist Bearer-authenticatie.

De Vite-proxies verbinden de interfaces met vaste lokale backendadressen.
Wijzigingen aan poorten vereisen ook aanpassingen aan die proxies en NEO's
trustconfiguratie. **Publiceer deze ontwikkelservers niet via Ngrok of een
publieke host**: TLS-terminatie, deploymenthardening en multi-user
identiteit/rollen vallen buiten deze alpha.
Commit nooit tokens, privésleutels, lokale databases of `.env`-bestanden.

## 📂 Structuur

```text
apps/
  neo-launcher/       # Vue-launcher en manifestcontrole
  aether-frontend/    # Vue crypto-UI
  bastion-frontend/   # Vue commandologboek
services/
  aether-engine/     # Zelfstandig Cargo-project met eigen lockbestand
  bastion-core/      # Node.js/Socket.io met ingebouwde SQLite
scripts/start-all.sh
docs/ARCHITECTURE.md
docs/D-013-PROTOCOL.md
crates/              # Bestaande Rust-workspacecrates
runtime/             # Bestaande palaco-kernel
specs/               # Canonieke PALACO-specificaties
```

De bestaande `engine/`, `database/`, `verification/`, apps en servicegrenzen
blijven behouden. Zie ook de
[bestaande workspace-indeling](docs/reference/repository-structure.md).

## Layering order

The workspace is organized from foundational crates to execution-facing crates, with the runtime kernel and RIO core layered above the shared constitutional and runtime contracts:

1. `palaco-foundation`
2. `palaco-constitution`
3. `palaco-types`
4. `palaco-errors`
5. `palaco-events`
6. `palaco-evidence`
7. `palaco-oracle`
8. `palaco-trias`
9. `palaco-knowledge`
10. `palaco-citadel`
11. `palaco-runtime`
12. `palaco-audit`
13. `palaco-observatory`
14. `palaco-rio-core`
15. `palaco-kernel`

## Canonical assembly

- `/specs` holds canonical specifications for ENGINE COMPLEET, RIO, MEMORY, IDENTITY, PROVENANCE, AUTHORITY, TRIAS, and PVB-011.
- `/engine`, `/services`, `/apps`, `/database`, and `/verification` reserve the repository assembly that will consume the Rust constitutional core over time.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

De rootworkspace omvat niet de zelfstandige AETHER-service. Valideer deze en
de vier Node-projecten afzonderlijk:

```bash
cargo fmt --manifest-path services/aether-engine/Cargo.toml --all -- --check
cargo clippy --manifest-path services/aether-engine/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path services/aether-engine/Cargo.toml --locked
cargo build --manifest-path services/aether-engine/Cargo.toml --locked
for project in services/bastion-core apps/neo-launcher apps/aether-frontend apps/bastion-frontend; do
  npm test --prefix "$project"
  npm run build --prefix "$project" --if-present
done
```

De BASTION-servicetests controleren ook de frontend-APIhelpers tegen een
echte tijdelijke lokale HTTP-service: tickets aanvragen, vastleggen,
intrekken, status opvragen en het logboek lezen. Ze testen ook een verloren
commitantwoord zonder herinzending en een volledig logboek van 100 maximaal
gevulde records. Hiervoor zijn alleen de dependencies van `bastion-core`
nodig; de frontend-APIhelpers gebruiken geen Vue. Dit zijn geen browser-
of Vite-proxytests en geen bewijs van productiegeschiktheid.

De bestaande PALACO CI-workflow controleert ook deze service en Node-projecten.

### Werken in Visual Studio Code

Open de **rootmap** van je lokale clone via **File → Open Folder** (of `code .`
vanuit die map). Installeer Rust met rustup en zorg dat `cargo` in je PATH staat;
de bestaande `rust-toolchain.toml` selecteert stable, rustfmt en Clippy.
Herstart VS Code na het installeren van de toolchain indien nodig.

De workspace beveelt **rust-analyzer**, **Vue (Official)** en **GitHub Pull Requests** aan via
Extensions → `@recommended`. Installatie vereist je eigen bevestiging.
Rust-bestanden gebruiken rust-analyzer voor opmaak bij opslaan en Clippy voor
editorcontroles. Gegenereerde mappen worden uitgesloten van zoeken en watching.

Gebruik **Terminal → Run Task**:

| Taak | Doel |
| --- | --- |
| `PALACO: build` | Workspace bouwen met het lockbestand; standaard buildtaak |
| `PALACO: format check` | Opmaak controleren zonder bestanden te wijzigen |
| `PALACO: clippy` | Alle targets linten; warnings zijn fouten |
| `PALACO: test` | Workspace-tests; standaard testtaak |
| `PALACO: validate` | Format, Clippy, tests en build achtereenvolgens uitvoeren |
| `PALACO: install Node dependencies` | Expliciet `npm ci` uitvoeren in de vier Node-projecten |
| `AETHER: validate` | De zelfstandige Rust-service formatteringscontrole, Clippy, tests en build laten doorlopen |
| `NEO: validate` | Launcher-tests en productiebuild |
| `AETHER UI: validate` | Crypto-interface-tests en productiebuild |
| `BASTION UI: validate` | Commando-interface-tests en productiebuild |
| `BASTION: validate` | Node-commandoservicetests |
| `PALACO: validate full stack` | Rootworkspace en vervolgens alle vijf modules sequentieel controleren |

De taken werken vanuit de geopende rootmap op Windows, macOS en Linux en
vereisen geen Bash. Ze worden niet automatisch bij het openen uitgevoerd.
Vertrouw de workspace alleen nadat je de repository hebt gecontroleerd.
De bestaande standaard build-/testtaken en `PALACO: validate` blijven gericht
op de Rust-domeinworkspace; ze controleren de zelfstandige AETHER-service niet.
Kies voor de hele applicatiestack expliciet `PALACO: validate full stack`.

Voer na een verse clone eerst `PALACO: install Node dependencies` uit.
Deze taak gebruikt de vier bestaande lockbestanden en kan aanwezige
`node_modules` vervangen; inspecteer ook de dependencies en installatiescripts
voordat je installeert. De validatietaken installeren niets automatisch en
starten geen servers. Bij een mislukte stap stopt de sequentiële keten.
Voor ieder Node-project bestaan ook afzonderlijke `install`- en `test`-taken;
de drie UI-projecten hebben een `build`-taak. AETHER heeft afzonderlijke
`format check`, `clippy`, `test` en `build`-taken. npm-processen gebruiken op
Windows expliciet `npm.cmd`; Cargo en Node.js moeten in je PATH staan.
Een geslaagde validatie is geen live integratie- of browsertest.

Start de modules in een terminal volgens de instructies hierboven;
het gezamenlijke startscript vereist Bash (op Windows bijvoorbeeld via WSL).

Voor GitHub-review of optioneel GitHub Copilot meld je jezelf in VS Code aan
met een GitHub-account met de benodigde toegang. Een Microsoft-aanmelding voor
Settings Sync koppelt deze cloudsessie niet aan je editor. Deze configuratie
meldt niemand aan en bevat geen accounts, tokens of lokale absolute paden.

Bijdragen: houd wijzigingen gericht, voeg tests toe voor gewijzigd gedrag en
voer bovenstaande controles uit voordat je een pull request indient.
Bewaar gedeelde Rust-domeinlogica in `crates/`; plaats applicatieassemblage in
`apps/` en `services/`.

### Bijdragen en review

1. Bespreek grotere wijzigingen eerst in een issue. Gebruik de bug- en
   featureformulieren; meld beveiligingsproblemen niet publiek.
2. Werk op een eigen branch of fork. Houd wijzigingen en bijbehorende tests
   bij elkaar en wijzig geen ongerelateerde onderdelen.
3. Voer de validatie hierboven uit. Gebruik daarnaast
   `cargo build --workspace --locked` voor een build met de vastgelegde dependencies.
4. Controleer je diff op secrets, persoonsgegevens en gegenereerde bestanden.
   `.gitignore` verwijdert geen eerder getrackte bestanden of Git-geschiedenis.
5. Beschrijf in je pull request wat verandert, welke controles zijn uitgevoerd
   en welke beperkingen blijven bestaan. Een maintainer beoordeelt de wijziging;
   bijdragen worden niet automatisch samengevoegd.

Houd communicatie respectvol en technisch onderbouwd. Maak duidelijk onderscheid
tussen ontwerp, referentie-implementatie en bewezen productiegedrag.

## 🔒 Veiligheid & D-013

Het [D-013-contract](docs/D-013-PROTOCOL.md) wordt in BASTION lokaal toegepast
met server-side tijdsvalidatie, eenmalige tickets en atomaire SQLite-mutaties.
Dit gebruikt de definitieve controle in de transactie als beslismoment, niet
de fysieke commit-tijd. Er is geen gecertificeerde klok of distributiegarantie.
Alle bezitters van hetzelfde servicetoken delen dezelfde bevoegdheid; geef
deze alpha geen gevoelige productiegegevens.

### Een kwetsbaarheid melden

Deze alpha biedt geen productiebeveiligingsgarantie of afgesproken responstijd.
Gebruik geen echte sleutels, financiële gegevens of andere gevoelige data in
demonstraties.

Meld mogelijke kwetsbaarheden **niet** in publieke issues of pull requests.
Gebruik op GitHub de tab **Security → Report a vulnerability** als private
vulnerability reporting is ingeschakeld. Ontbreekt die optie, vraag dan via een
issue uitsluitend om een privé-meldkanaal, zonder technische details, logs,
exploitcode of gevoelige gegevens. Wacht op dat kanaal voordat je details deelt.

Een privémelding bevat bij voorkeur de betrokken commit, impact, minimale
reproductiestappen met fictieve gegevens en een mogelijke oplossing. Bij
gelekte credentials: trek ze onmiddellijk in of roteer ze; alleen het bestand
verwijderen is niet voldoende.

## 📄 Licentie en publicatie

Zie [LICENSE](LICENSE) voor de MIT-licentie. Bestaande Rust-packagemetadata
declareert `MIT OR Apache-2.0` en is ongewijzigd.

Publicatie-instellingen worden niet door deze bestanden gewijzigd. Controleer
voor een publieke release de repositoryzichtbaarheid, licenties, secrets en
implementatiestatus. Voeg desgewenst topics `rust`, `cybersecurity`, `vue`,
`nodejs`, `encryption`, `monorepo` en `d-013` toe en pin de repository op je profiel.
Publiceer `v1.0.0 - Genesis` pas nadat de beschreven applicaties en
veiligheidsclaims aantoonbaar werken.

### Publicatiechecklist voor de maintainer

Dit is een voorbereiding, geen bewijs dat de onderstaande GitHub-instellingen
al zijn ingeschakeld.

- [ ] Controleer rechten en herkomst van alle code en documenten. Los vóór
  publicatie de licentiepresentatie op: de root bevat nu alleen de MIT-tekst,
  terwijl Rust-packages `MIT OR Apache-2.0` declareren. Bevestig met de
  rechthebbenden de bedoelde licenties en voeg zo nodig de bijbehorende teksten
  toe; verander bestaande licenties niet stilzwijgend.
- [ ] Controleer de volledige te publiceren Git-geschiedenis, branches, tags,
  artifacts en voorbeelddata op secrets, persoonsgegevens en materiaal dat
  niet openbaar mag worden. Roteer gevonden credentials vóór publicatie.
- [ ] Controleer GitHub Actions op de exacte releasecommit en voer alle
  relevante tests uit. Een lokale geslaagde build bewijst niet dat CI groen is.
- [ ] Activeer private vulnerability reporting en, waar beschikbaar,
  dependency alerts, secret scanning en push protection in de
  beveiligingsinstellingen van GitHub.
- [ ] Stel een ruleset in voor de standaardbranch: pull-requestreview,
  geslaagde vereiste statuschecks en blokkeren van force-pushes/verwijdering.
  Selecteer checknamen uit echte workflowruns; de twee Rust-workflows hebben
  verschillende validatiejobs.
- [ ] Controleer repositorynaam, beschrijving, topics en standaardbranch.
  Wijzig de zichtbaarheid alleen na expliciete goedkeuring en bovenstaande
  controles; deze wijziging maakt de repository niet openbaar.
- [ ] Kies een prereleaseversie die overeenkomt met de packagemetadata
  (momenteel `0.1.0-alpha.1`). Controleer bestaande tags en releases voordat
  een nieuwe, onveranderlijke tag op de beoordeelde commit wordt gemaakt.
- [ ] Maak eerst een conceptrelease met samenvatting, exacte commit,
  uitgevoerde controles, bekende beperkingen en upgrade-instructies.
  Markeer een alpha als **prerelease**, niet als stabiele `v1.0.0`.
- [ ] Laat een maintainer het concept beoordelen en publiceer het daarna
  handmatig. Publiceer geen binaries of packages die niet afzonderlijk
  zijn gebouwd, getest en gecontroleerd.

Een eventuele alpha-release betreft de aanwezige Rust-workspace en de lokale
NEO/AETHER/BASTION-referentie-implementaties. Er wordt geen productiegeschiktheid,
volledige ERA-conformiteit of geverifieerde code-integriteit geclaimd.
