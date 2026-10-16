# PALACO-CITADEL — Architectuur

## Status en grenzen

De bestaande PALACO Genesis Rust-workspace blijft intact in `crates/` en
`runtime/`. NEO, AETHER en BASTION zijn geplande applicatieassemblages; hun
launchmappen bevatten nog geen implementaties. Dit document beschrijft het
doelontwerp, niet een reeds uitgerold systeem.

| Onderdeel | Locatie | Verantwoordelijkheid |
| --- | --- | --- |
| NEO | `apps/neo-launcher/` | Vue-launcher en module-identiteitscontrole |
| AETHER UI | `apps/aether-frontend/` | Crypto-interface in Vue of React |
| BASTION UI | `apps/bastion-frontend/` | Vue-commandointerface |
| AETHER | `services/aether-engine/` | Uitvoerbare Rust-cryptoservice |
| BASTION | `services/bastion-core/` | Node.js/Socket.io en D-013-mutaties |

## Technologiekeuzes

Rust biedt memory safety en voorspelbare prestaties voor de cryptografische
service. Het ontwerp voorziet `ring` voor AES-256-GCM en `rusqlite` voor
transactionele opslag. Memory safety vervangt geen sleutelbeheer, unieke nonces,
authenticatie of toegangscontrole; SQLite versleutelt niet automatisch de data.

Node.js biedt een breed webecosysteem en past bij eventgedreven samenwerking
via Socket.io. Vue/React verzorgen de gebruikersinterfaces, niet de
autorisatiebeslissingen. Alle beveiligingsbeslissingen blijven server-side.

## Moduleverificatie door NEO

NEO moet alleen expliciet toegestane HTTPS-origins benaderen en daar
`/.well-known/palaco-app.json` ophalen. Het toekomstige manifestcontract moet
een verwachte module-identiteit, protocolversie en toegestane endpoints
definiëren. Ontbrekende, ongeldige of niet-passende manifests leiden tot weigering;
redirects naar niet-vertrouwde origins mogen de controle niet omzeilen.

Een publiek JSON-manifest bewijst op zichzelf geen authenticiteit of
code-integriteit. De trustconfiguratie, HTTPS en eventuele ondertekende manifests
vereisen een afzonderlijk uitgewerkt vertrouwensmodel. CORS is geen autorisatie.
Een succesvolle launchercontrole geeft nooit toestemming voor backendmutaties.

## Mutatiepad

De BASTION UI vraagt een actie aan; BASTION controleert identiteit, scope,
ticketgeldigheid en replaystatus binnen dezelfde transactionele grens als de
mutatie. Pas na een succesvolle commit volgt een Socket.io-bevestiging.
Zie [D-013](D-013-PROTOCOL.md) voor het tijdscontract.

De bestaande ERA-specificaties onder `specs/ERA/` blijven afzonderlijke
contracten: een D-013-tijdscheck vervangt geen atomair geordende
commit-/revocatiebeslissing.

## Lokale orchestration

`scripts/start-all.sh` verwacht een uitvoerbaar Cargo-project voor AETHER en
`npm run dev` voor BASTION en alle drie de frontends. Een zelfstandig
Cargo-project onder `services/` moet zijn workspacekeuze expliciet maken:
lidmaatschap van de rootworkspace of een eigen workspace. Bestaande crates
worden niet verplaatst.

Poorten en API-origins horen in de toekomstige applicatieconfiguratie; bind
ontwikkelservers standaard aan loopback. Ngrok-tunnels zijn optioneel, worden
niet automatisch gestart en vereisen expliciete trustconfiguratie.
