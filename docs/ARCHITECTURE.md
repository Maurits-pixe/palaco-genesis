# PALACO-CITADEL — Architectuur

## Status en grenzen

De bestaande PALACO Genesis Rust-workspace blijft intact in `crates/` en
`runtime/`. Daarnaast staan vijf uitvoerbare lokale alpha-projecten in `apps/`
en `services/`. De services hebben aparte opslag en aparte operatorcredentials.
Dit is geen productie-uitrol of gedistribueerd autorisatiesysteem.

| Onderdeel | Locatie | Verantwoordelijkheid |
| --- | --- | --- |
| NEO | `apps/neo-launcher/` | Vue-launcher en module-identiteitscontrole |
| AETHER UI | `apps/aether-frontend/` | Crypto-interface in Vue |
| BASTION UI | `apps/bastion-frontend/` | Vue-commandointerface |
| AETHER | `services/aether-engine/` | Uitvoerbare Rust-cryptoservice |
| BASTION | `services/bastion-core/` | Node.js/Socket.io en D-013-mutaties |

## Technologiekeuzes

Rust biedt memory safety en voorspelbare prestaties voor de cryptografische
service. AETHER gebruikt `ring` voor AES-256-GCM en `rusqlite` voor
transactionele opslag. Per record wordt een willekeurige nonce gebruikt en de
record-ID is authenticated associated data. De database bewaart ciphertext en
nonce; de 256-bit sleutel komt uit `AETHER_KEY_HEX`, niet uit de database.
Memory safety vervangt geen sleutelbeheer, unieke nonces,
authenticatie of toegangscontrole; SQLite versleutelt niet automatisch de data.

Node.js biedt een breed webecosysteem en past bij eventgedreven samenwerking
via Socket.io. BASTION gebruikt Node's ingebouwde SQLite-API voor een
commandologboek en eenmalige tickets. Een commando is data, nooit een
OS-/shellopdracht. Vue verzorgt de gebruikersinterfaces, niet de
autorisatiebeslissingen. Alle beveiligingsbeslissingen blijven server-side.

## Moduleverificatie door NEO

NEO controleert `/.well-known/palaco-app.json` via vaste Vite-proxyroutes
`/verify/aether` en `/verify/bastion`. De proxydoelen zijn uitsluitend de twee
lokale API's. Het manifest bevat `id` (`aether` of `bastion`), `name` en
`protocol` (`palaco-app/v1`). Verwachte identiteit/protocol en de twee UI-origins
staan in de launcherconfiguratie; een manifest kan geen nieuwe launch-URL
introduceren. De lanceerlink blijft uitgeschakeld tot de controle slaagt.
Fouten, redirects, timeouts en verkeerde manifestwaarden leiden tot weigering.
Een nieuwe controle schakelt eerdere goedkeuring uit.

HTTP is uitsluitend voor expliciete loopback-ontwikkeling toegestaan;
andere origins vereisen HTTPS. Dit is geen dynamische URL-proxy of modulemarkt.

Een publiek JSON-manifest bewijst op zichzelf geen authenticiteit of
code-integriteit. Ondertekende manifests en distributievertrouwen zijn niet
geïmplementeerd. CORS is geen autorisatie.
Een succesvolle launchercontrole geeft nooit toestemming voor backendmutaties.

## Mutatiepad

De BASTION UI vraagt een actie aan; BASTION controleert identiteit, scope,
ticketgeldigheid en replaystatus binnen dezelfde transactionele grens als de
mutatie. Pas na een succesvolle commit volgt een Socket.io-bevestiging.
Zie [D-013](D-013-PROTOCOL.md) voor het tijdscontract.

De bestaande ERA-specificaties onder `specs/ERA/` blijven afzonderlijke
contracten: een D-013-tijdscheck vervangt geen atomair geordende
commit-/revocatiebeslissing.

## API-contracten

Iedere service biedt `GET /health` en `GET /.well-known/palaco-app.json`
zonder credentials. AETHER vereist `AETHER_TOKEN` via Bearer-authenticatie;
BASTION gebruikt het afzonderlijke `BASTION_TOKEN`. Tokens bestaan uit
32–4096 afdrukbare ASCII-tekens zonder whitespace.

| AETHER-verzoek | JSON | Resultaat |
| --- | --- | --- |
| `POST /v1/records` | `plaintext` (maximaal 16 KiB UTF-8) | `201`, `id` |
| `GET /v1/records/{id}` | Geen body | `id`, ontsleutelde `plaintext` |

AETHER begrenst HTTP-bodies op 64 KiB. De sleutel is exact 64 hexadecimale
tekens (32 bytes). Sleutelverlies maakt bestaande records onleesbaar;
deze alpha biedt geen recovery of rotatiemigratie.

Zie [D-013](D-013-PROTOCOL.md#lokale-api) voor de BASTION-routes.
Commandotekst is maximaal 1024 tekens; JSON-bodies maximaal 8 KiB.
Socket.io gebruikt `auth.token` bij het verbinden en publiceert
`command:committed` met het vastgelegde commandorecord. Een gemist event is
geen bewijs van een mislukte commit: lees het logboek opnieuw. Er is geen
gegarandeerde duurzame eventlevering.

## Lokale orchestration

`scripts/start-all.sh` start `cargo run` voor AETHER en `npm run dev` voor
BASTION en de drie frontends. AETHER heeft een eigen Cargo-workspace en
lockbestand; bestaande crates worden niet verplaatst. Rootworkspace-tests
controleren AETHER dus niet automatisch. CI heeft aparte modulejobs.

| Module | UI | API |
| --- | --- | --- |
| NEO | `127.0.0.1:5173` | Vaste verificatieproxies |
| AETHER | `127.0.0.1:5174` | `127.0.0.1:8787` |
| BASTION | `127.0.0.1:5175` | `127.0.0.1:8788` |

De API's publiceren alleen health en manifest zonder authenticatie.
Datatoegang vereist het betreffende Bearer-token uit de serveromgeving.
Socket.io vereist hetzelfde BASTION-token bij de handshake. Tokens worden
handmatig in de UI ingevoerd en uitsluitend in componentgeheugen gehouden.
Vite proxyt naar de vaste loopback-API's en is geen productieserver.

De standaarddatabases staan in de servicemappen; `AETHER_DB` en `BASTION_DB`
kunnen een ander pad kiezen. Tokens en AETHER-sleutel worden niet automatisch
gegenereerd of opgeslagen door het startscript; ontbrekende configuratie wordt
geweigerd. De umask van het script beperkt lokale bestandsrechten.
Publiceer deze alpha niet via tunnels: TLS, gebruikersrollen, rate limiting,
sleutelrotatie, operationele backups en deploymenthardening vereisen extra werk.
