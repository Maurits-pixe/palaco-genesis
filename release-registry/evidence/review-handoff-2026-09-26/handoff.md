# PALACO / ERA — onafhankelijke reviewoverdracht

Status: REVIEW BASELINE FROZEN / HANDOFF PREPARED / REVIEWER UNASSIGNED / REVIEW NOT STARTED / NOT MERGED / NOT ACTIVATED.

## Artifact en checksum

Dit document wordt als `handoff.md` gepubliceerd naast `SHA256SUMS`. Dat bestand bevat de SHA-256 van de volledige UTF-8-bytes van dit document, zonder BOM en met LF-regeleinden. De checksum staat afzonderlijk om een zelfverwijzende hash te vermijden. Controleer beide bestanden via dezelfde vaste publicatiecommit. De checksum bewijst byte-integriteit, geen auteursidentiteit of goedkeuring.

## Bevroren reviewbaseline

Genesis bewijscommit: `5c3b261b4aad3fee2f17181ffc47ddff839f9d7e`.

[Bewijsdossier](https://github.com/Maurits-pixe/palaco-genesis/blob/5c3b261b4aad3fee2f17181ffc47ddff839f9d7e/release-registry/evidence/reproducibility-2026-09-26/README.md).

Publieke broncommit: `183ddd9e69e9adbfda17ea1d853f37a4e82a5f91` in Maurits-pixe/PALACO.

[Publieke testbestanden](https://github.com/Maurits-pixe/PALACO/tree/183ddd9e69e9adbfda17ea1d853f37a4e82a5f91/release-registry).

De baseline is een vaste commitverwijzing. Dit document creëert geen ondertekende tag, GitHub-branchbeveiliging of repositorybrede schrijflock. Eventuele correcties krijgen nieuwe commits en vereisen een expliciete nieuwe reviewbaseline. Gebruik geen bewegende branch als bewijsverwijzing.

## Opdracht aan de reviewer

1. Verkrijg toegang tot het dossier en controleer de exacte commitverwijzingen. Gebruik uitsluitend het dossier en de aangewezen openbare bronbestanden voor reproductie; leg ontbrekende toegang of instructies als bevinding vast.
2. Controleer de bronchecksums tegen reproduction.json. Houd rekening met omzetting van regeleinden tijdens checkout.
3. Voer de 39 testmethoden uit met Python 3.12 volgens het dossier. Bewaar volledige uitvoer, exitcode, UTC-uitvoertijd, Python-, SQLite- en besturingssysteemversie.
4. Controleer de verdeling 4 positief / 28 negatief / 7 gemengd op methodeniveau. Beoordeel of de assertions de claims daadwerkelijk ondersteunen; groen testresultaat alleen is onvoldoende.
5. Controleer met name concurrency, replay/idempotency, intrekking, heropenen van opslag en conflicterende tijd. Maak onderscheid tussen testdekking en ontbrekende crash-, stroomuitval-, netwerk- en productie-integratietests.
6. Beoordeel de scheiding tussen temporeel bewijs, autorisatie en uitvoering, plus de OPEN punten in het threat model. Registreer bevindingen met ernst, bronlocatie, reproductiestappen en afsluitcriterium.
7. Lever een afzonderlijk reviewresultaat op met revieweridentiteit, onafhankelijkheidsverklaring, exacte scope en broncommits, toolchain, testuitvoerchecksums, bevindingen en oordeel. Leg expliciet vast wat niet is beoordeeld.

## Ondertekening en acceptatie

### Onafhankelijkheidscriteria

- De reviewer heeft de te beoordelen implementatie en bijbehorende tests niet geschreven of mede-ontworpen en beoordeelt geen eigen werk.
- De reviewer voert de reproductie zelf uit in een eigen, schone omgeving, zonder toegang tot de werkmap van de implementator. Hulp, afwijkingen en gebruikte bronnen worden vastgelegd.
- De reviewer verklaart relevante organisatorische, financiële en persoonlijke belangen en eerdere betrokkenheid. De aanwijzende bevoegde actor beoordeelt en registreert deze verklaring vóór aanvang; onafhankelijkheid wordt niet afgeleid uit een GitHub-account of AI-uitvoer.
- De reviewer beschikt over aantoonbare deskundigheid voor de afgesproken scope. Ontbrekende expertise of toegang wordt als beperking of INCOMPLETE geregistreerd.
- Een herhaling door dezelfde implementerende assistent is geen onafhankelijke review. Aanwijzing, reviewoordeel en releasebevoegdheid zijn afzonderlijke registraties.

### Reproductieomgeving en commando's

Referentieomgeving: CPython 3.12.14, Windows 11 build 26200, AMD64, SQLite 3.53.1. Alleen Python-standaardbibliotheek; geen pip-pakketten nodig. CI gebruikte Ubuntu en Python 3.12. De reviewer legt zijn werkelijke versies vast; verschillen mogen niet stilzwijgend worden gelijkgesteld.

Voer dit uit in een nieuwe werkmap met Git en Python 3.12 beschikbaar:

```sh
git -c core.autocrlf=false clone https://github.com/Maurits-pixe/PALACO.git palaco-review
cd palaco-review
git -c core.autocrlf=false checkout --detach 183ddd9e69e9adbfda17ea1d853f37a4e82a5f91
git rev-parse HEAD
python -c "import sys,platform,sqlite3; print(sys.version); print(platform.platform()); print(sqlite3.sqlite_version)"
python -m unittest discover -s release-registry -p 'test_*.py' -v
```

Bewaar stdout, stderr en exitcode. Verwacht 39 geslaagde testmethoden. Controleer alle negen bronchecksums tegen `reproduction.json` in het vastgepinde bewijsdossier. Een succesvolle uitvoering zonder checksumcontrole sluit de reproductie niet af.

Controle van het gedownloade overdrachtsdocument, vanuit de map met `handoff.md` en `SHA256SUMS`:

```sh
python -c "from pathlib import Path; import hashlib; actual=hashlib.sha256(Path('handoff.md').read_bytes()).hexdigest(); expected=Path('SHA256SUMS').read_text().split()[0]; print(actual); assert actual==expected, 'Checksum mismatch'"
```

### Toegestane reviewuitkomsten

| Uitkomst | Betekenis |
|---|---|
| PASS | Alle afgesproken reviewcriteria binnen de vermelde scope zijn onderzocht en voldaan, met reproduceerbaar bewijs en zonder open bevindingen binnen die scope. Geen automatische merge of activering. |
| PASS WITH LIMITATIONS | Het onderzochte deel voldoet, maar benoemde beperkingen blijven bestaan. Verplichte mergevoorwaarden blijven geblokkeerd zolang zij niet zijn afgedekt. |
| FAIL | Minimaal één onderzocht criterium faalt; bevindingen en herstelcriteria zijn vastgelegd. |
| INCOMPLETE | De review kan niet worden afgerond door ontbrekende toegang, bewijs, expertise, omgeving of andere noodzakelijke input. Ontbrekend bewijs wordt geen PASS. |

Het uiteindelijke resultaat bevat verplicht: volledige revieweridentiteit en verifieerbare identifier; onafhankelijkheidsverklaring; UTC-datum van uitvoering en ondertekening; baseline-SHA en publieke bron-SHA; checksum van deze overdracht; exacte scope en uitsluitingen; omgeving, commando's en exitcodes; hashes van uitvoer en bewijsbestanden; bevindingen; één van de vier uitkomsten; algoritme, sleutel-ID, openbare sleutel, identiteit-sleutelbinding en verifieerbare handtekening over het afzonderlijke resultaat. Ontbrekende ondertekening wordt expliciet UNSIGNED en geldt niet als geaccepteerde ondertekende review.

Reviewer: nog niet aangewezen. Publieke sleutel en identiteit-sleutelbinding: nog niet geverifieerd. Dit document is geen reviewresultaat en bevat geen handtekening.

Het daadwerkelijke reviewresultaat moet als afzonderlijk artefact worden ondertekend. Bewaar de exacte ondertekende bytes, handtekening, algoritme, sleutel-ID, openbare sleutel en controleerbare identiteit-sleutelbinding. Leg de gebruikte ondertekeningsmethode vooraf vast; een gebruikersnaam, checksum of ingevuld handtekeningveld vervangt geen verificatie. Deel geen privésleutels in het dossier.

De reviewer legt een reviewoordeel vast, geen impliciete releasebevoegdheid. Onafhankelijke review, sleutelbinding, threat-modelsluiting en mergebesluit zijn afzonderlijke stappen. Bij onopgeloste bevindingen blijft de poort gesloten. Een later mergebesluit vereist controle van de exacte dan voorgestelde head en de toepasselijke CI- en authorityvoorwaarden.

## Huidige grenzen

CONCEPT IMPLEMENTED / SCOPED TESTING PASS / CI GREEN op de vastgelegde bewijscommit / NOT MERGED / NOT ACTIVATED.

De visuele laag blijft bevroren. EVA-LA-001 blijft DRAFT. Er is geen reviewer benaderd, geen review ondertekend, geen sleutel aangewezen, geen threat-modelpunt gesloten en geen merge of deployment uitgevoerd door deze overdracht.
