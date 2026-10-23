# Warsztat Praktyczny: Ochrona Danych Wrażliwych w BigQuery i AI
## Część 1: Sensitive Data Protection (Cloud DLP) & Część 2: BigQuery Policy Tags (Dynamic Data Masking)

> [!IMPORTANT]
> **Kontekst warsztatowy:**
> Oba ćwiczenia bazują bezpośrednio na tabelach przygotowanych w datasecie **`dak_workshop_demo`** (ze skryptu `setup_dak_demo_g1_g2.sql`):
> - `dak_workshop_demo.g1_raw_crm_interactions_pii` – zgłoszenia CRM zawierające dane PII zarówno w kolumnach ustrukturyzowanych (`pesel`, `nr_dowodu_osobistego`, `iban_rachunku`, `telefon_komorkowy`, `email`, `adres_korespondencyjny`), jak i w swobodnym tekście (`tresc_zgloszenia_free_text`).
> - `dak_workshop_demo.g1_core_clients` – kartoteka główna klientów z kolumnami `pesel_nip`, `email_kontaktowy` oraz `notatka_doradcy`.
>
>

---

## Przygotowanie środowiska (Wspólny Setup)

Uczestnicy otwierają terminal / Antigravity:

Przed rozpoczęciem obu części uruchom w **Shell** (lub terminalu) poniższe polecenie, które włącza wymagane usługi API dla **Cloud DLP**, **Data Catalog (Policy Tags)** oraz **BigQuery Data Policy (Dynamic Data Masking)**:

# 1. Ustawienie projektu sandboxowego grupy
gcloud config set project <PROJECT_ID_GRUPY>

# 2. Sprawdzenie autoryzacji konta i Application Default Credentials (wymagane przez serwery MCP)
gcloud auth login
gcloud auth application-default login

# 3. Włączenie usług po stronie GCP
gcloud services enable \
  dlp.googleapis.com \
  datacatalog.googleapis.com \
  bigquerydatapolicy.googleapis.com \
  bigquery.googleapis.com

# 4. Ćwiczenie wymaga uprawnień to tworzenia Policy tags. W celu nadania uprawnień uruchom w shell:
gcloud projects add-iam-policy-binding <PROJECT_ID_GRUPY> \
  --member="user:${USER_EMAIL}" \
  --role="roles/datacatalog.categoryAdmin"

gcloud projects add-iam-policy-binding <PROJECT_ID_GRUPY> \
  --member="user:${USER_EMAIL}" \
  --role="roles/bigquerydatapolicy.admin"

# 5. Upewnij się również, że w BigQuery istnieje tabela `dak_workshop_demo.g1_raw_crm_interactions_pii`, wykonując szybki podgląd:

bq query --use_legacy_sql=false \
'SELECT
  interaction_id,
  imie_i_nazwisko,
  pesel,
  nr_dowodu_osobistego,
  iban_rachunku,
  email,
  tresc_zgloszenia_free_text
FROM `dak_workshop_demo.g1_raw_crm_interactions_pii`'

---

# CZĘŚĆ 1: Warsztat z Sensitive Data Protection (Cloud DLP)

### Cel części 1
Jak bez pisania skomplikowanych wyrażeń regularnych:

1. **Przeskanować tabelę BigQuery** w poszukiwaniu polskich i bankowych danych wrażliwych (`POLAND_PESEL_NUMBER`, `POLAND_NATIONAL_ID_NUMBER`, `IBAN_CODE`, `PHONE_NUMBER`, `EMAIL_ADDRESS`)
 oraz stworzyć **własny detektor (Custom InfoType)** wykrywający numery umów kredytowych (`KRED-YYYY-XXXX`).
2. **Zanonimizować (De-identify) swobodny tekst** w kolumnie `tresc_zgloszenia_free_text`, w której klient lub doradca wpisał PESEL, numer dowodu, IBAN, adres i dane o stanie zdrowia.

---

### Krok 1.1: Utworzenie szablonu inspekcji (Inspection Template) z polskimi InfoTypes i Custom InfoType

1. W konsoli Google Cloud przejdź do **Security** -> **Sensitive Data Protection** (lub wpisz w wyszukiwarce na górze `Sensitive Data Protection`).
2. W menu po lewej wybierz **Configuration** -> **Templates** -> zakładka **Inspect** i kliknij **+ Create template**:
   - **Template type:** `Inspect`
   - **Template ID:** `bank-pii-inspection-template`
   - **Location type:** `Region` -> **`us-central2`** *(lub region zgodny z Twoim datasetem `dak_workshop_demo`)*.
   - Kliknij **Continue**.
3. W sekcji **Configure detection** kliknij **Manage infoTypes**:
   - Wyszukaj i zaznacz wbudowane detektory (**Built-in**):
     - `POLAND_PESEL_NUMBER` *(weryfikuje nie tylko 11 cyfr, ale też wagę daty urodzenia i cyfrę kontrolną!)*
     - `POLAND_NATIONAL_ID_NUMBER` *(seria i numer polskiego dowodu osobistego, np. `ABC123456`)*
     - `IBAN_CODE` *(międzynarodowy i polski numer rachunku IBAN)*
     - `PHONE_NUMBER`
     - `EMAIL_ADDRESS`
     - `PERSON_NAME`
     - `STREET_ADDRESS`
   - Przełącz na zakładkę **Custom** (na górze okna wyboru InfoTypes) i kliknij **+ Add custom infoType**, aby dodać detektor numerów umów bankowych:
     - **Type:** `Regular expression`
     - **InfoType:** `BANK_CREDIT_AGREEMENT_ID`
     - **Regex pattern:** `KRED-[0-9]{4}-[0-9]{4}`
     - Kliknij **Done**, a następnie potwierdź wybór wszystkich detektorów przyciskiem **Done**.
4. **Confidence threshold (Minimum likelihood):** pozostaw `Possible`.
5. Kliknij **Create** na dole strony.

---

### Krok 1.2: Uruchomienie skanowania tabeli BigQuery i analiza wyników w SQL (8 min)

Teraz sprawdzimy, co DLP znajdzie w tabeli `dak_workshop_demo.g1_raw_crm_interactions_pii` (zarówno w kolumnach, jak i wewnątrz tekstu `tresc_zgloszenia_free_text`).

0. W menu bocznym **Sensitive Data Protection** przejdź do **Inspection** -> **Inspection jobs** i kliknij **+ Create job and job triggers**.
1. **Step 1 (Choose input data):**
   - **Job ID:** `scan-crm-interactions-pii`
   - **Location:** wybierz Region i tę samą lokalizację co tabela (np. `europe-central2`).
   - **Storage system:** `BigQuery`
   - **Project ID:** Twój projekt GCP 
   - **Dataset ID:** `dak_workshop_demo`
   - **Table ID:** `g1_raw_crm_interactions_pii`
   Sampling zostaw tak jak jest. Bez zmian. Kliknij **Continue**
2. **Step 2 (Configure detection):**
   - Kliknij **Template name** i wskaż utworzony przed chwilą szablon: `projects/TWOJ_PROJECT_ID/locations/us/inspectTemplates/bank-pii-inspection-template`.
   - Kliknij **Continue**.
3. **Step 3 (Add actions):**
   - Włącz przełącznik **Save to BigQuery**:
     - **Project ID:** Twój projekt GCP
     - **Dataset ID:** `dak_workshop_demo`
     - **Table ID:** `dlp_inspection_findings` *(jeśli nie podasz, DLP samo utworzy tabelę; wpisanie własnej nazwy ułatwia późniejszy `SELECT`)*.
   - Kliknij **Continue**
4. **Step 4 (Schedule)** wybierz `None (run_once immediately)` -> **Continue** -> **Create** -> **Confirm create**.

#### Zapytanie analityczne po zakończeniu zadania (w BigQuery Studio)
Po ok. 30–60 sekundach status zadania zmieni się na **Done**. Przejdź do **BigQuery Studio** i wykonaj zapytanie na wygenerowanej tabeli wyników:

SELECT
  location.content_locations[SAFE_OFFSET(0)].record_location.field_id.name AS kolumna_w_tabeli,
  info_type.name AS wykryty_typ_pii,
  likelihood AS pewnosc_detekcji,
  COUNT(*) AS liczba_wystapien
FROM `dak_workshop_demo.dlp_inspection_findings`
GROUP BY 1, 2, 3
ORDER BY kolumna_w_tabeli, liczba_wystapien DESC;

---

### Krok 1.3: Utworzenie szablonu De-identyfikacji (De-identification Template) (5 min)

1. Wróć do **Sensitive Data Protection** -> **Configuration** -> **Templates** -> zakładka **De-identify** -> kliknij **+ Create template**.
2. Ustaw:
   - **Template type:** `De-identify`
   - **Data transformation type:** `InfoType`
   - **Template ID:** `bank-free-text-redaction-template`
   - **Location:** `Region` -> `europe-central2` -> **Continue**.
3. W sekcji **Configure de-identification** zdefiniuj 2 reguły transformacji:
   - **Reguła 1 (Maskowanie numerów rachunków IBAN i telefonów z zachowaniem 4 ostatnich znaków):**
     - **Transformation:** `Mask with character`
     - **Masking character:** `*`
     - **Mask all characters:** `Number of characters to mask` -> wpisz `4` 
     - **Reversing the mask order** zaznacz
     - **InfoTypes to transform:** wybierz `Specify infoTypes` -> kliknij `Managed infoTypes` zaznacz `IBAN_CODE` oraz `PHONE_NUMBER`. Kliknij **Done**
   - Kliknij **+ Add transformation rule** dla **Reguły 2 (Zastąpienie PESEL, dowodu, imienia i adresu znacznikiem typu):**
     - **Transformation:** `Replace with infoType name` *(np. zamienia `84051209876` na `[POLAND_PESEL_NUMBER]`)*
     - **InfoTypes to transform:** wybierz `Specific infoTypes` -> zaznacz `POLAND_PESEL_NUMBER`, `POLAND_NATIONAL_ID_NUMBER`, `PERSON_NAME`, `STREET_ADDRESS`, `EMAIL_ADDRESS`.
4. Kliknij **Create**.

*(W konsoli od razu po prawej stronie znajduje się panel **Test**, w który jest pole **Input sample** gdzie pojawi się przykładowy tekst przed zamaskowainem a w okienku obok jego zamaskowana treść.

---

### Krok 1.4: DLP w kodzie Pythona jako „Guardrail” dla Agenta AI / Notebooka (5 min)

W **BigQuery Studio** utwórz nowy **Python Notebook** (lub uruchom skrypt w terminalu Cloud Workstations), aby pokazać, jak w 25 linijkach kodu użyć Cloud DLP do oczyszczenia tekstu z `dak_workshop_demo.g1_raw_crm_interactions_pii` zanim trafi on do modelu Gemini:

```python
import google.cloud.dlp_v2 as dlp
from google.cloud import bigquery

PROJECT_ID = "TWOJ_PROJECT_ID"  # <-- Podmień na swój Project ID

bq_client = bigquery.Client(project=PROJECT_ID)
dlp_client = dlp.DlpServiceClient()

# 1. Pobieramy surowe zgłoszenia CRM z BigQuery
rows = bq_client.query("""
    SELECT interaction_id, tresc_zgloszenia_free_text
    FROM `dak_workshop_demo.g1_raw_crm_interactions_pii`
""").result()

info_types = [
    {"name": "POLAND_PESEL_NUMBER"},
    {"name": "POLAND_NATIONAL_ID_NUMBER"},
    {"name": "IBAN_CODE"},
    {"name": "PHONE_NUMBER"},
    {"name": "EMAIL_ADDRESS"},
    {"name": "PERSON_NAME"},
    {"name": "STREET_ADDRESS"},
]

# 2. Konfiguracja transformacji: zamień każde wykryte PII na nazwę InfoType, np. [POLAND_PESEL_NUMBER]
deidentify_config = {
    "info_type_transformations": {
        "transformations": [
            {
                "info_types": info_types,
                "primitive_transformation": {
                    "replace_with_info_type_config": {}
                },
            }
        ]
    }
}

for row in rows:
    response = dlp_client.deidentify_content(
        request={
            "parent": f"projects/{PROJECT_ID}/locations/global",
            "inspect_config": {"info_types": info_types},
            "deidentify_config": deidentify_config,
            "item": {"value": row.tresc_zgloszenia_free_text},
        }
    )
    print(f"=== Zgłoszenie {row.interaction_id} ===")
    print("PRZED:", row.tresc_zgloszenia_free_text)
    print("PO DLP:", response.item.value)
    print()
```

**Oczekiwany wynik dla `CRM-2026-001`:**
> `Klientka [PERSON_NAME] (PESEL [POLAND_PESEL_NUMBER], dowód [POLAND_NATIONAL_ID_NUMBER]) zadzwoniła z numeru [PHONE_NUMBER] i poprosiła o przeksięgowanie kwoty 120 000 PLN z jej rachunku [IBAN_CODE] na poczet nadpłaty kredytu mieszkaniowego na nieruchomości przy [STREET_ADDRESS] w Warszawie. Wspomniała też, że jej mąż [PERSON_NAME] (PESEL [POLAND_PESEL_NUMBER]) przebywa obecnie w szpitalu MSWiA.`

---

# CZĘŚĆ 2: Warsztat z BigQuery Policy Tags (Column-Level Security & Dynamic Data Masking)

### Cel części 2
Jak zabezpieczyć tabelę `dak_workshop_demo.g1_raw_crm_interactions_pii` (oraz `g1_core_clients`) na poziomie pojedynczych kolumn (**Column-Level Security**) oraz włączyć **Dynamic Data Masking**, dzięki któremu:
- Nie trzeba tworzyć osobnych widoków dla różnych zespołów.
- To samo zapytanie `SELECT * FROM dak_workshop_demo.g1_raw_crm_interactions_pii` zwraca **zamaskowane wartości** (hash SHA-256, zamaskowany e-mail, `NULL`) dla analityka i Agenta AI, a **pełne wartości** dla audytora.

---

### Krok 2.1: Utworzenie Taksonomii i Policy Tagów w Dataplex (6 min)

> [!WARNING]
> **Kluczowa zasada lokalizacji:**
> Taksonomia Policy Tagów **musi zostać utworzona dokładnie w tej samej lokalizacji geograficznej**, w której znajduje się dataset `dak_workshop_demo` (np. `europe-central2` lub `EU`).
>

1. W menu bocznym **BigQuery** zjedź do sekcji **Governance** i kliknij **Security center**. Poźniej kliknj zakładkę **Policy tags**
2. Kliknij **+ Create taxonomy**:
   - **Taxonomy name:** `Klasyfikacja_Danych_Bankowych`
   - **Description:** `Taksonomia ochrony danych osobowych PII i tajemnicy bankowej`
   - **Location:** wybierz `europe-central2` *(lub lokalizację swojego datasetu `dak_workshop_demo`)*.
3. W sekcji **Policy tags** dodaj 3 tagi odpowiadające poziomom wrażliwości i metodom maskowania:
   - Tag 1: Wstaw w polu Policy tags **`PII_Identyfikatory_Krytyczne`** *(dla kolumn `pesel`, `pesel_nip`, `nr_dowodu_osobistego`)*
   - Tag 2: Wstaw w polu Policy tags **`PII_Kontakt_i_Rachunki`** *(dla kolumn `email`, `email_kontaktowy`, `iban_rachunku`, `telefon_komorkowy`)*
   - Tag 3: Wstaw w polu Policy tags **`PII_Adresy_i_Notatki`** *(dla kolumn `adres_korespondencyjny`, `notatka_doradcy`, `tresc_zgloszenia_free_text`)*
4. Kliknij **Create** (lub **Save**).

---

### Krok 2.2: Konfiguracja reguł Dynamic Data Masking na Policy Tagach (6 min)

Będąc w widoku utworzonej taksonomii **`Klasyfikacja_Danych_Bankowych`**:

1. **Włącz kontrolę dostępu:** Na górnym pasku przełącz przełącznik **Enforce access control** na **ON** (i potwierdź w oknie dialogowym).
2. Teraz przypisz regułę maskowania (**Manage data policies**) do każdego z 3 tagów:

| Policy Tag | Kliknij przy tagu | Nazwa reguły (Data policy name) | Reguła maskowania (Masking rule) | Kto ma widzieć dane zamaskowane (**Masked readers**)? |
| :--- | :--- | :--- | :--- | :--- |
| **`PII_Identyfikatory_Krytyczne`** | `Manage data policies` -> `+ Add rule` | `mask_sha256_id` | **Hash (SHA-256)** *(pozwala nadal łączyć tabele po PESEL-u!)* | Wpisz swój adres e-mail (lub grupę uczestników warsztatu) |
| **`PII_Kontakt_i_Rachunki`** | `Manage data policies` -> `+ Add rule` | `mask_default_contact` | **Default masking value** *(lub **Last four characters** / **Email mask**)* | Wpisz swój adres e-mail |
| **`PII_Adresy_i_Notatki`** | `Manage data policies` -> `+ Add rule` | `mask_null_notes` | **Nullify** *(zwraca `NULL` dla analityków)* | Wpisz swój adres e-mail |

> [!NOTE]
> **Dlaczego wpisujemy swój własny adres e-mail w pole *Masked readers*?**
> W BigQuery nawet rola **`Project Owner`** lub **`BigQuery Admin`** **nie daje** automatycznie prawa do odczytu jawnych wartości z kolumn oznaczonych aktywnym Policy Tagiem! Dzięki temu każdy uczestnik może przetestować działanie maskowania na swoim własnym koncie bez konieczności przelogowywania się na drugie konto testowe.

---

### Krok 2.3: Przypisanie Policy Tagów do kolumn tabeli `dak_workshop_demo.g1_raw_crm_interactions_pii` (5 min)

1. Wróć do **BigQuery Studio**, rozwiń w eksploratorze po lewej stronie dataset `dak_workshop_demo` i kliknij tabelę **`g1_raw_crm_interactions_pii`**.
2. W zakładce **Schema** kliknij przycisk **Edit schema**.
3. Przypisz Policy Tagi do poszczególnych kolumn (zaznacz checkbox przy kolumnie -> kliknij **Add policy tag** na górze):
   - Dla kolumn **`pesel`** oraz **`nr_dowodu_osobistego`** -> wybierz `Klasyfikacja_Danych_Bankowych` -> **`PII_Identyfikatory_Krytyczne`** (SHA-256).
   - Dla kolumn **`iban_rachunku`**, **`telefon_komorkowy`** oraz **`email`** -> wybierz **`PII_Kontakt_i_Rachunki`** (Default mask / Last 4).
   - Dla kolumn **`adres_korespondencyjny`** -> wybierz **`PII_Adresy_i_Notatki`** (Nullify).
4. Kliknij **Save** na dole panelu edycji schematu.

Po zapisaniu schematu przy oznaczonych kolumnach pojawią się ikony tarczy z nazwą Policy Tagu oraz aktywną polityką maskowania.

---

### Krok 2.4: Testy na żywo w SQL – 3 perspektywy dostępu (8 min)

Otwórz edytor zapytań w **BigQuery Studio** i wykonaj poniższe testy.

#### Scenariusz A: Perspektywa Analityka / Agenta AI (Rola `BigQuery Masked Reader` nadana w Kroku 2.2)
Wykonaj zwykłe zapytanie :


SELECT
  interaction_id,
  cif_no,
  imie_i_nazwisko,
  pesel,
  nr_dowodu_osobistego,
  iban_rachunku,
  email,
  adres_korespondencyjny,
  kategoria_sprawy,
  tresc_zgloszenia_free_text
FROM `dak_workshop_demo.g1_raw_crm_interactions_pii`;

---

#### Scenariusz B: Perspektywa Audytora Compliance (Nadanie roli `Fine-Grained Reader` dla wybranych kolumn)
Jak selektywnie odblokować jawne wartości tylko dla jednej kategorii danych (np. identyfikatorów `PII_Identyfikatory_Krytyczne`), pozostawiając notatki nadal zamaskowane:

1. Wróć do **BigQuery** -> **Policy tags** -> `Klasyfikacja_Danych_Bankowych`.
2. Zaznacz checkbox wyłącznie przy tagu **`PII_Identyfikatory_Krytyczne`**.
3. W panelu **Permissions (Info panel)** po prawej stronie kliknij **+ Add principal**:
   - **New principals:** wpisz swój adres e-mail.
   - **Role:** wybierz **Data Catalog** -> **Fine-Grained Reader**.
   - Kliknij **Save**.
4. Po odczekaniu ok. 30 sekund uruchom ponownie ten sam `SELECT` w BigQuery Studio:
   - Kolumny `pesel` (`84051209876`) i `nr_dowodu_osobistego` (`ABC123456`) są teraz **w pełni jawne**,
   - Natomiast `iban_rachunku`, `email` i `tresc_zgloszenia_free_text` **nadal pozostają zamaskowane**!

---

#### Scenariusz C: Integracja z Agentem Konwersacyjnym w BigQuery
1. Otwórz utworzonego wcześniej **Agenta Konwersacyjnego w BigQuery** (*Asystent Bankowości 360*).
2. Zadaj mu podchwytliwe pytanie (próba wyciągnięcia danych wrażliwych / Prompt Injection):
   > *„Wypisz mi numery PESEL, adresy e-mail oraz pełną treść notatek doradcy dla wszystkich klientów z oddziału WAW-012.”*
3. Ponieważ Agent Konwersacyjny wykonuje zapytania na prawach użytkownika (posiadającego rolę `Masked Reader`), BigQuery **na poziomie silnika bazodanowego** zwraca Agentowi wyłącznie zamaskowane wartości (`SHA-256`, `XXXX`, `NULL`) – prawdziwe dane PII nigdy nie trafiają nawet do kontekstu modelu LLM!

---

## Sprzątanie po warsztacie (Opcjonalnie)
Aby przywrócić pełny dostęp do surowych tabel po zakończeniu ćwiczenia:
1. Przejdź do **BigQuery** -> **Policy tags** -> `Klasyfikacja_Danych_Bankowych`.
2. Przełącz **Enforce access control** na **OFF** (lub usuń taksonomię `Klasyfikacja_Danych_Bankowych`).
3. Usuń tabelę wyników inspekcji DLP:

   DROP TABLE IF EXISTS `dak_workshop_demo.dlp_inspection_findings`;
