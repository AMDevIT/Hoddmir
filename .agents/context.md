
## Analisi delle funzionalità di Hoddmir

- Obiettivo e stato. Ricognizione e analisi statica completate.
- Decisione. Confrontati i sorgenti e i casi di test con README e changelog.
- File interessati. Consultati Core, Bouncy Castle, MSTest e app console. Aggiunta la [nota di analisi](analisi-funzionalita.md).
- Controlli. Lettura del codice e del test di unicità. Restore, build e test esclusi dal perimetro concordato.
- Questioni aperte. Riproduzione dinamica dei difetti di append e riuso dei nonce, da affrontare prima di validare la persistenza su file.

## Riverifica delle funzionalità di Hoddmir

- Obiettivo e stato. Riverifica completata. Confermati i rilievi su append, nonce, indice e provider Bouncy Castle.
- Decisione. Distinte la prova isolata di FileStream e le conferme ottenute per tracciamento del codice.
- File interessati. Aggiunta la [nota di riverifica](riverifica-funzionalita.md) e aggiornato questo contesto. Consultati store, backend file, provider Bouncy Castle, test e README.
- Controlli. La prova FileStream ha scritto alla posizione 4 con lunghezza 9. Verificati i percorsi dei nonce e della ricostruzione dell'indice. Restore, build e MSTest non eseguiti.
- Questioni aperte. Prove di integrazione e correzioni. Il prossimo passo è aggiungere regressioni che osservino i nonce effettivi e la sequenza lettura-scrittura sul backend su file.

## Correzioni della persistenza nel formato 0x01

- Obiettivo e stato. Implementati i fix concordati su append, nonce e ricostruzione dell'indice.
- Decisioni. Append con offset effettivo, chiave HKDF per record e indice in memoria ricostruito dal log. Recupero della coda incompleta con compattazione. Nessun percorso legacy.
- File interessati. Core Storage e provider, README e test MSTest. Dettagli nella [nota delle correzioni](fix-persistenza-formato-01.md).
- Controlli. Analisi sintattica Roslyn C# 13 e git diff --check superati. Restore, build e MSTest esclusi su richiesta dell'utente.
- Questioni aperte. Convalida a runtime su .NET 9 e .NET 10 quando autorizzata, con particolare attenzione al backend su file.
