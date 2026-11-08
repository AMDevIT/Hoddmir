# Riverifica delle funzionalità di Hoddmir

Riverifica completata sul checkout con HEAD 57bc0cb. Esaminati i percorsi di lettura, scrittura, riapertura, verifica e riscrittura. Effettuata una prova isolata di FileStream con PowerShell.

- **Append su file.** ReadAtAsync sposta il cursore dello stream condiviso. AppendAsync scrive dal cursore mentre PutAsync e DeleteAsync indicizzano usando la lunghezza del file. La prova isolata ha letto DATA da DATAINDEX, lasciando il cursore a 4 con lunghezza 9. La scrittura di NEW ha prodotto DATANEWEX, sempre di lunghezza 9.
- **Nonce dell'indice.** PersistIndexAsync usa sempre lo stesso IndexToken. Il nonce del prefisso combina quattro byte dello store e otto del token. Gli snapshot riusano quindi il nonce sotto la stessa chiave anche nella stessa sessione.
- **Nonce dei payload.** Il primo Put usa 1 per il dato e 2 per l'indice. La ricostruzione calcola il massimo sui soli record dati con token riconosciuto, quindi il Put dopo la riapertura usa ancora 2. CompactAsync riparte da 1 con la stessa chiave e lo stesso prefisso. RotateDekAsync genera una nuova chiave e un nuovo prefisso.
- **Persistenza separata.** Record e indice vengono scritti e sottoposti a flush separatamente. Un token assente dagli snapshot leggibili rende il record invisibile alla riapertura. Una cancellazione interrotta prima dello snapshot può lasciare attiva la versione precedente.
- **Verifica dell'indice.** VerifyAsync autentica il prefisso e controlla la lunghezza, ma salta l'autenticazione del payload dell'indice. Corrompere soltanto il tag del payload dell'unico snapshot può lasciare IsHealthy a true e l'indice vuoto alla riapertura.
- **Riscritture e provider.** CompactAsync e RotateDekAsync saltano i record attivi illeggibili. Lo store rifiuta il nome AES-GCM (BouncyCastle) con NotSupportedException.
- **Documentazione e test.** Il README descrive un nonce del prefisso diverso da quello implementato. Le chiavi sono cifrate sia nei record dati sia negli snapshot. Il test di unicità usa numeri sintetici. CorruptedDataRecordTag modifica il prefisso del record. I test di integrazione dello store usano il backend in memoria.

La prova isolata conferma il comportamento del cursore. Gli altri esiti derivano dal tracciamento dei sorgenti. Restore, build e MSTest non eseguiti. Prossimo passo consigliato. Aggiungere prove di integrazione sul backend file e sui nonce osservati dal provider AEAD, quindi correggere append e gestione dei nonce.
