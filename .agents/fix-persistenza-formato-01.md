# Correzioni della persistenza nel formato 0x01

## Decisioni

- Il formato corrente resta 0x01. Il confronto di versione esistente è l'unico controllo di compatibilità.
- I backend restituiscono l'offset effettivo di append. Il backend file posiziona il cursore sotto semaforo e onora il flush su disco. Lo store serializza mutazioni e riscritture, coordinando letture e pubblicazione degli offset.
- Ogni mutazione persiste un solo record. Un salt CSPRNG di 32 byte alimenta HKDF-SHA-256 per la chiave per record. Prefisso e payload usano nonce distinti sotto quella chiave. Il prefisso autentica l'offset assoluto. Il payload autentica il prefisso cifrato.
- L'indice in memoria si ricostruisce dal log autenticato. Un record completo corrotto impedisce l'apertura. Una coda incompleta consente di leggere i record precedenti, viene segnalata dalla verifica e richiede compattazione prima di nuove scritture.
- Compattazione e rotazione usano lo stesso codec, preparano il nuovo indice prima del cambio di file e interrompono la riscrittura se un record attivo è illeggibile. Il provider AES-GCM Bouncy Castle è riconosciuto come implementazione AES-GCM compatibile.

## File e verifiche

- Core Storage. EncryptedEntryStore.cs, nuovo EncryptedRecordCodec.cs, IAppendOnlyStoreProvider.cs, i backend file e memoria e VerifyResult.cs.
- Documentazione e integrazione. README.md, commento del provider Bouncy Castle, EncryptedStoreTests.cs e VerifyAsyncTests.cs.
- Regressioni aggiunte o aggiornate. Lettura seguita da put concorrenti e riapertura su file, coppie chiave–nonce effettive, coda incompleta, tag corrotti e compattazione interrotta su dato illeggibile.
- Controlli statici. Roslyn ha analizzato i sorgenti C# modificati con le regole C# 13. git diff --check superato. Restore, build e test non eseguiti su indicazione esplicita dell'utente.

Prossimo passo. Quando autorizzato, eseguire restore, build e suite MSTest sui target .NET 9 e .NET 10. Restano da misurare le prestazioni di apertura su log grandi e da confermare a runtime la sostituzione dei file sui sistemi supportati.
