STRUTTURA DELLA REPOSITORY:
- la directory "Scripts" contiene lo script "artifacts_gpg_verification_script.py" che può essere utilizzato per la verifica dell'autenticità e integrità degli artefatti provenienti dal Maven Central Repository.
- la directory "multi_provenance_example" contiene:
  - una repository locale su cui viene fatto il deploy degli artefatti "interni", chiamata "maven-repos/internal/com/mycompany/secure-lib".
  - un progetto con dipendenze verso la repository locale sopra descritta e verso il Maven Central Repository (trusted-artifacts-test).
  - un progetto di test che si occupa della creazione di un artefatto "interno" il cui deploy avviene all'interno della repository locale (secure-lib).
