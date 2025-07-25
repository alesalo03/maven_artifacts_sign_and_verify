import os
import subprocess
import sys


def verify_files(folder, publickey):
    #Definisco una variabile che a fine ciclo indicherà se la verifica della firma è andata a buon fine PER OGNUNO dei file esaminati
    all_signatures_valid = True
    number_of_signatures_verified = 0

    #Importo la chiave all'interno del keyring
    try:
        print(f"Importing public key: {publickey}")
        subprocess.run(
            ["gpg", "--import", publickey],
            check=True,
            capture_output=True,
            text=True
        )
        print("Public key imported successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to import public key: {e}")
        print(f"Command output: {e.stdout}")
        print(f"Command error: {e.stderr}")
        return False


    # Scansiona ricorsivamente la directory corrente e tutte le sottodirectory
    for root, _, files in os.walk(os.path.abspath(folder)):
        for file in files:
            print(file) #stampa il nome del file corrente per debug

            # mi interessa trovare solo i file .asc
            if not file.endswith('.asc'):
                continue

            print("\n----------------------------------------------------------------------------------")
            # ottiene il nome del file senza l'estensione .asc
            file_without_asc = file.removesuffix(".asc")
            # verifica se il file senza l'estensione .asc esiste nella stessa directory, se non esiste lo salta
            if file_without_asc not in files:
                print(f"Skipping {file} as the corresponding file without .asc does not exist.")
                continue

            # Costruisce il percorso completo del file .asc e del artefatto corrispondente
            file_with_asc = os.path.join(root, file)
            file_without_asc = os.path.join(root, file_without_asc)

            try:
                print(f"Verifying: {file_with_asc}")
                # per evitare problemi con la lingua obbligo gpg ad utilizzare l'inglese
                env = os.environ.copy()
                env["LC_ALL"] = "C"
                # Eseguo la verifica passando i due percorsi completi dei file e cattura l'output
                result = subprocess.run(
                    ["gpg", "--status-fd=1", "--verify", file_with_asc, file_without_asc],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=env
                )
                # Analizza l'output per verificare se la firma è valida
                if "[GNUPG:] GOODSIG" in result.stdout:
                    print(f"\nSignature is valid for {file_with_asc}")
                    number_of_signatures_verified += 1
                else:
                    print(f"\nSignature verification failed for {file_with_asc}")
                    all_signatures_valid = False
                    number_of_signatures_verified += 1

                print("----------------------------------------------------------------------------------\n")
            except subprocess.CalledProcessError as e:
                # Gestisce gli errori di esecuzione della verifica
                print(f"Error verifying {file_with_asc}: {e}")
                print(f"Command output: {e.stdout}")
                print(f"Command error: {e.stderr}")

    
    if number_of_signatures_verified == 0:
        print("Nessun file .asc trovato nella cartella specificata.")
    else:
        print("----------------------------------------------------------------------------------\n")
        if all_signatures_valid:
            print("Tutte le firme sono valide\n\n")
        else:
            print("Non tutte le firme sono valide\n\n")

    

# Controlla se è stato passato l'argomento che indica il percorso della cartella su cui eseguire la verifica delle firme
if len(sys.argv) != 3:
    print("Usage: python artifacts_verification_script.py <absolute_path_to_folder> <absolute_path_to_publickey.asc_file>")
    sys.exit(1)

print("Passato il numero corretto di argomenti\n")

# Ottiene i percorsi assoluti dalla riga di comando
folder = sys.argv[1]
publickey = sys.argv[2]

print("Cartella da verificare: ", folder)
print("Path assoluto della public key: ", publickey)

# Esegue la funzione di verifica
verify_files(folder, publickey)