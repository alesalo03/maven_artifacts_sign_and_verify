import os
import subprocess
import sys
import zipfile
import re
import urllib.request
import requests
import tempfile
import shutil

def get_maven_central_base_url_from_jar(jar_url):
    base_repo_url = "https://repo1.maven.org/maven2/"
    try:
        with zipfile.ZipFile(jar_url, 'r') as jar:
            pom_props_path = None
            for name in jar.namelist():
                if name.endswith("pom.properties") and name.startswith("META-INF/maven/"):
                    pom_props_path = name
                    break

            if pom_props_path is None:
                print(f"No pom.properties found in {jar_url}, skipping.")
                return None

            with jar.open(pom_props_path) as prop_file:
                props = prop_file.read().decode('utf-8').splitlines()
                props_dict = {k.strip(): v.strip() for line in props if '=' in line for k, v in [line.split('=', 1)]}
                group_id = props_dict.get("groupId")
                artifact_id = props_dict.get("artifactId")
                version = props_dict.get("version")

                if not all([group_id, artifact_id, version]):
                    print(f"Missing info in pom.properties of {jar_url}, skipping.")
                    return None

                group_path = group_id.replace('.', '/')
                url_base = f"{base_repo_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}."
                print("URL BASE: "+url_base)
                return [url_base, group_id, artifact_id, version]
    except zipfile.BadZipFile:
        print(f"{jar_url} is not a valid jar file, skipping.")
        return None


def get_maven_central_files(jar_dir, pom_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    downloaded_files = []

    for filename in os.listdir(jar_dir):
        jar_path = os.path.normpath(os.path.join(jar_dir, filename))
        try:
            result = get_maven_central_base_url_from_jar(jar_path)
            if result is None:
                saltati.append(jar_path)
                continue

            url_base, groupId, artifactId, version = result
            pom_name = f"{artifactId}-{version}.pom"
            pom_path = os.path.normpath(os.path.join(pom_dir, pom_name))

            url_jar_asc = f"{url_base}jar.asc"
            url_pom_asc = f"{url_base}pom.asc"

            file_jar_asc = os.path.normpath(os.path.join(output_dir, f"{artifactId}-{version}.jar.asc"))
            file_pom_asc = os.path.normpath(os.path.join(output_dir, f"{artifactId}-{version}.pom.asc"))

            try:
                print(f"Scarico: {url_jar_asc}")
                urllib.request.urlretrieve(url_jar_asc, file_jar_asc)
                print(f"Scarico: {url_pom_asc}")
                urllib.request.urlretrieve(url_pom_asc, file_pom_asc)
                downloaded_files.append([jar_path, pom_path, file_jar_asc, file_pom_asc])
            except Exception as e:
                print(f"Errore nel download di {artifactId}: {e}")
        except zipfile.BadZipFile:
            print(f"{filename} is not a valid jar file, skipping.")
            continue

    return downloaded_files


def extract_fingerprint(asc_path):
    try:
        result = subprocess.run(
            ['gpg', '--list-packets', asc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        match = re.search(r'issuer fpr v4 ([A-F0-9]{40})', result.stdout)
        if match:
            return match.group(1)
        else:
            raise ValueError("Fingerprint non trovato nel file ASC")
    except subprocess.CalledProcessError as e:
        print("Errore durante l'analisi del file .asc:", e.stderr)
        return None


def create_temp_keyring():
    temp_dir = tempfile.mkdtemp(prefix="gpg_keyring_")
    os.makedirs(os.path.normpath(os.path.join(temp_dir, "private-keys-v1.d")), exist_ok=True)
    return temp_dir


def import_key_to_keyring(key_path, keyring_dir):
    try:
        subprocess.run(
            ['gpg', '--homedir', keyring_dir, '--import', key_path],
            check=True
        )
        print(f"Chiave importata correttamente in {keyring_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Errore nell'import della chiave: {e}")
        return False


def download_key_from_servers(fingerprint, output_path, keyring_dir):
    servers = [
        f"https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}",
        f"https://pgp.surf.nl/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://pgpkeys.eu/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://keys.mailvelope.com/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://keyserver.pgp.com/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://keyserver.cryptnet.net/pks/lookup?op=get&search=0x{fingerprint}",
        f"https://zimmermann.mayfirst.org/pks/lookup?op=get&search=0x{fingerprint}"
    ]

    for url in servers:
        print(f"Provo: {url}")
        try:
            response = requests.get(url, timeout=10)
            if "BEGIN PGP PUBLIC KEY BLOCK" in response.text:
                with open(output_path, "w") as f:
                    f.write(response.text)
                print(f"Chiave trovata da {url} e salvata in {output_path}")
                if import_key_to_keyring(output_path, keyring_dir):
                    os.remove(output_path)
                    return True
        except Exception as e:
            print(f"Errore contattando {url}: {e}")

    print("Nessun keyserver ha restituito la chiave pubblica.")
    return False

def verify_signature(keyring_dir, signature_file, file_to_verify):
    try:
        result = subprocess.run(
            ['gpg', '--homedir', keyring_dir, '--verify', signature_file, file_to_verify],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "Good signature" in result.stderr or "gpg: Firma valida da" in result.stderr:
            print(f"Verifica OK per {file_to_verify} con {signature_file}")
            return True
        else:
            print(f"Verifica FALLITA per {file_to_verify} con {signature_file}.\nGPG output:\n{result.stderr}")
            return False
    except Exception as e:
        print(f"Errore nella verifica della firma: {e}")
        return False




# === MAIN SCRIPT ===

if len(sys.argv) != 1:
    print("Usage: python artifacts_verification_script.py")
    sys.exit(1)

print("Passato il numero corretto di argomenti\n")

#uso queste liste per fare un recap finale di come sono andate le verifiche
verifiche_ok = []
verifiche_ko = []
saltati = []

#scarico tutti i file necessari per la verifica
files = get_maven_central_files("target/dependency/mavenCentral", "target/dependency/poms", "target/asc")
print("Files scaricati:", files)

# Crea un keyring temporaneo
keyring_temp = create_temp_keyring()
print(f"Keyring temporaneo creato in: {keyring_temp}")

# Scarica e importa le chiavi nel keyring temporaneo
for riga in files:
    asc_path = riga[2]
    fingerprint = extract_fingerprint(asc_path)
    if fingerprint:
        temp_key_path = os.path.join("target", f"{fingerprint}.asc")
        download_key_from_servers(fingerprint, temp_key_path, keyring_temp)

# Eseguo la verifica delle firme per ogni artefatto
print("\nVerifica delle firme:")
for riga in files:
    jar_file = riga[0]
    pom_file = riga[1]
    jar_asc = riga[2]
    pom_asc = riga[3]

    jar_verifica = verify_signature(keyring_temp, jar_asc, jar_file)
    pom_verifica = verify_signature(keyring_temp, pom_asc, pom_file)

    if jar_verifica and pom_verifica:
        verifiche_ok.append((jar_file, pom_file))
    else:
        verifiche_ko.append((jar_file, pom_file))


# elimino il keyring temporaneo
shutil.rmtree(keyring_temp)
print(f"Keyring temporaneo eliminato: {keyring_temp}")

# riepilogo finale
print("\n\n===== RIEPILOGO =====\n\n")
print(f"DIPENDENZE VERIFICATE CON SUCCESSO: {len(verifiche_ok)}")
for jar, pom in verifiche_ok:
    print(f"  - {os.path.basename(jar)}")

print(f"\nDIPENDENZE VERIFICATE CON INSUCCESSO: {len(verifiche_ko)}")
for jar, pom in verifiche_ko:
    print(f"  - {os.path.basename(jar)}")

print(f"\nDIPENDENZE CHE NON SONO STATE VERIFICATE: {len(saltati)}")
for skipped in saltati:
    print(f"  - {os.path.basename(skipped)}")

print("\n\n")
