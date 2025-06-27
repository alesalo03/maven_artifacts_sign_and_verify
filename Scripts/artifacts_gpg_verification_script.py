import os
import subprocess
import sys


def get_maven_central_urls_from_jars(jar_dir, output_dir):
    base_repo_url = "https://repo1.maven.org/maven2/"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for filename in os.listdir(jar_dir):
        jar_path = os.path.join(jar_dir, filename)
        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                # Cerco il file pom.properties in META-INF/maven/**/
                pom_props_path = None
                for name in jar.namelist():
                    if name.endswith("pom.properties") and name.startswith("META-INF/maven/"):
                        pom_props_path = name
                        break
                if pom_props_path is None:
                    print(f"No pom.properties found in {filename}, skipping.")
                    continue

                with jar.open(pom_props_path) as prop_file:
                    props = prop_file.read().decode('utf-8').splitlines()
                    props_dict = {}
                    for line in props:
                        if '=' in line:
                            k, v = line.split('=', 1)
                            props_dict[k.strip()] = v.strip()

                    group_id = props_dict.get("groupId")
                    artifact_id = props_dict.get("artifactId")
                    version = props_dict.get("version")

                    if not all([group_id, artifact_id, version]):
                        print(f"Missing info in pom.properties of {filename}, skipping.")
                        continue

                    group_path = group_id.replace('.', '/')
                    urlBase = f"{base_repo_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}."
                    urlJar = f"{urlBase}jar"
                    urlJarAsc = f"{urlBase}jar.asc"
                    urlPom = f"{urlBase}pom"
                    urlPomAsc = f"{urlBase}pom.asc"

                    try:
                        local_file = os.path.join(output_dir, f"{artifact_id}-{version}.jar.asc")
                        print(f"Scarico: {url}")
                        urllib.request.urlretrieve(url, local_file)
                        except Exception as e:
                            print(f"Errore nel download di {artifact_id}: {e}")

        except zipfile.BadZipFile:
            print(f"{filename} is not a valid jar file, skipping.")
            continue


def extract_key_id_from_asc(asc_path):
    result = subprocess.run(["gpg", "--list-packets", asc_path], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "keyid" in line:
            return line.strip().split("keyid ")[-1]
    return None

def verify_signatures(asc_dir, jar_dir):
    for filename in os.listdir(asc_dir):
        asc_path = os.path.join(asc_dir, filename)
        jar_name = filename.replace(".jar.asc", ".jar")
        jar_path = os.path.join(jar_dir, jar_name)

        print(f"\nVerifico: {jar_name}")

        key_id = extract_key_id_from_asc(asc_path)
        if not key_id:
            print("Impossibile estrarre il Key ID dal file .asc")
            continue

        print(f"Scarico chiave: {key_id}")
        recv = subprocess.run(["gpg", "--keyserver", "hkps://keys.openpgp.org", "--recv-keys", key_id])
        if recv.returncode != 0:
            print("Errore nel download della chiave")
            continue

        # Verifica firma
        result = subprocess.run(["gpg", "--verify", asc_path, jar_path], capture_output=True, text=True)
        if "Good signature" in result.stderr:
            print("Firma valida")
        else:
            print("Firma non valida:\n", result.stderr.strip())


# Controlla se è stato passato l'argomento che indica il percorso della cartella su cui eseguire la verifica delle firme
if len(sys.argv) != 1:
    print("Usage: python artifacts_verification_script.py")
    sys.exit(1)

print("Passato il numero corretto di argomenti\n")

#ottengo la lista delle dipendenze del progetto verso Maven Central
centralMavenUrls = get_maven_central_urls_from_jars()
printf("urls: ", centralMavenUrls)

#scarica tutti i file di ogni dipendenza dal maven central
download_asc_files(centralMavenUrls, "target/asc-central")


# Esegue la funzione di verifica
verify_signatures("target/asc-central", "target/dependency/mavenCentral")