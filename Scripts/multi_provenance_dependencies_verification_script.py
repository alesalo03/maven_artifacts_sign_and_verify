import subprocess
from pathlib import Path
import sys

MAVEN_CMD = r"C:/Program Files/apache-maven-3.9.9/bin/mvn.cmd"

def run_mvn_copy_dependencies():
    print("Eseguo 'mvn dependency:copy-dependencies' per copiare le dipendenze in target/dependency...")
    try:
        result = subprocess.run(
            [MAVEN_CMD, "dependency:copy-dependencies", "-DoutputDirectory=C:/Users/Alessandro/Documents/UNI/Tirocinio/multi_provenance_example/trusted-artifacts-test/target/dependency", "-DincludeScope=runtime"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Errore eseguendo mvn dependency:copy-dependencies:\n{e.stderr}")
        sys.exit(1)

def verify_jar_signature(jar_path, truststore_path=None, truststore_password=None):
    cmd = [
        "jarsigner", "-verify", "-verbose", "-certs", str(jar_path)
    ]
    if truststore_path:
        cmd += [
            "-J-Djavax.net.ssl.trustStore=" + truststore_path
        ]
        if truststore_password:
            cmd += [
                "-J-Djavax.net.ssl.trustStorePassword=" + truststore_password
            ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Errore verificando {jar_path}: {e}")
        return False

def main(truststore_path, truststore_password):
    run_mvn_copy_dependencies()

    dep_dir = Path("C:/Users/Alessandro/Documents/UNI/Tirocinio/multi_provenance_example/trusted-artifacts-test/target/dependency")
    if not dep_dir.exists():
        print(f"La cartella {dep_dir} non esiste dopo 'copy-dependencies', qualcosa è andato storto.")
        sys.exit(1)

    jars = list(dep_dir.glob("*.jar"))
    if not jars:
        print(f"Nessun JAR trovato in {dep_dir} da verificare!")
        sys.exit(1)

    print(f"Verifico la firma di {len(jars)} JAR in {dep_dir}...\n{'-'*50}")

    failed_count = 0
    for jar_path in jars:
        print(f"Verifico: {jar_path}")
        if verify_jar_signature(jar_path,truststore_path, truststore_password):
            print("  --> Firma OK")
        else:
            print("  --> Firma NON valida o assente!")
            failed_count += 1

    print('-'*50)
    if failed_count == 0:
        print("Tutti i JAR firmati risultano corretti.")
        sys.exit(0)
    else:
        print(f"Attenzione! {failed_count} JAR hanno firme non valide o mancanti.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py <truststore_path> <truststore_password>")
        sys.exit(1)
    truststore_path = sys.argv[1]
    truststore_password = sys.argv[2]
    main(truststore_path, truststore_password)
