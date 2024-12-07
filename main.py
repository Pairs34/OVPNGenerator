import json
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# config.json dosyasını yükle
with open("config.json", "r") as cfg_f:
    config = json.load(cfg_f)

output_dir = config["output"]  # config.json içindeki output key'ini okuduk.

# Root CA sertifikasını ve private keyini yükle
with open("ca.crt", "rb") as f:
    root_ca_cert = x509.load_pem_x509_certificate(f.read())

with open("ca.key", "rb") as f:
    root_ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# OVPN şablonunu yükle
with open("template.ovpn", "r") as f:
    ovpn_template = f.read()

# users.txt içeriğinden kullanıcı adlarını oku
with open("users.txt", "r") as f:
    users = f.readlines()

for user in users:
    username = user.strip()
    if not username:
        continue  # Boş satır varsa atla

    # İstemci için özel anahtar oluştur
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # CSR oluştur
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(client_private_key, hashes.SHA256())

    # İstemci sertifikasını Root CA ile imzala
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(username)]),
            critical=False,
        )
        .sign(root_ca_private_key, hashes.SHA256())
    )

    # Üretilen sertifika ve key’i PEM formatında string olarak al
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    client_key_pem = client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # OVPN şablonunun içine sertifika ve key’i yerleştir
    ovpn_content = ovpn_template.replace("<cert>\n</cert>", f"<cert>\n{client_cert_pem}\n</cert>") \
                                .replace("<key>\n</key>", f"<key>\n{client_key_pem}\n</key>")

    # username.ovpn dosyasına config.json'dan okuduğumuz output klasörüne kaydet
    output_path = os.path.join(output_dir, f"{username}.ovpn")
    with open(output_path, "w") as out_f:
        out_f.write(ovpn_content)

    print(f"{username}.ovpn oluşturuldu!")
