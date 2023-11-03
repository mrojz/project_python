import re
import hashlib
import bcrypt
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from getpass import getpass

def generate_self_signed_certificate():
    pk = open("private_key.pem", "rb")
    private_key = load_pem_private_key(pk.read(), password=None, backend=default_backend())
    pk.close()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tekup"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed Certificate"),
    ])

    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(private_key, hashes.SHA256(), default_backend())
    cert_file = open("self_signed_certificate.pem", "wb")
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    cert_file.close()

def encrypt_rsa_with_certificate():
    message = input("Enter the message to encrypt with the self-signed certificate: ")
    with open("self_signed_certificate.pem", "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        public_key = certificate.public_key()
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    print("Encrypted Message with Certificate:", ciphertext.hex())

def validate_email(email):
    email_regex = r'^[\w\.-]+@[\w\.-]+$'
    return re.match(email_regex, email)

def validate_password(password):
    return re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$', password)

def register():
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email format")

    password = getpass("Enter your password: ")
    if not validate_password(password):
        print("Invalid password format")

    creds =  open("Enregistrement.txt", "a")
    creds.write(f"Email: {email}, Password: {password}\n")

def authenticate():
    email = input("Enter your email: ")
    password = getpass("Enter your password: ")

    creds = open("Enregistrement.txt", "r")
    credentials = creds.readlines()
    for line in credentials:
        if f"Email: {email}, Password: {password}\n" == line:
            return True
    return False

def hash_sha256():
    text = getpass("Enter a text to hash (invisible): ")
    hashed = hashlib.sha256(text.encode()).hexdigest()
    print("SHA-256 Hash:", hashed)

def hash_bcrypt():
    text = getpass("Enter a text to hash (invisible): ")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(text.encode(), salt)
    print("BCrypt Hash:", hashed)

def dictionary_attack():
    dic=input("Enter wordlist filename : ")
    ha=input("Enter the hash: ")
    hash_type=int(input("1) SHA256 \n2) md5\n>>>> "))
    if hash_type in [1,2]:
        dic_file=open(dic,"r").read().splitlines()
        if hash_type==1:
            for word in dic_file:
                if hashlib.sha256(word.encode()).hexdigest()==ha:
                    print("Hash trouvé !! le mot craqué : "+word)
                    print ("Done !")
                    return
        if hash_type==2:
            for word in dic_file:
                if hashlib.md5(word.encode()).hexdigest()==ha:
                    print("Hash trouvé !! le mot craqué : "+word)
                    print ("Done !")
                    return
    print ("Done !")

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_file = open("private_key.pem", "wb")
    private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
    ))
    private_key_file.close()

    public_key = private_key.public_key()
    public_key_file = open("public_key.pem", "wb")
    public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    public_key_file.close()

    print("RSA key pair generated and saved as private_key.pem and public_key.pem")

# Fonctions pour le chiffrement et le déchiffrement RSA
def encrypt_rsa():
    message = input("Enter the message to encrypt with RSA: ")
    public_key_file = open("public_key.pem", "rb").read()
    public_key = serialization.load_pem_public_key(public_key_file, backend=default_backend())
    ciphertext = public_key.encrypt(message.encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print("Encrypted Message:", ciphertext.hex())

def decrypt_rsa():
    ciphertext = bytes.fromhex(input("Enter the ciphertext to decrypt with RSA (hexadecimal): "))
    private_key_file = open("private_key.pem", "rb")
    private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())
    private_key_file.close()
    plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print("Decrypted Message:", plaintext.decode())

# Fonctions pour la signature et la vérification RSA
def sign_rsa():
    message = input("Enter the message to sign with RSA: ")
    private_key_file = open("private_key.pem", "rb")
    private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())
    private_key_file.close()
    signature = private_key.sign(message.encode(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    print("Signature:", signature.hex())

def verify_rsa_signature():
    message = input("Enter the original message: ")
    signature = bytes.fromhex(input("Enter the signature to verify (hexadecimal): "))
    public_key_file = open("public_key.pem", "rb")
    public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())
    public_key_file.close()
    try:
        public_key.verify(signature,message.encode(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        print("Signature is valid.")
    except Exception:
        print("Signature is not valid.")

def main():
    while True:
        print("\nMenu:")
        print("1) Register")
        print("2) Authenticate")
        print("3) Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            register()
        elif choice == '2':
            if authenticate():
                print("Authentication successful.")
                while True:
                    print("\nAuthenticated Menu:")
                    print("1) Hashing")
                    print("2) RSA Encryption/Decryption and Signing/Verification")
                    print("3) Certificate (RSA)")
                    print("4) Exit")
                    sub_choice = input("Enter your choice: ")

                    if sub_choice == '1':
                        print("1) SHA-256 Hash")
                        print("2) BCrypt Hash")
                        print("3) Dictionary Attack")
                        print("4) Back to main menu")
                        sub_choice_a = input("Enter your choice: ")
                        if sub_choice_a == '1':
                            hash_sha256()
                        elif sub_choice_a == '2':
                            hash_bcrypt()
                        elif sub_choice_a == '3':
                            dictionary_attack()
                        elif sub_choice_a == '4':
                            break
                        else:
                            print("Invalid choice")
                    elif sub_choice == '2':
                        print("1) Generate RSA Keys")
                        print("2) Encrypt with RSA")
                        print("3) Decrypt with RSA")
                        print("4) Sign with RSA")
                        print("5) Verify RSA Signature")
                        print("6) Back to main menu")
                        sub_choice_b = input("Enter your choice: ")
                        if sub_choice_b == '1':
                            generate_rsa_keys()
                        elif sub_choice_b == '2':
                            encrypt_rsa()
                        elif sub_choice_b == '3':
                            decrypt_rsa()
                        elif sub_choice_b == '4':
                            sign_rsa()
                        elif sub_choice_b == '5':
                            verify_rsa_signature()
                        elif sub_choice_b == '6':
                            break
                        else:
                            print("Invalid choice")
                    elif sub_choice == '3':
                        print("1) Generate RSA Keys")
                        print("2) Generate Self-Signed Certificate")
                        print("3) Encrypt with Certificate")
                        print("4) Back to authenticated menu")
                        sub_choice_c = input("Enter your choice: ")
                        if sub_choice_c == '1':
                            generate_rsa_keys()
                        elif sub_choice_c == '2':
                            generate_self_signed_certificate()
                        elif sub_choice_c == '3':
                            encrypt_rsa_with_certificate()
                        elif sub_choice_c == '4':
                            break
                        else:
                            print("Invalid choice")
                    elif sub_choice == '4':
                        break
                    else:
                        print("Invalid choice")
            else:
                print("Authentication failed.")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()