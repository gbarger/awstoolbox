from os import system, name
import base64
import boto3


def main():
    kms_client = get_kms_client()

    while True:
        clear()
        print("\nmain menu:\n\n[1] encrypt\n[2] decrypt\n[3] exit\n")
        input_value = input("action: ")

        if input_value == "1":
            encrypt_menu(kms_client)
        elif input_value == "2":
            decrypt_menu(kms_client)
        elif input_value == "3":
            clear()
            return None
        else:
            print("Please select a valid value.\n")


def encrypt_menu(kms_client):
    clear()
    while True:
        print("\nencrypt menu:\n\n[1] list aliases\n[2] encrypt string\n[3] exit\n")
        input_value = input("action: ")

        if input_value == "1":
            clear()
            kms_aliases = kms_client.list_aliases()
            print("\naliases:\n")

            for alias in kms_aliases["Aliases"]:
                alias_name = alias["AliasName"]
                kms_describe = kms_client.describe_key(KeyId=alias_name)
                print("{} - {}".format(alias_name, kms_describe["KeyMetadata"]["KeyId"]))
        elif input_value == "2":
            input_key = input("provide input key or alias: ")
            input_string = input("string to encrypt: ")

            print("\nencrypted string:\n{}\n".format(encrypt_value(kms_client, input_key, input_string)))
        elif input_value == "3":
            clear()
            return None
        else:
            print("Please select a valid value.\n")


def encrypt_value(kms_client, input_key, input_string):
    ciphertext = kms_client.encrypt(
        KeyId=input_key,
        Plaintext=bytes(input_string, 'utf-8'),
    )

    return  base64.b64encode(ciphertext["CiphertextBlob"]).decode("utf-8")


def decrypt_menu(kms_client):
    clear()
    while True:
        print("\ndecrypt menu:\n\n[1] decrypt string\n[2] exit\n")
        input_value = input("action: ")

        if input_value == "1":
            clear()
            input_string = input("string to decrypt: ")

            print("\ndecrypted string:\n{}\n".format(decrypt_value(kms_client, input_string)))
        elif input_value == "2":
            clear()
            return None
        else:
            print("Please select a valid value.\n")


def decrypt_value(kms_client, input_string):
    plaintext = kms_client.decrypt(
        CiphertextBlob=bytes(base64.b64decode(input_string))
    )

    return plaintext["Plaintext"].decode("utf-8")


def get_kms_client():
    session = boto3.session.Session()
    kms_client = session.client('kms')

    return kms_client


def clear():
    if name == 'nt': 
        system('cls') 
    else: 
        system('clear')


if __name__ == "__main__":
    main()