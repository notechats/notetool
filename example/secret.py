from notetool import SecretManage, encrypt, decrypt

secret = SecretManage()
v = secret.read("drive", "lanzou", 'phpdisk_info')
print(v)


def run1():
    text = 'My super secret message'
    print(encrypt(text))
    print(encrypt(text))
    print(decrypt(encrypt(text)))
