import pathlib
import msgpack

CWD = pathlib.Path(__file__).resolve().parent
USERS_DIR = CWD / "Users/"

username = input("Username: ")

with open(USERS_DIR / f"{username}.usr", "rb+") as f:
    userData = msgpack.unpackb(f.read())

    print(userData)
    userData["USRNAME"] = "GigaPixel_Entertainment"
    print(userData)

    f.seek(0)
    f.write(msgpack.packb(userData))
    f.truncate()

    f.close()

print("User edited successfully!")