# import time for time.sleep() function what is the animation for the text outputs
import time
import os

# main code entrypoint
def startProtocol():

    text = "Loading to Start Simple CLI..."
    for a in text:
        print(a, end="", flush=True)
        time.sleep(0.1)
    print()

# comment of the before a login/signup
def beforeLogin():

    text = "Please select your option"
    for a in text:
        print(a, end="", flush=True)
        time.sleep(0.1)

# print line for next output
def line():

    print("=====================================")
    time.sleep(0.5)

def login():

    line()
    text = "Please Enter your Username and Password"
    for a in text:
        print(a, end="", flush=True)
        time.sleep(0.1)
    print()

    username = str(input("Username : "))
    password = str(input("Password : "))
    line()

    if (username == "chacha1650a" and password == "admin_123456"):
        print("Login Success!")
    else :
        print("Username or Password is incorrect!")


    
# 2 options for user's select
def selectOption():

    print("1. Login\n2. SignUp")
    line()
    option = int(input())

    if (option == 1):
        login()
    elif (option == 2):
        print("2")

# calling function 
startProtocol()
time.sleep(0.5)

line()
selectOption()