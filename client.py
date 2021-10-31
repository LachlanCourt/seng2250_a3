import socket, time, sys
from IdGen import IdGen
from RSA import RSA
from SHA import SHA
from Comms import Comms
from DH import DH
from Hmac import Hmac
from AES2 import AES2

DHp = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
DHg = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730

def log(msg):
    print("\nCLIENT LOGGING: " + msg)

def serialise(data):
    return str.encode(str(data))

def deserialise(data):
    return data.decode()


if __name__ == "__main__":
    idGen = IdGen()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to server
        log("Connecting to server")
        s.connect(("localhost", 50007))
        log("Connected")
        
        # Send setup request
        log("Sending setup request: Hello")
        s.sendall(b"Hello")

        # Receive keys
        data = deserialise(s.recv(2048)).split("#")
        rsan = int(data[0])
        log(f"Key n received: \n{rsan}")
        rsae = int(data[1])
        log(f"Key e received: \n{rsae}")

        # Generate and send RSA key
        log("Generating client RSA keys")
        keys = RSA.genRSA()
        sendMessage = str(keys[0][0]) + "#" + str(keys[0][1])
        log(f"Sending RSA public keys: \n{sendMessage}")
        s.sendall(serialise(sendMessage)) # public key n and e

        time.sleep(3)
        
        ## NEW COMMUNICATION ##

        # Send Client Hello
        idc = idGen.getID(20)
        log(f"Sending client hello:\n{idc}")
        s.sendall(serialise(idc))

        # Receive IDs and SID
        data = s.recv(2048)
        ids = deserialise(data)
        log(f"IDs received: \n{ids}")
        data = s.recv(2048)
        sid = deserialise(data)
        log(f"SID received: \n{sid}")

        # Send p for DH key exchange
        message = DHp
        encrypted = Comms.sendRSAMessage(s, rsan, rsae, keys, message)
        log(f"Sending RSA encrypted DHp prime and RSA signature: \n{encrypted}")
        # Send g for DH key exchange
        message = DHg
        encrypted = Comms.sendRSAMessage(s, rsan, rsae, keys, message)
        log(f"Sending RSA encrypted DHg generator and RSA signature: \n{encrypted}")

        # Receive server public key
        servPub = int(Comms.recvRSAMessage(s, rsan, rsae, keys))
        log(f"Received DH public key: \n{servPub}")

        # Generate DH keys
        dhPriv = DH.genPrivateKey(DHp)
        log(f"Generated DH private key: \n{dhPriv}")
        dhPub = DH.genPublicKey(DHp, DHg, dhPriv)
        
        # Send public key with no encryption, as the server doesn't need to verify the client
        s.sendall(serialise(dhPub))
        log(f"Sending public key: \n{dhPub}")

        # Calculate session key
        sessionKey = DH.genSessionKey(servPub, dhPriv, DHp)
        log(f"Calculated session key: \n{sessionKey}")

        # Check session key
        clientHashed = SHA.hash(str(sessionKey) + idc + sid)
        log(f"Sending hashed key with id and session id: \n{clientHashed}")
        s.sendall(serialise(clientHashed))

        
        serverHashed = deserialise(s.recv(10000))
        log(f"Received server hashed key with id and session id:\n{clientHashed}")
        testHashed = SHA.hash(str(sessionKey) + idc + ids + sid)
        if serverHashed != testHashed:
            s.close()
            sys.exit(1)
        log("Server session key is valid")

        ###### Data Exchange ######

        # Send message
        message = "This message is exactly 64 bytes long to be encrypted with AES!!"
        log(f"Message to be sent to server:\n{message}")
        encryptedMessage = AES2.encrypt(message, sessionKey)
        #encryptedMessage = message
        log(f"Generated encrypted message: \n{encryptedMessage}")
        # Create HMAC from session key
        messageMac = Hmac.hmac(encryptedMessage, sessionKey)
        log(f"Hashed message for integrity: \n{messageMac}")
        sendMessage = encryptedMessage + "#" + messageMac
        s.sendall(serialise(sendMessage))
        log(f"Sending encrypted message: \n{sendMessage}")


        # Receive message
        data = deserialise(s.recv(10000)).split("#")
        log(f"Received AES encrypted message with hash verification: \n{data}")
        if not Hmac.verHmac(data[0], data[1], sessionKey):
            s.close()
            sys.exit(1)
        log(f"Hash verified data: \n{data[0]}")
        message = AES2.decrypt(data[0], sessionKey)
        log(f"Decrypted AES data to original message: \n{message}")























        
        
