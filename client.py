import socket, time
from IdGen import IdGen
from RSA import RSA
from SHA import SHA
from Comms import Comms
from DH import DH

DHp = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
DHg = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730

def log(msg):
    print("CLIENT LOGGING: " + msg)

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
        data = s.recv(2048)
        rsan = int(deserialise(data))
        log(f"Key n received: \n{rsan}")
        data = s.recv(2048)
        rsae = int(deserialise(data))
        log(f"Key e received: \n{rsae}")

        # Generate and send RSA key
        log("Generating client RSA keys")
        keys = RSA.genRSA()
        log(f"Sending RSA public key n: \n{keys[0][0]}")
        s.sendall(serialise(keys[0][0])) # public key n
        log(f"Sending RSA public key e: \n{keys[0][1]}")
        s.sendall(serialise(keys[0][1])) # public key e


        time.sleep(3)
        ## NEW COMMUNICATION ##

        # Send Client Hello
        idc = idGen.getID(20)
        log(f"Sending client hello:\n {idc}")
        s.sendall(serialise(idc))

        # Receive IDs and SID
        data = s.recv(2048)
        ids = data
        log(f"IDs received: \n{ids}")
        data = s.recv(2048)
        sid = data
        log(f"SID received: \n{sid}")

        # Send p for DH key exchange
        message = DHp
        encrypted = Comms.sendEncryptedMessage(s, rsan, rsae, keys, message)
        log(f"Sending RSA encrypted DHp prime and RSA signature: \n{encrypted}")
        # Send g for DH key exchange
        message = DHg
        encrypted = Comms.sendEncryptedMessage(s, rsan, rsae, keys, message)
        log(f"Sending RSA encrypted DHg generator and RSA signature: \n{encrypted}")

        # Receive server public key
        servPub = int(Comms.recvEncryptedMessage(s, rsan, rsae, keys))
        log(f"Received DH public key: \n{servPub}")

        # Generate DH keys
        dhPriv = DH.genPrivateKey(DHp)
        log(f"Generated DH private key: \n{dhPriv}")
        dhPub = DH.genPublicKey(DHp, DHg, dhPriv)
        # Send public key
        encrypted = Comms.sendEncryptedMessage(s, rsan, rsae, keys, dhPub)
        log(f"Sending RSA encrypted public key: \n{encrypted}")

        # Calculate session key
        sessionKey = DH.genSessionKey(servPub, dhPriv, DHp)
        log(f"Calculated session key: \n{sessionKey}")

























        
        
