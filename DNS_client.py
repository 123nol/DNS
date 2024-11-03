import socket
import struct
import binascii
import random
import sys
class DQuery:
  def __init__(self,domain) -> None:
    self.domain=domain
    #here the gethostname returns the ip of whereever the program is running from and since the server is also running from the computer the serverIP is the same 
    #as the ip we get here form gethostname, since both the client and server are running from the computer
    self.host_addr=(str(socket.gethostname),54)
    self.request_packet=b''
    self.response_packet=b'' 
  def form_packet(self):
    
    rq_pkt=b''
    pId=struct.pack("!H",random.randint(1000,5000))
    pFlag=b'/x00/x00'
    qCount=b'/x00/x01'
    aCount=b'/x00/x00'
    AtCount=b'x00/x00'
    AdCount=b'/x00/x00'
    rq_header=b''
    rq_header+=pId+pFlag+qCount+aCount+AtCount+AdCount







    if self.domain:
      rq_pkt+=rq_header
      pQsec=b''
      pDomain=b''
      Dsplit=list(self.domain.split("."))
      for token in Dsplit:
        #converts it into an 8 bit binary
        Ilen=struct.pack("!B", len(token))
        pDomain+=Ilen
        pDomain+=token.encode()
      pDomain+=b'/x00'
      pQsec+=pDomain
      #Qtype: 1 for type A
      pQsec+=b'/x00/x01'
      #Qclass: 1 for class Internet
      pQsec+=b'/x00/x01'
      

    
      rq_pkt+=pQsec
    self.request_packet=rq_pkt
  
  
  def connect_server(self):
    if self.request_packet:
      clientSocket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
      clientSocket.connect(self.host_addr)
      clientSocket.send(self.request_packet)
      self.response_packet=clientSocket.recv(1024)
      clientSocket.close()
  
  
  def decode_response(self):
    #this funtion gets the ip bytes from the response then decodes it, then concatnate the four components of the ip using a dot, then prints that ip string, it can also return it.
    data=self.response_packet
    domain_ip=""
    
    pointer=data[12]
    ini=12
    #counter stores the size of each token of the domain in the quesiton section
    #we are doing this to find where in the response packet we should refernce, to get the resourceData(ip)
    while pointer!=0:
      counter+=pointer
      ini+=counter
      pointer=data[ini]
      
    
    #the first +1 accounts for the 0 byte at the end of the qsec, then the two +2s account for the Qtype and Qclass 2 bytes each respectively
    sizeOfQsec=counter+1+2+2
    
    #this is the count of bytes in the answer section before the actual resource data
    # the additions account for bytes occupied by the pointer, the record type,the class, the TTL, and the resource Data length respectively
    sizeOfAns= 2+2+2+4+2

    #itterate over each byte in the 4 byte IPv4 address, each byte correspnds to the each of the four values in an ip address
    for i in range(4):
      domain_ip+=str(data[12+sizeOfQsec+sizeOfAns+i])+"."
    #droping the "." at the end
    domain_ip=domain_ip[:-1]
    
    return domain_ip

def make_request():
  site=str(sys.argv[1])
  query=DQuery(site)
  query.form_packet()
  query.connect_server()
  ip=query.decode_response()
  print(ip)



if __name__=="__main__":
  make_request()







    
        
      
    