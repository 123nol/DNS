import socket
import struct
import binascii


dictionary={
  'www.google.com': "192.23.11.3",
  'www.facebook.com': "192.54.88.1",
  'www.youtube.com':"196.43.32.3"

}

class DNS_query:
  def __init__(self,data) -> None:
    self.data=data
    self.domain=''
    self.responseIP=""

  def ext_dmn(self):
    qtype=self.data[2]
    qtype>>=3
    qytpe&=15
    if qtype==0:
    #the first 12 bytes of a dns request packet is the heaeder. the domain in question starts on the 13th byte
      tlen=self.data[12]
      ini=12

      while tlen !=0:
        self.domain+=self.data[ini+1:ini+tlen+1].decode('utf-8') + '.'
        '''
        tlen is the length of each token in the question domain, beacuse by convention each token is preceded by the length of the token in bytes(each character is encoded in one byte each(utf-8) long so it is the same as the actual length of the string )
        '''
        tlen=self.data[ini+tlen+1]
        ini=ini+tlen+1
      self.domain=self.domain[:-1]
      self.responseIP=dictionary[self.domain]
      
  def response(self):
    packet=b''
    #this offset will be used to construct the pointer in the answer section that points to the question section's domain, we made 12 because in DNS packets the 
    #since the header's 12 byte long, the domin will start at the 13byte 
    offset=12
    #the inital C000 hex signifies or tells the compiler/executer that "pointer" is only a pointer and not an actual data, we are ORing it with the offeset value to 
    #to finish contructing the pointer
    pointer=b'/xC0/x00' | offset
    if self.domain and self.responseIP:
      #id
      packet+=self.data[:2]
      #respnse flag, convention
      packet+=b'/x81/x80'
      #question count
      packet+=self.data[4:6]
      #in the request packet the 3rd pair of bytes repesent the count of questions in the packet that need to be addressed 
      #answer count
      packet+=self.data[4:6]
      #authority count(we have none for now)
      packet+=b'/x00/x00'
      #additional section count
      packet+=b'/x00/x00'
      #question section
      packet+=self.data[12:]

      #answer section
      packet+=pointer
      #recordType: 1 for type A
      packet+=b'/x00/x01'
      #class: 1 for IN(internet)
      packet+=b'/x00/x01'
      #TTL(the time we want this response to live in the cache of the client in seconds), 
      # its size is 4
      # bytes by convention(3c=60 meaning we want it to persist for 60 second )
      packet+=b'/x00/x00/x00/x3c'
      #data length(tells how much buffer memory needs to be assigned for the resource data #
      #we send back in our case is an IPv4 address, and all IPv4 address can be stored #
      #within a 4 byte space) 255.255.255.255(the maximum allowed IPv4 address)
      packet+=b'/x00/x04'

      #resource data
      packet+=bytes(map(int,self.responseIP.split('.')))
    return packet


def start_server(port=54):
  server_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  
  host=socket.gethostname()
   




  server_socket.bind((host,port))
  server_socket.listen(1)
  try:
    while True:
      data,sender=server_socket.recvfrom(1024)
      query=DNS_query(data=data)
      query.ext_dmn()
      response=query.response()
      server_socket.sendto(response,sender)
  except KeyboardInterrupt:
    print("closing server")
    server_socket.close

if __name__=="__main__":
  start_server()



  














    


  
    
    

