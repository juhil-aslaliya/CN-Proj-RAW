""" When submitting, remove many lines in such 3-quotes, cuz they are instructions. """

import socket, threading, sys, time, os, signal, time

lock = threading.Lock()
if(not(os.path.exists("Logs"))): os.mkdir("Logs")
log_file_name = "Logs/logs_" + str(time.localtime()[0])[2:] + str(time.localtime()[1]) + str(time.localtime()[2]) + "_" + str(time.localtime()[3]) + str(time.localtime()[4]) + str(time.localtime()[5]) + ".py"

""" When submitting, Comment out all the lines where debug_option=1 , in all the invokations of this fn """
# The invokations with debug_option=1, can be used to debug the program , you need to simply uncomment them.  
def logg(debug_option,message):
    print(message)
    log_file_fd = open(log_file_name,"a")
    log_file_fd.write("\n"+"Debug -> "*(debug_option==1) + message)      # To not print the msg, change `1` to `0` ; To not show "Debug->", change `1` to `2`
    log_file_fd.close()

def signal_handler(signal,frame):
    """ To make the program stop when Ctrl+C is pressed. """
    logg(0,'\n\nExiting via Ctrl+C.')
    sys.exit(0)

signal.signal(signal.SIGINT,signal_handler)
logg(0,'\nPress Ctrl+C and wait for some time to exit.')


class ProxyServer:

    def __init__(self,host,port):
        """ Creates a server on the `host` and listens to `port`. Initiates other resources. """
        self.server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server.bind((host,port))
        self.server.listen(5)
        self.cache = {}
        self.cache_content_times = 0
        self.keep_cleaning_cache = True
        self.blocked_urls = ["example.com"]
        self.forbidden_url_message = "\nThis URL is blocked by proxy."
        self.uncache_time = 5 # In seconds            # <<<<<<<<------------------------- Change this later
        logg(0,f"\n[*] Proxy server started on {host}:{port} .\n")


    def uncache(self):
        while(self.keep_cleaning_cache):
            logg(1,f"\n Cache invalidated at this time : {time.time()} . \n")
            with lock:      # Because the cache is a shared resourse between Uncache thread & client_handler threads
                curr_time = time.time()
                for url in self.cache:
                    if(self.cache[url][1] - curr_time >= self.uncache_time):
                        del self.cache[url]
            time.sleep(self.uncache_time)
            logg(1,f"\n Cache status at this time is : {self.cache} . \n")


    def handle_client(self,client_socket):
        """ Proccesses a request for a client, using our implemented proxy. """
        # Get the request from the client browser and extract info
        request = client_socket.recv(4096)
        logg(1,f"This is the request :  || {request}  || .")
        first_line = request.split(b'\n')[0]
        url = first_line.split(b' ')[1]
        logg(1,str(first_line[2:])+" is the first line of request.")
        

        # Check if URL is blocked
        for blocked_url in self.blocked_urls:
            if blocked_url.encode() in url:
                client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\n" + self.forbidden_url_message + b".")
                client_socket.close()
                logg(1,"Forbidden URL. Closing.\n")
                return
        

        # Check if URL is cached
        if url in self.cache:
            with lock:          # Cache is shared between uncaching/using
                client_socket.send(self.cache[url][0])
                client_socket.close()
                logg(1,"Cahed URL. Sending cached.\n")
                return


        # Otherwise, contact destination server and fetch data

        # Extract the destination host and port from the request
        http_pos = url.find(b"http://")
        if(http_pos == -1): temp = url
        else: temp = url[(http_pos+7):]
        
        port_pos = temp.find(b":")
        web_server_pos = temp.find(b"/")
        if(web_server_pos == -1): web_server_pos = len(temp)
        
        web_server = ""
        port = -1
        if(port_pos == -1 or web_server_pos < port_pos):
            port = 80
            web_server = temp[:web_server_pos]
        else:
            port = int(temp[(port_pos+1):web_server_pos])
            web_server = temp[:port_pos]


        # Connect to destination and request for data
        try:
            destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            destination_server.connect((web_server,port))


            """ THE CAUSE OF ERROR 404 MAY BE LYING HERE. 
            `We` are sending the `original` request, may be invalidating `checksum` at the server. """
            destination_server.send(request)
            """ request = b"GET / HTTP/1.1\r\nHost: " + web_server + b"\r\n\r\n"
                destination_server.send(request)  
                
                If you're trying to access http://www.google.com, then web_server would be www.google.com.
                If you're trying to access http://example.com/some/path, then web_server would be example.com.
                If you're trying to access http://another-example.com:8080, then web_server would be another-example.com.

            """


            response_data = b""
            while(True):
                data = destination_server.recv(4096)
                if(len(data) <= 0): break
                response_data += data
            
            destination_server.close()
            client_socket.send(response_data)
            client_socket.close()

            # Cache the response
            with lock:
                self.cache[url] = [response_data, time.time()]
            self.cache_content_times += 1
            logg(1,f"Times we cached the data is {self.cache_content_times} .")


        except Exception as e:
            logg(0,f"[!] Error: {e} .")
            client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n" + b"Some Error Occurred.")
            client_socket.close()


    def run(self):
        """ To run our implemented proxy server. """

        # To invalidate the cache / uncaching independently any client or request
        cache_cleaner = threading.Thread(target=self.uncache)
        cache_cleaner.start()
        
        logg(0,f"\n-> Press Ctrl+C to exit. Though, it may take some time.")
        while(1):
            client_sock, host_ip_port = self.server.accept()    # Get a request from a client
            logg(0,f"\n[*] Received connection from {host_ip_port[0]}:{host_ip_port[1]} .")
            client_handler = threading.Thread(target=self.handle_client, args=(client_sock,))
            client_handler.start()


if __name__ == "__main__":
    proxy = ProxyServer("0.0.0.0",8080)     # Starts the proxy server onto the machine on which the code is run. 
    proxy.run()
