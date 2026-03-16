# Library for asynchronously executing functions.
# The ThreadPoolExecutor does the asynchronous execution with thread.
from concurrent.futures import ThreadPoolExecutor
# Library for working with sockets. We will use it to attempt to form a TCP connection.
import socket
# Library for working with time. We will use it to calculate how long the application took to run.
import time 
import ai_anomaly_integration

MAX_WORKERS = 100 

def generate_port_chunks(port_range):
  # Get the min and max port numbers from the port ranges
  port_range = port_range.split ('-')
  port_chunks = []
  # Divide the port range into chunks
  chunk_size = int((int(port_range[1]) - int(port_range[0])) / MAX_WORKERS)
  #Create a nested list of port chuncks to be handled by each worker
  for i in range(MAX_WORKERS):
    start = int(port_range[0]) + (chunk_size * i)
    end = start + chunk_size
    port_chunks.append((start, end))
  return port_chunks


def scan(ip_address, port_chunk):
  print(f"[~] Scanning {ip_address} from {port_chunk[0]} to {port_chunk[1]}.")
  open_ports = []
  # Loop throug the min and max port chunks
  for port in range(int(port_chunk[0]), int(port_chunk[1])):
    # Attempt a TCP IPv4 Connections to the provided port and IP address
    try:
      scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      scan_socket.settimeout(0.5)
      scan_socket.connect((ip_address, port))
      print(f"[!] Port {port} is open")
      open_ports.append((port, "Unknown Service"))
      scan_socket.close()
    # If the port is closed an exception will be thrown, capture it here
    except:
      pass
      
  return open_ports

def main(): 
  ip_address = '192.168.100.111'
  port_range = '0-10000' 

  # Divided port range into chunks
  port_chunks = generate_port_chunks(port_range)

  # Start the timer
  start_time = time.time()
  # Submit task to be excuted by the thread pool using map
  with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    results = executor.map(scan, [ip_address] * len(port_chunks), port_chunks)

  # Collect all open ports from the results
  open_ports_detected = []
  for chunk_ports in results:
    open_ports_detected.extend(chunk_ports)

  # Finish the timer
  end_time = time.time()
  print(f"Scanned {port_range.split('-')[1]} ports in {end_time - start_time:.2f} seconds.")

  if open_ports_detected:
    print(f"\nDiscovered {len(open_ports_detected)} open ports. Running AI analysis suite...")
    ai_anomaly_integration.analyze_scan_results(ip_address, open_ports_detected)
  else:
    print("\nNo open ports found. Skipping analysis.")

if __name__ == '__main__':
  main()
