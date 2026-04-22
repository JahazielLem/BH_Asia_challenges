import struct
import string

def hexdump(data: bytes, width: int = 16) -> str:
  lines = []

  for offset in range(0, len(data), width):
    chunk = data[offset:offset + width]

    hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
    hex_bytes = hex_bytes.ljust(width * 3)

    ascii_bytes = ''.join(chr(b) if chr(b) in string.printable and b >= 0x20 else '.' for b in chunk)

    lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")

  return "\n".join(lines)

def hexdump_split(data: bytes, header_len=6):
  header = data[:header_len]
  payload = data[header_len:]

  print("\033[33m[HEADER]\033[0m")
  print(hexdump(header))

  print("\033[36m[PAYLOAD]\033[0m")
  print(hexdump(payload))


class SpacePacketProtocolDecoder:
  def __init__(self, raw_frame: bytes = None):
    self.raw_frame = raw_frame
    self.packet_id = 0
    self.sequence = 0
    self.length = 0
    self.version = 0
    self.f_type = 0
    self.sec_header = 0
    self.apid = 0
    self.seq_flags = 0
    self.seq_count = 0
    self.seq_flag_str = "Unknown"
    self.payload = None


  def decode(self) -> bool:
    if self.raw_frame is None:
      return False
    
    if len(self.raw_frame) < 6:
      print("Space Packet to short")
      return False
    
    print(self.raw_frame.hex())
    (self.packet_id, self.sequence, self.length) = struct.unpack_from(">HHH", self.raw_frame)

    self.version    = (self.packet_id >> 13) & 0x7
    self.f_type     = (self.packet_id >> 12) & 0x1
    self.sec_header = (self.packet_id >> 11) & 0x1
    self.apid       = self.packet_id & 0x7FF

    self.seq_flags = (self.sequence >> 14) & 0x3
    self.seq_count = self.sequence & 0x3FFF

    self.payload = self.raw_frame[6:6 + (self.length + 1)]

    self.seq_flag_str = {
        0b00: "Continuation",
        0b01: "Start",
        0b10: "End",
        0b11: "Unsegmented"
    }.get(self.seq_flags, "Unknown")
    
    return True
  
  def print_details(self):
    print(f"\n=========== Space Packet ===========")
    print(f"Version:            {self.version}")
    print(f"Type:               {self.f_type:02X} ({'TM' if self.f_type == 0x00 else 'TC'})")
    print(f"Secondary Header:   {self.sec_header}")
    print(f"APID:               0x{self.apid:04X}")
    print(f"Sequence Flags:     0x{self.seq_flags:X} ({self.seq_flag_str})")
    print(f"Sequence Count:     {self.seq_count}")
    print(f"Data Length:        {self.length}")
    hexdump_split(self.raw_frame)
  
  def print_summary(self):
    print(
        f"\033[36m[TM - SPP]\033[0m "
        f"APID=0x{self.apid:03X} "
        f"SEQ={self.seq_count} SEQ_FLAG={self.seq_flag_str} "
        f"LEN={self.length} "
        f"TYPE={'TM' if self.f_type == 0 else 'TC'} "
        f"FLAGS={self.seq_flags}")

def read_binary(filename):
  with open(filename, "rb") as f:
    data = f.readline()
    spp = SpacePacketProtocolDecoder(data)
    
    if spp.decode():
      spp.print_details()
      print("\n")
      
      
read_binary(filename="challenge6.bin")