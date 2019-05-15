import sys
import os.path
  
def read_bytes(filename, offset=0, chunksize=8192):
  # This method returns the bytes of a provided file ##
  try:
    with open(filename, "rb") as f:
      f.seek(offset)
      while True:
        chunk = f.read(chunksize)
        if chunk:
          for b in chunk:
            yield b
        else:
          break
  except IOError:
    print ""
    print "Error - The file provided does not exist"
    print ""
    sys.exit(0)
        
def is_character_printable(s):
  ## This method returns true if a byte is a printable ascii character ##
  return all((ord(c) < 127) and (ord(c) >= 32) for c in s)
  
def validate_byte_as_printable(byte):
  ## Check if byte is a printable ascii character. If not replace with a '.' character ##
  if is_character_printable(byte):
    return byte
  else:
    return '.'
  
## main ##

def read_hex_dump(file_path, offset=0):
  result = '<table class="table table-sm table-bordered">'
  memory_address = 0
  ascii_string = ""
  count = 0

  for byte in read_bytes(file_path, offset):
    ascii_string = ascii_string + validate_byte_as_printable(byte)
    if memory_address%16 == 0:
      count = count + 1
      if count == 150:
        break
      result = result + ('<tr><td>' + format(memory_address, '06X') + '</td><td>' + byte.encode('hex') + ' ')
    elif memory_address%16 == 15:
      result = result + (byte.encode('hex') + '</td><td>' + ascii_string + '</td></tr>')
      ascii_string = ""
    else:
      result = result + (byte.encode('hex') + ' ')
    memory_address = memory_address + 1
  return result + '</table>'