import base64
import struct
import gssapi
from gssapi.raw.ext_dce import IOV, IOVBufferType
from gssapi.raw.ext_dce import wrap_iov_length, wrap_iov, unwrap_iov
from io import BytesIO

class MSKerberosCrypt(object):
  def __init__(self, hostname, service="WSMAN"):
    spn=service+"/"+hostname

    gss_spn = gssapi.Name(spn, name_type=gssapi.NameType.kerberos_principal)

    self._ctx = gssapi.SecurityContext(name=gss_spn)

    self.token = "".join(base64.encodestring(self._ctx.step()).decode().split("\n"))

  def get_token(self):
    return self.token

  def step(self, b64_token):
    raw_intoken = base64.decodestring(b64_token.encode())
    self._ctx.step(raw_intoken)

  def encrypt(self, data):
    #print(data)
    iov=IOV(IOVBufferType.header, (IOVBufferType.data, data), IOVBufferType.padding, std_layout=False)
    wrap_iov(self._ctx, iov)
    header_len=len(iov[0].value)
    if iov[2].value != None:
      pad_len=len(iov[2].value)
    else:
      pad_len = 0

    enc_block = b""
    enc_block = enc_block + struct.pack("I", header_len)
    enc_block = enc_block + iov[0].value
    enc_block = enc_block + iov[1].value
    if pad_len > 0:
      enc_block = enc_block + iov[2].value

    header = ["--Encrypted Boundary",
            "Content-Type: application/HTTP-Kerberos-session-encrypted",
            "OriginalContent: type=application/soap+xml;charset=UTF-8;Length="+str(len(data)+pad_len),
            "--Encrypted Boundary",
            "Content-Type: application/octet-stream"]
    header_txt = '\r\n'.join(header)

    out_buffer=BytesIO()
    out_buffer.write(header_txt.encode())
    out_buffer.write("\r\n".encode())
    out_buffer.write(enc_block)
    out_buffer.write("--Encrypted Boundary--\r\n".encode())

    return out_buffer.getvalue()

  def decrypt(self, encrypted_data):
    header_length, = struct.unpack("I", encrypted_data[0:4])

    encrypted_header = encrypted_data[4:header_length+4]
    encrypted_block = encrypted_data[header_length+4:]

    iov=IOV((IOVBufferType.header, False, encrypted_header), (IOVBufferType.data, encrypted_block), std_layout=False)

    unwrap_iov(self._ctx, iov)

    decrypted = iov[1].value

    #print(decrypted)
    return decrypted
