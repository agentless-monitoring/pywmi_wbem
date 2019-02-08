import base64
import ctypes
import struct

libgssapi_krb5 = ctypes.cdll.LoadLibrary("libgssapi_krb5.so.2")

class gss_name_struct(ctypes.Structure): pass
gss_name_t = ctypes.POINTER(gss_name_struct)

class gss_ctx_id_struct(ctypes.Structure): pass
gss_ctx_id_t = ctypes.POINTER(gss_ctx_id_struct)

class gss_cred_id_struct(ctypes.Structure): pass
gss_cred_id_t = ctypes.POINTER(gss_cred_id_struct)

class gss_OID_set_desc_struct(ctypes.Structure): pass
gss_OID_set = ctypes.POINTER(gss_OID_set_desc_struct)


class gss_buffer_desc(ctypes.Structure):
  _fields_ = [('length', ctypes.c_size_t),
              ('value', ctypes.c_void_p)]

  def as_str(self):
    return ctypes.string_at(self.value, self.length)

gss_buffer_t = ctypes.POINTER(gss_buffer_desc)

OM_uint32 = ctypes.c_uint32
gss_cred_usage_t = ctypes.c_int

class gss_iov_buffer_desc(ctypes.Structure):
  _fields_ = [('iov_type', OM_uint32),
              ('iov_buffer', gss_buffer_desc)]

gss_iov_buffer_t = ctypes.POINTER(gss_iov_buffer_desc)

GSS_IOV_BUFFER_TYPE_DATA = 1
GSS_IOV_BUFFER_TYPE_HEADER = 2
GSS_IOV_BUFFER_TYPE_PADDING = 9
GSS_IOV_BUFFER_FLAG_ALLOCATE = 0x00010000

GSS_C_MUTUAL_FLAG = 2
GSS_C_SEQUENCE_FLAG = 8
GSS_C_CONF_FLAG = 16
GSS_C_INTEG_FLAG = 32

GSS_C_NO_OID = None
GSS_C_NT_HOSTBASED_SERVICE = ctypes.c_void_p.in_dll(libgssapi_krb5, "GSS_C_NT_HOSTBASED_SERVICE")
GSS_KRB5_NT_PRINCIPAL_NAME = ctypes.c_void_p.in_dll(libgssapi_krb5, "GSS_KRB5_NT_PRINCIPAL_NAME")
GSS_C_NT_USER_NAME = ctypes.c_void_p.in_dll(libgssapi_krb5, "GSS_C_NT_USER_NAME")
GSS_C_NO_CREDENTIAL=None
GSS_C_NO_CHANNEL_BINDINGS=None
GSS_C_INDEFINITE=OM_uint32(0xffffffff)

# OM_uint32 gss_display_status(OM_uint32 *minor_status, OM_uint32 status value, int status type, const gss_OID mech_type, OM_uint32 *message_context, gss_buffer_t status string);

gss_display_status = libgssapi_krb5.gss_display_status
gss_display_status.restype = OM_uint32
gss_display_status.argtypes = (ctypes.POINTER(OM_uint32),
                               OM_uint32,
                               ctypes.c_int,
                               ctypes.c_void_p,
                               ctypes.POINTER(OM_uint32),
                               gss_buffer_t)
                               

#  OM_uint32 gss_import_name(
#     OM_uint32 *    minor_status,
#     gss_buffer_t   input_name_buffer,  
#     gss_OID      input_name_type,
#     gss_name_t *   output_name);

gss_import_name = libgssapi_krb5.gss_import_name
gss_import_name.restype = OM_uint32
gss_import_name.argtypes = (ctypes.POINTER(OM_uint32),
                            gss_buffer_t,
                            ctypes.c_void_p,
                            ctypes.POINTER(gss_name_t))

#OM_uint32 gss_acquire_cred (
#OM_uint32         *minor_status,
#const gss_name_t  desired_name,
#OM_uint32         time_req,
#const gss_OID_set desired_mechs,
#gss_cred_usage_t  cred_usage,
#gss_cred_id_t     *output_cred_handle,
#gss_OID_set       *actual_mechs,
#OM_uint32         *time_rec)

gss_acquire_cred = libgssapi_krb5.gss_acquire_cred
gss_acquire_cred.restype = OM_uint32
gss_acquire_cred.argtypes = (ctypes.POINTER(OM_uint32),
                            gss_name_t,
                            OM_uint32,
                            gss_OID_set,
                            gss_cred_usage_t,
                            ctypes.POINTER(gss_cred_id_t),
                            ctypes.POINTER(gss_OID_set),
                            ctypes.POINTER(OM_uint32))

# gss_init_sec_context(
#    OM_uint32 *,        /* minor_status */
#    gss_cred_id_t,      /* claimant_cred_handle */
#    gss_ctx_id_t *,     /* context_handle */
#    gss_name_t,         /* target_name */
#    gss_OID,            /* mech_type (used to be const) */
#    OM_uint32,          /* req_flags */
#    OM_uint32,          /* time_req */
#    gss_channel_bindings_t,     /* input_chan_bindings */
#    gss_buffer_t,       /* input_token */
#    gss_OID *,          /* actual_mech_type */
#    gss_buffer_t,       /* output_token */
#    OM_uint32 *,        /* ret_flags */
#    OM_uint32 *);       /* time_rec */ 

gss_init_sec_context = libgssapi_krb5.gss_init_sec_context
gss_init_sec_context.restype = OM_uint32
gss_init_sec_context.argtypes = (ctypes.POINTER(OM_uint32),
                                 gss_cred_id_t,
                                 ctypes.POINTER(gss_ctx_id_t),
                                 gss_name_t,
                                 ctypes.c_void_p,
                                 OM_uint32,
                                 OM_uint32,
                                 ctypes.c_void_p,
                                 gss_buffer_t,
                                 ctypes.c_void_p,
                                 gss_buffer_t,
                                 ctypes.POINTER(OM_uint32),
                                 ctypes.POINTER(OM_uint32))

# OM_uint32 gss_wrap_iov(OM_uint32 *minor_status,
#                        gss_ctx_id_t context_handle,
#                        int conf_req_flag, gss_qop_t qop_req,
#                        int *conf_state,
#                        gss_iov_buffer_desc *iov, int iov_count);

gss_wrap_iov = libgssapi_krb5.gss_wrap_iov
gss_wrap_iov.restype = OM_uint32
gss_wrap_iov.argtypes = (ctypes.POINTER(OM_uint32),
                         gss_ctx_id_t,
                         ctypes.c_int,
                         ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_int),
                         gss_iov_buffer_t,
                         ctypes.c_int)

# OM_uint32 gss_wrap_iov_length(OM_uint32 *minor_status,
#                               gss_ctx_id_t context_handle,
#                               int conf_req_flag,
#                               gss_qop_t qop_req, int *conf_state,
#                               gss_iov_buffer_desc *iov,
#                               int iov_count);

gss_wrap_iov_length = libgssapi_krb5.gss_wrap_iov_length
gss_wrap_iov_length.restype = OM_uint32
gss_wrap_iov_length.argtypes = (ctypes.POINTER(OM_uint32),
                                gss_ctx_id_t,
                                ctypes.c_int,
                                ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_int),
                                gss_iov_buffer_t,
                                ctypes.c_int)

# OM_uint32 gss_unwrap_iov(OM_uint32 *minor_status,
#                          gss_ctx_id_t context_handle,
#                          int *conf_state, gss_qop_t *qop_state,
#                          gss_iov_buffer_desc *iov, int iov_count);

gss_unwrap_iov = libgssapi_krb5.gss_unwrap_iov
gss_unwrap_iov.restype = OM_uint32
gss_unwrap_iov.argtypes = (ctypes.POINTER(OM_uint32),
                           gss_ctx_id_t,
                           ctypes.POINTER(ctypes.c_int),
                           ctypes.c_void_p,
                           gss_iov_buffer_t,
                           ctypes.c_int)

def has_gss_error(x):
  GSS_C_CALLING_ERROR_OFFSET=24
  GSS_C_ROUTINE_ERROR_OFFSET=16
  GSS_C_CALLING_ERROR_MASK=0377
  GSS_C_ROUTINE_ERROR_MASK=0377

  return ((x) & ((GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET) | (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))) != 0

class GSSError(Exception):
  def __init__(self, major, minor):
    self.__major = major
    self.__minor = minor

  def __get_error_txt(self):
    GSS_C_GSS_CODE = 1
    GSS_C_MECH_CODE = 2

    major_string = gss_buffer_desc()
    minor_string = gss_buffer_desc()
    display_ctx = OM_uint32(0)
    display_major = OM_uint32()
    display_minor = OM_uint32()

    while True:
      display_major = gss_display_status(ctypes.byref(display_minor), self.__major, GSS_C_GSS_CODE, GSS_C_NO_OID, ctypes.byref(display_ctx), ctypes.byref(major_string))

      if has_gss_error(display_major):
        break

      display_major = gss_display_status(ctypes.byref(display_minor), self.__minor, GSS_C_MECH_CODE, GSS_C_NO_OID, ctypes.byref(display_ctx), ctypes.byref(minor_string))
      #print("%s: %s" % (major_string.as_str(), minor_string.as_str()))

      if has_gss_error(display_major) == True or display_ctx.value == 0:
        break

    return "%s: %s" % (major_string.as_str(), minor_string.as_str())

  def __str__(self):
    return self.__get_error_txt()

class MSKerberosCrypt(object):
  def __init__(self, hostname, service="WSMAN"):
    spn=service+"/"+hostname

    spn_buf=gss_buffer_desc()
    spn_buf.value=ctypes.cast(ctypes.create_string_buffer(spn), ctypes.c_void_p)
    spn_buf.length=len(spn)

    self.name = gss_name_t()

    major = OM_uint32()
    minor = OM_uint32()

    major = gss_import_name(ctypes.byref(minor), spn_buf, GSS_KRB5_NT_PRINCIPAL_NAME, ctypes.byref(self.name))

    if has_gss_error(major):
      raise GSSError(major, minor)

    self.context = gss_ctx_id_t()
    in_token = gss_buffer_desc()
    out_token = gss_buffer_desc()
    flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG

    major = gss_init_sec_context(ctypes.byref(minor), GSS_C_NO_CREDENTIAL, ctypes.byref(self.context), self.name,
                                 GSS_C_NO_OID, flags, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, ctypes.byref(in_token),
                                 None, ctypes.byref(out_token), None, None)

    if has_gss_error(major):
      raise GSSError(major, minor)

    self.token = "".join(base64.encodestring(out_token.as_str()).split("\n"))

  def get_token(self):
    return self.token

  def step(self, b64_token):
    major = OM_uint32()
    minor = OM_uint32()

    in_token = gss_buffer_desc()
    out_token = gss_buffer_desc()

    raw_intoken = base64.decodestring(b64_token)
    in_token.value=ctypes.cast(ctypes.create_string_buffer(raw_intoken), ctypes.c_void_p)
    in_token.length=len(raw_intoken)
    
    flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
    major = gss_init_sec_context(ctypes.byref(minor), GSS_C_NO_CREDENTIAL, ctypes.byref(self.context),
                                 self.name, GSS_C_NO_OID, flags, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 ctypes.byref(in_token), None, ctypes.byref(out_token), None, None)

    if has_gss_error(major):
      raise GSSError(major, minor)

  def encrypt(self, data):
    #print(data)
    major = OM_uint32()
    minor = OM_uint32()

    iov = (gss_iov_buffer_desc * 3)()

    iov[0].iov_type = GSS_IOV_BUFFER_TYPE_HEADER
    iov[1].iov_type = GSS_IOV_BUFFER_TYPE_DATA
    iov[1].iov_buffer.value = ctypes.cast(ctypes.create_string_buffer(data), ctypes.c_void_p)
    iov[1].iov_buffer.length = len(data)
    iov[2].iov_type = GSS_IOV_BUFFER_TYPE_PADDING

    major = gss_wrap_iov_length(ctypes.byref(minor), self.context, 1, 0, None, iov, 3)

    if has_gss_error(major):
      raise GSSError(major, minor)

    header_buf=ctypes.create_string_buffer(iov[0].iov_buffer.length)
    padding_buf=ctypes.create_string_buffer(iov[2].iov_buffer.length)

    iov[0].iov_buffer.value = ctypes.cast(header_buf, ctypes.c_void_p)
    iov[2].iov_buffer.value = ctypes.cast(padding_buf, ctypes.c_void_p)

    major = gss_wrap_iov(ctypes.byref(minor), self.context, 1, 0, None, iov, 3)

    if has_gss_error(major):
      raise GSSError(major, minor)

    enc_block = b""
    enc_block = enc_block + struct.pack("I", iov[0].iov_buffer.length)
    enc_block = enc_block + header_buf.raw
    enc_block = enc_block + iov[1].iov_buffer.as_str()
    pad_len = iov[2].iov_buffer.length
    if pad_len > 0:
      enc_block = enc_block + padding_buf.raw

    body = ["--Encrypted Boundary",
            "Content-Type: application/HTTP-Kerberos-session-encrypted",
            "OriginalContent: type=application/soap+xml;charset=UTF-8;Length="+str(len(data)+pad_len),
            "--Encrypted Boundary",
            "Content-Type: application/octet-stream",
            "%s--Encrypted Boundary--"
            "\r\n"]
    body_txt = '\r\n'.join(body)

    return body_txt % (enc_block)

  def decrypt(self, encrypted_data):
    major = OM_uint32()
    minor = OM_uint32()

    header_length, = struct.unpack("I", encrypted_data[0:4])

    encrypted_header = encrypted_data[4:header_length+4]
    encrypted_block = encrypted_data[header_length+4:]

    conf_state = ctypes.c_int()

    iov = (gss_iov_buffer_desc * 3)()

    iov[0].iov_type = GSS_IOV_BUFFER_TYPE_HEADER
    iov[0].iov_buffer.value = ctypes.cast(ctypes.create_string_buffer(encrypted_header), ctypes.c_void_p)
    iov[0].iov_buffer.length = len(encrypted_header)
    
    iov[1].iov_type = GSS_IOV_BUFFER_TYPE_DATA
    iov[1].iov_buffer.value = ctypes.cast(ctypes.create_string_buffer(encrypted_block), ctypes.c_void_p)
    iov[1].iov_buffer.length = len(encrypted_block)

    iov[2].iov_type = GSS_IOV_BUFFER_TYPE_DATA

    major = gss_unwrap_iov(ctypes.byref(minor), self.context, ctypes.byref(conf_state), 0, iov, 3)

    if has_gss_error(major):
      raise GSSError(major, minor)

    decrypted = iov[1].iov_buffer.as_str()

    #print(decrypted)
    return decrypted
