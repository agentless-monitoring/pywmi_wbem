import requests
from requests.cookies import extract_cookies_to_jar
from requests.compat import urlparse
from requests.structures import CaseInsensitiveDict
from requests import Session
import re
import StringIO
import logging
from mskerberos_crypt import MSKerberosCrypt
from gssapi.raw.misc import GSSError
from mskerberos_crypt import MSKerberosCrypt


class HTTPMSKerberosAdapter(requests.adapters.HTTPAdapter):
  krb_dict = {}

  def _establish_kerberos(self, url, stream=False, timeout=None, verify=True, cert=None, proxies=None):
    parsed = urlparse(url)
    crypt = None

    try:
      crypt = MSKerberosCrypt(parsed.hostname)
    except GSSError:
      crypt = MSKerberosCrypt(parsed.hostname, service="HTTP")

    headers = {}
    headers['Authorization'] = ("Kerberos " + crypt.get_token())
    headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
    headers["Connection"] = 'Keep-Alive'

    p = requests.PreparedRequest()
    p.prepare_method("POST")
    p.prepare_url(url, None)
    p.prepare_headers(headers)
    p.prepare_body("", None, None)
    auth = HTTPMSKerberosAuth()
    p.prepare_auth(auth, url)

    verify = requests.adapters.HTTPAdapter.send(self, p, stream, timeout, verify, cert, proxies)
    field = verify.headers['www-authenticate']
    kind, __, details = field.strip().partition(" ")
    if kind.lower() == "kerberos":
      crypt.step(details.strip())

    HTTPMSKerberosAdapter.krb_dict[url] = crypt

    verify.content
    verify.close()

    return verify

  def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):

    try:
      HTTPMSKerberosAdapter.krb_dict[request.url]
    except KeyError:
      response = self._establish_kerberos(request.url)
      # kerberos encryption is established
      # connection is lost after this call

    if HTTPMSKerberosAdapter.krb_dict.get(request.url) != None and HTTPMSKerberosAdapter.krb_dict[request.url] != None:
      method = request.method
      url = request.url
      headers = {}
      headers["Connection"] = 'Keep-Alive'
      headers[
        "Content-Type"] = "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""
      data = HTTPMSKerberosAdapter.krb_dict[request.url].encrypt(request.body)
      req = requests.Request(method, url, data=data, headers=headers).prepare()
      req.plain = request
      request = req

    return requests.adapters.HTTPAdapter.send(self, request, stream, timeout, verify, cert, proxies)

  def build_response(self, req, resp):
    response = requests.adapters.HTTPAdapter.build_response(self, req, resp)

    if response.headers.get("content-type") != None:
      if response.headers["content-type"].startswith("multipart/encrypted"):
        _, options_part = response.headers["content-type"].split(";", 1)

        options = CaseInsensitiveDict()

        for item in options_part.split(";"):
          key, value = item.split("=")
          if value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
            value = value.replace(b'\\\\', b'\\').replace(b'\\"', b'"')

          options[key] = value

        if options.get("protocol") is not None and options["protocol"] == "application/HTTP-Kerberos-session-encrypted":
          boundary = options["boundary"]
          encrypted_data = None
          re_multipart = r'(?:--' + boundary + r'(?:(?:\r\n)|(?:--(?:\r\n)*)))'
          for part in re.split(re_multipart, response.content):
            if part == '':
              continue
            (header_raw, data) = part.split('\r\n', 1)
            key, value = map(lambda x: x.strip(), header_raw.split(":"))
            if key.lower() == "content-type" and value == "application/HTTP-Kerberos-session-encrypted":
              _, orginaltype = map(lambda x: x.strip(), data.split(":"))
              original_values = CaseInsensitiveDict()
              for item in orginaltype.split(";"):
                subkey, subvalue = item.split("=")
                original_values[subkey] = subvalue

            if key.lower() == "content-type" and value == "application/octet-stream":
              encrypted_data = data

          con = self.get_connection(req.url, None)
          decrypted = HTTPMSKerberosAdapter.krb_dict[req.url].decrypt(encrypted_data)
          response.headers["Content-Type"] = original_values["type"] + "; charset=" + original_values["charset"]
          response.headers["Content-Length"] = len(decrypted)
          response.encoding = requests.utils.get_encoding_from_headers(response.headers)
          response.raw = StringIO.StringIO(decrypted)
          response._content_consumed = False
          response._content = False

    return response


class HTTPMSKerberosAuth(requests.auth.AuthBase):
  def handle_401(self, r, **kwargs):
    """Takes the given response and tries kerberos-auth, if needed."""

    if r.status_code != 401:
      return
    s_auth = r.headers.get('www-authenticate', '')

    if 'kerberos' in s_auth.lower():
      # Consume content and release the original connection
      # to allow our new request to reuse the same one.
      r.content
      r.close()

      url = r.request.url
      parsed = urlparse(r.request.url)

      prep = r.request.copy()

      # Reauthentication? - invalidate old kerberos context
      con = r.connection.get_connection(url, None)
      if krb_dict.get(url) != None:
        krb_dict[url] = None

      # Use the unencrypted message
      prep = r.request.plain.copy()

      extract_cookies_to_jar(prep._cookies, r.request, r.raw)
      prep.prepare_cookies(prep._cookies)

      crypt = None
      try:
        crypt = MSKerberosCrypt(parsed.hostname)
      except GSSError:
        crypt = MSKerberosCrypt(parsed.hostname, service="HTTP")

      headers = {}
      headers['Authorization'] = ("Kerberos " + crypt.get_token())

      headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
      headers["Connection"] = 'Keep-Alive'

      p = requests.PreparedRequest()
      p.prepare_method("POST")
      p.prepare_url(url, None)
      p.prepare_headers(headers)
      p.prepare_body("", None, None)
      p.prepare_auth(self, url)

      verify = r.connection.send(p, **kwargs)
      verify.history.append(r)
      field = verify.headers['www-authenticate']
      kind, __, details = field.strip().partition(" ")
      if kind.lower() == "kerberos":
        crypt.step(details.strip())

      krb_dict[url] = crypt

      verify.content
      verify.close()

      _r = verify.connection.send(prep, **kwargs)
      _r.history.append(verify)
      _r.request = prep

      return _r

    return r

  def __call__(self, r):
    r.register_hook('response', self.handle_401)

    return r
