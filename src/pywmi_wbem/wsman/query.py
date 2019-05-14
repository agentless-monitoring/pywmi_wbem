from lxml import etree as ET
from lxml import objectify  
import uuid
import requests
from pywmi_wbem.mskerberos.auth import HTTPMSKerberosAuth, HTTPMSKerberosAdapter
from requests.auth import HTTPBasicAuth

from dateutil.parser import parse as date_parse

try:
  import http.client as http_client
except ImportError:
  # Python 2
  import httplib as http_client

import base64

#http_client.HTTPConnection.debuglevel=9

class States():
  INITIAL = {"name" : "Initial", "action": "Initial"}
  FAULT = {"name" : "Fault", "action": "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault"}
  #Remote shell states
  CREATE_SHELL = {"name" : "Create", "action": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"}
  CREATE_RESPONSE = {"name" : "CreateResponse", "action": "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"}
  COMMAND_RESPONSE = {"name" : "CommandResponse", "action": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse"}
  FETCH_OUTPUT = {"name" : "FetchOutput", "action": "Fetch"}
  RECEIVE_RESPONSE = {"name" : "ReceiveResponse", "action": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"}
  RECEIVE_DONE = {"name" : "RECEIVE_DONE", "action": "ReceiveDone"}
  SIGNAL_RESPONSE = {"name" : "SIGNAL_RESPONSE", "action": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse"}
  DELETE_SHELL = {"name" : "DeleteShell", "action": "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"}
  #WQL States
  ENUMERATE_RESPONSE = {"name" : "EnumareResponse", "action": "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"}
  PULL = {"name" : "Pull", "action": "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"}
  PULL_RESPONSE = {"name" : "PullResponse", "action": "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse"}
  
class WSManFault(Exception):
  pass
  
class WSManFault_NoShellOutput(Exception):
  pass

class WSMAN_Constants:
  CONTENT_TYPE = "application/soap+xml"
  SOAP_ENVELOPE = "http://www.w3.org/2003/05/soap-envelope"
  WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
  TRANSFER = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
  WSMAN_1 = "http://schemas.microsoft.com/wbem/wsman/1"  
  WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  LANG = "{http://www.w3.org/XML/1998/namespace}lang"
  WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"   
  ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
  XSI = "http://www.w3.org/2001/XMLSchema-instance"
  WMI = "%s/wmi" % (WSMAN_1)
  WSMAN_FAULT = "%s/wsmanfault"  % (WSMAN_1)
  SHELL = "%s/windows/shell" % (WSMAN_1)
  SIGNAL = "%s/signal/terminate" % (SHELL) 
  WQL = "%s/WQL"  % (WSMAN_1)
  ACTION_TAG = "{%s}Action" % (WSA)
  TO_TAG = "{%s}To" % (WSA)
  MESSAGE_ID_TAG = "{%s}MessageID" % (WSA)
  ADRESS_TAG = "{%s}Address" % (WSA)
  REPLY_TO_TAG = "{%s}ReplyTo" % (WSA)
  ACTION_PATH = "Envelope.Header.%s" % (ACTION_TAG)
  MUST_UNDERSTAND = "{%s}mustUnderstand" % (SOAP_ENVELOPE)
  ENVELOPE_TAG = "{%s}Envelope" % (SOAP_ENVELOPE)
  HEADER_TAG = "{%s}Header" % (SOAP_ENVELOPE)
  BODY_TAG = "{%s}Body" % (SOAP_ENVELOPE)
  CREATE_ACTION = "%s/Create" % (TRANSFER)
  DELETE_ACTION = "%s/Delete" % (TRANSFER)
  RESOURCE_URI_TAG = "{%s}ResourceURI" % (WSMAN) 
  LOCALE_TAG = "{%s}Locale" % (WSMAN)     
  OPERATION_TIMEOUT_TAG = "{%s}OperationTimeout" % (WSMAN)
  MAX_ENVELOPE_SIZE_TAG = "{%s}MaxEnvelopeSize"  % (WSMAN)
  OPTION_SET_TAG = "{%s}OptionSet"  % (WSMAN)
  OPTION_TAG = "{%s}Option" % (WSMAN)
  SELECTOR_TAG = "{%s}Selector" % (WSMAN)
  SELECTOR_SET_TAG = "{%s}SelectorSet" % (WSMAN)
  SELECTOR_PATH = "Envelope.Body.{%s}ResourceCreated.{%s}ReferenceParameters.%s.%s" % (TRANSFER, WSA, SELECTOR_SET_TAG, SELECTOR_TAG)
  FILTER_TAG = "{%s}Filter" % (WSMAN)
  DIALECT_TAG = "{%s}Dialect" % (WSMAN)  
  CMD = "%s/cmd" % (SHELL)
  SHELL_TAG = "{%s}Shell" % (SHELL) 
  COMMAND_ID = "Envelope.Body.{%s}CommandResponse.{%s}CommandId" % (SHELL, SHELL)
  RECEIVE_TAG = "{%s}Receive" % (SHELL)
  SIGNAL_TAG = "{%s}Signal" % (SHELL)
  CODE_TAG = "{%s}Code" % (SHELL)
  DESIRED_STREAM_TAG = "{%s}DesiredStream" % (SHELL)
  RECEIVE_ACTION = "%s/Receive" % (SHELL)
  RECEIVE_RESPONSE = "Envelope.Body.{%s}ReceiveResponse" % (SHELL)
  STREAM = "%s.{%s}Stream" % (RECEIVE_RESPONSE, SHELL)
  COMMAND_STATE = "%s.{%s}CommandState" % (RECEIVE_RESPONSE, SHELL)  
  COMMAND_ACTION = "%s/Command" % (SHELL)
  SIGNAL_ACTION = "%s/Signal" % (SHELL)
  COMMAND_TAG = "{%s}Command" % (SHELL)
  ARGUMENTS_TAG = "{%s}Arguments" % (SHELL)
  COMMANDLINE_TAG = "{%s}CommandLine" % (SHELL) 
  PULL_RESPONSE_TAG = "{%s}PullResponse" % (WSEN)
  PULL_TAG = "{%s}Pull" % (WSEN)
  ENUMERATION_CONTEXT_TAG = "{%s}EnumerationContext" % (WSEN)
  MAX_ELEMENTS_TAG = "{%s}MaxElements" % (WSEN)
  PULL = "%s/Pull" % (WSEN)
  ENUMERATE_RESPONSE_TAG = "{%s}EnumerateResponse" % (WSEN)
  ENUMERATE_TAG = "{%s}Enumerate" % (WSEN)
  ENUMERATE = "%s/Enumerate" % (WSEN)

class WSMan():  
  
  def __init__(self, server, port = None, tls=False, username=None, password=None, timeout=60):
    self.adapter = None
    self.tls=tls
    self.username=username
    self.server = server	
	
    if self.tls is True:
      if port is None:
	      port = 5986
      protocol = "https"
    else:
      if port is None:
	      port = 5985
      protocol = "http"
     
    self.session = requests.Session()

    if self.username != None and password != None:
      self.auth=HTTPBasicAuth(self.username, password)
    else:
      self.auth=HTTPMSKerberosAuth()
      if self.adapter is None:
	      self.adapter = HTTPMSKerberosAdapter()
      self.session.mount('%s://' % (protocol), self.adapter)

    self.host = "%s://%s:%i/wsman" % (protocol, self.server, port)	   
    self.headers = {"Content-Type" : "%s; charset=UTF-8" % (WSMAN_Constants.CONTENT_TYPE)}
    self.timeout = timeout
    self.resource_uri = ""
	
    #state specific
    self.current_state = States.INITIAL
    self.current_action = ""	
    
    #remote shell
    self.script = ""
    self.sub_header = []
    self.output = {}
    self.commandId = None
    self.command = {'text': "",  'arguments' : []}
    self.maxenvelope = "512000"
    #only for powershell
    self.operationtimeout = "PT%s.000S" % (timeout)
    
        
  def generate_message(self, action, to, resource_uri, uuid, sub_body=None, sub_header=None, nsmap=None):
    if nsmap == None:
      nsmap={"soap-envelope": WSMAN_Constants.SOAP_ENVELOPE,
	     "wsa": WSMAN_Constants.WSA,
	     "wsman": WSMAN_Constants.WSMAN,
	     "wsen": WSMAN_Constants.WSEN        
      }
	  
    root = ET.Element(WSMAN_Constants.ENVELOPE_TAG, nsmap=nsmap)
    header = ET.SubElement(root, WSMAN_Constants.HEADER_TAG)

    if sub_header != None:
      for sub_header_element in sub_header:
        header.append(sub_header_element)

    body = ET.SubElement(root, WSMAN_Constants.BODY_TAG)

    # Header
    action_element=ET.SubElement(header, WSMAN_Constants.ACTION_TAG)
    action_element.attrib[WSMAN_Constants.MUST_UNDERSTAND]="true"
    action_element.text=action

    to_element=ET.SubElement(header, WSMAN_Constants.TO_TAG)
    to_element.attrib[WSMAN_Constants.MUST_UNDERSTAND]="true"
    to_element.text=to

    resource_uri_element=ET.SubElement(header, WSMAN_Constants.RESOURCE_URI_TAG)
    resource_uri_element.attrib[WSMAN_Constants.MUST_UNDERSTAND]="true"
    resource_uri_element.text=resource_uri

    message_id=ET.SubElement(header, WSMAN_Constants.MESSAGE_ID_TAG)
    message_id.attrib[WSMAN_Constants.MUST_UNDERSTAND]="true"
    message_id.text="uuid:%s" % (uuid)

    reply_to=ET.SubElement(header, WSMAN_Constants.REPLY_TO_TAG)
    address=ET.SubElement(reply_to, WSMAN_Constants.ADRESS_TAG)
    address.text= WSMAN_Constants.ANONYMOUS
 
    if sub_body != None:
      body.append(sub_body)  
   
    return root

  #not fully implemented
  def generate_invoke_action_query(self, to, uuid, obj, method, selectorset, params=None, namespace="root/cimv2"):
    resource_uri="http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/%s" % (namespace, obj)
    input_element=ET.Element("{%s}%s_INPUT" % (resource_uri, method))

    if params != None:
      for i in params:
	key=i
	value=params[key]
	param_element=ET.SubElement(input_element, "{%s}%s" % (resource_uri, key))
	param_element.text=str(value)

    selectorset_element=ET.Element("{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet")
    for i in selectorset:
      key=i
      value=selectorset[key]
      selector_element=ET.SubElement(selectorset_element, "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector")
      selector_element.attrib["Name"]=key
      selector_element.text=str(value)

    root=self.generate_message(resource_uri+"/"+method, to, resource_uri, uuid, input_element, sub_header=selectorset_element)

    return root

  def wql_send_pull_request(self):
    self.message_body_type = WSMAN_Constants.PULL_RESPONSE_TAG
    pull_element=ET.Element(WSMAN_Constants.PULL_TAG)
    context_el=ET.SubElement(pull_element, WSMAN_Constants.ENUMERATION_CONTEXT_TAG)
    context_el.text= self.enum_context

    max_elements=20
    if max_elements > 0:
      max_elements_el=ET.SubElement(pull_element, WSMAN_Constants.MAX_ELEMENTS_TAG)
      max_elements_el.text=str(max_elements)

    resource_uri="%s/%s/*" % (WSMAN_Constants.WMI, self.namespace)

    root=self.generate_message(WSMAN_Constants.PULL, self.host, resource_uri, uuid.uuid4(), pull_element)
    msg=ET.tostring(root)
    r=self.session.post(self.host, auth=self.auth, data=msg, headers=self.headers, timeout=self.timeout)
    self.check_response(r)
	
  #called directly by wql nagios checks (load,memory,disc)
  def wql_group_result(self, output, group_key):  
    ret={}
    if isinstance(output, dict):
      if output.get(group_key):  
	ret[output[group_key]]=output  
	del output[group_key]  
	return ret
    else:
      for i in output:  
	ret[i[group_key]]=i  
	del ret[i[group_key]][group_key]  
    
    return ret
   
  def search_wql(self, wql, namespace="root/cimv2"):
    self.values = []
    self.namespace = namespace
    self.wql = wql
    self.enum_context = None	
    self.wql_send_enumerate()
    
    if len(self.values) == 1:
       return self.values[0]
    else: 
      return self.values

  def check_response(self, r):	
    if 'Content-Type' not in r.headers:
      r.raise_for_status()
    if r.headers['Content-Type'].startswith(WSMAN_Constants.CONTENT_TYPE) is False:
      raise TypeError(r.content)
    answer=objectify.fromstring(r.content)
    action_path=objectify.ObjectPath(WSMAN_Constants.ACTION_PATH)
    action_el=action_path.find(answer)
    self.current_action = action_el.text
    self.response = r
    self.next_state()
  
  def next_state(self):
    # Only look for faults if we already sent something, the initial state has no response
    if hasattr(self, "response"):
      # A Fault can happen on any action - look for Fault element not for action
      xml=objectify.fromstring(self.response.content)
      is_fault = objectify.ObjectPath("Envelope.Body.Fault")
      if is_fault.hasattr(xml):
        self.current_state = States.FAULT
        self.handle_fault()
  
    #remote shell states
    if self.current_action == States.CREATE_SHELL['action']:
      self.current_state = States.CREATE_SHELL
      self.create_shell()	
    elif self.current_action == States.CREATE_RESPONSE['action']:
      self.current_state = States.CREATE_RESPONSE
      self.shell_execute_command()
    elif self.current_action == States.COMMAND_RESPONSE['action']:
      self.current_state = States.COMMAND_RESPONSE
      self.shell_fetch_output(0)
    elif not self.current_state == States.RECEIVE_RESPONSE and self.current_action == States.RECEIVE_RESPONSE['action']:
      self.current_state = States.RECEIVE_RESPONSE
      self.parse_shell_output()
    elif self.current_action == States.RECEIVE_DONE['action']:
      self.current_state = States.RECEIVE_DONE
      self.shell_terminate_signal()
    elif self.current_action == States.SIGNAL_RESPONSE['action']:  
      self.current_state = States.SIGNAL_RESPONSE
      self.delete_shell()
    elif self.current_action == States.FETCH_OUTPUT['action']:
      self.current_state = States.FETCH_OUTPUT
      self.shell_fetch_output(0)
	  
    #wql states	  
    elif self.current_action == States.ENUMERATE_RESPONSE['action']:
      self.current_state = States.ENUMERATE_RESPONSE
      self.wql_check_enum_context()
    elif self.current_action == States.PULL['action']:
      self.current_state = States.PULL
      self.wql_send_pull_request()
    elif self.current_action == States.PULL_RESPONSE['action']:
      self.current_state = States.PULL_RESPONSE
      self.wql_parse_pull_response()
	  
  def wql_send_enumerate(self):
    #the message body type indicates in which kind of message the enum_context can be found. see wql_check_enum_context
    self.message_body_type = WSMAN_Constants.ENUMERATE_RESPONSE_TAG
    enumerate_element=ET.Element(WSMAN_Constants.ENUMERATE_TAG)
    filter_element=ET.SubElement(enumerate_element, WSMAN_Constants.FILTER_TAG)
    filter_element.attrib[WSMAN_Constants.DIALECT_TAG]=WSMAN_Constants.WQL
    filter_element.text= self.wql
    resource_uri="%s/%s/*" % (WSMAN_Constants.WMI, self.namespace)
    enumerate = WSMAN_Constants.ENUMERATE
    root=self.generate_message(enumerate, self.host, resource_uri, uuid.uuid4(), enumerate_element)
    msg=ET.tostring(root)
    r=self.session.post(self.host, auth=self.auth, data=msg, headers=self.headers, timeout=self.timeout)
    self.check_response(r)  
	  
  def wql_parse_pull_response(self):   
    
    item_fragment_path=objectify.ObjectPath("Envelope.Body.{%s}PullResponse.Items.{%s}XmlFragment" % (WSMAN_Constants.WSEN, WSMAN_Constants.WSMAN ))
    item_full_path=objectify.ObjectPath("Envelope.Body.{%s}PullResponse.Items" % (WSMAN_Constants.WSEN))
    xml = objectify.fromstring(self.response.content)
    
    items = None	
    try:
	  items=item_fragment_path.find(xml)
    except AttributeError:
	  try:
	    items=item_full_path.find(xml)
	  except AttributeError:
	    pass
        
    for item in items:
      entry={}
      for i in item.iterchildren():
        if hasattr(i, "countchildren") and i.countchildren() == 1:
          for subchild in i.iterchildren():
            if subchild.tag == "Datetime":
              entry[i.tag]=date_parse(str(subchild))
        else:              
          entry[i.tag]=i
      
      if entry:
        self.values.append(entry)           
	
    self.wql_check_enum_context()    
	  	
  def wql_check_enum_context(self):
    xml = objectify.fromstring(self.response.content)
	
    try:
      enum_context = xml.Body[self.message_body_type].EnumerationContext.text
      if self.enum_context != enum_context:
        self.enum_context = enum_context
        self.current_action = States.PULL["action"]
        self.next_state()
    except AttributeError:
      pass	 	
	
  def handle_fault(self):    
    xml=objectify.fromstring(self.response.content)    	
    is_fault = objectify.ObjectPath("Envelope.Body.Fault")
    if is_fault.hasattr(xml):		  
      fault=is_fault.find(xml)      
      fault_text=fault.Reason.Text.text
      has_wsman_details = objectify.ObjectPath(".Detail.{%s}WSManFault" % (WSMAN_Constants.WSMAN_FAULT))
      if has_wsman_details.hasattr(fault):
        details=has_wsman_details.find(fault)
        if details.attrib.__contains__("Code") and details.attrib["Code"] == "2150858793":
          #retry  
          self.shell_fetch_output(0)      
        else:
          detail_text=details.Message.text
          if detail_text != None:
            raise WSManFault(detail_text.encode('utf-8'))
	
  def run_powershell_script(self, script=""):   
        
    self.command["text"] = "powershell"
    self.command["arguments"].append("-encodedcommand")
    self.command["arguments"].append(base64.b64encode(script.encode('utf_16_le')).decode('ascii'))
    self.current_action = WSMAN_Constants.CREATE_ACTION
    self.next_state() 	 
    return self.output   	
	
  def get_shell_sub_header(self):
    #sub_header can be set (e.g. shell id is only parsed once and then set in the sub_header)
    if self.sub_header:
      return self.sub_header

    locale = ET.Element(WSMAN_Constants.LOCALE_TAG)
    locale.attrib[WSMAN_Constants.MUST_UNDERSTAND]="false"
    locale.attrib[WSMAN_Constants.LANG]="en-US"
    
    operationtimeout = ET.Element(WSMAN_Constants.OPERATION_TIMEOUT_TAG)
    operationtimeout.text = self.operationtimeout
    
    maxenvelope = ET.Element(WSMAN_Constants.MAX_ENVELOPE_SIZE_TAG)
    maxenvelope.attrib[WSMAN_Constants.MUST_UNDERSTAND]="true"
    maxenvelope.text= self.maxenvelope	
	
    option_set=ET.Element(WSMAN_Constants.OPTION_SET_TAG , nsmap={"xsi": WSMAN_Constants.XSI})
    option1 = ET.SubElement(option_set, WSMAN_Constants.OPTION_TAG)
    option1 .attrib["Name"]="WINRS_CONSOLEMODE_STDIN"
    option1 .text ="TRUE"   
    option2 = ET.SubElement(option_set, WSMAN_Constants.OPTION_TAG)
    option2 .attrib["Name"]="WINRS_SKIP_CMD_SHELL"
    option2 .text ="FALSE"
    option3 = ET.SubElement(option_set, WSMAN_Constants.OPTION_TAG)
    option3.attrib["Name"]="WINRS_NOPROFILE"
    option3.text = "TRUE"
    option4 = ET.SubElement(option_set, WSMAN_Constants.OPTION_TAG)
    option4. attrib["Name"]="WINRS_CODEPAGE"
    option4.text = "65001" 
    return [option_set, operationtimeout, locale, maxenvelope]
  	
  def create_shell(self):
    sub_body=ET.Element(WSMAN_Constants.SHELL_TAG, nsmap = {"rsp": WSMAN_Constants.SHELL})
    action = WSMAN_Constants.CREATE_ACTION
    root=self.generate_message(action, self.host, WSMAN_Constants.CMD , uuid.uuid4(), sub_body = sub_body, sub_header = self.get_shell_sub_header())
    msg=ET.tostring(root)   
    create_shell_response = self.session.post(self.host, auth=self.auth, data=msg, headers=self.headers, timeout=self.timeout)
    self.check_response(create_shell_response) 
	
  def shell_execute_command(self): 
     
    sub_header = self.get_shell_sub_header() 
    # set shell id 
    selector_set=ET.Element(WSMAN_Constants.SELECTOR_SET_TAG, nsmap={"wsman": WSMAN_Constants.WSMAN})
    selector_set.attrib["xmlns"]=WSMAN_Constants.WSMAN
    selector = ET.SubElement(selector_set, WSMAN_Constants.SELECTOR_TAG)
    selector.attrib["Name"]="ShellId"
    selector.text = self.parse_shell_id()
    subheader = sub_header.append(selector_set)
    self.sub_header = sub_header
       	
    #build command
    commandLine=ET.Element(WSMAN_Constants.COMMANDLINE_TAG , nsmap={"rsp": WSMAN_Constants.SHELL})
    command_el = ET.SubElement(commandLine, WSMAN_Constants.COMMAND_TAG)
    command_el.text = self.command["text"]

    for argument in self.command["arguments"]:
      arguments = ET.SubElement(commandLine, WSMAN_Constants.ARGUMENTS_TAG)
      arguments.text = argument
              	
    #send command
    root=self.generate_message(WSMAN_Constants.COMMAND_ACTION, self.host, WSMAN_Constants.CMD , uuid.uuid4(), commandLine, sub_header=sub_header)
    command_msg = ET.tostring(root)
    command_response = self.session.post(self.host, auth=self.auth, data=command_msg, headers=self.headers, timeout=self.timeout)
    self.check_response(command_response)    

  def parse_shell_id(self):
   selectorset_selector_path=objectify.ObjectPath(WSMAN_Constants.SELECTOR_PATH)
   selectorset_selector_el=selectorset_selector_path.find(objectify.fromstring(self.response.content))
   return selectorset_selector_el.text	
  
  def shell_fetch_output(self, sequence):
    commandId_path= WSMAN_Constants.COMMAND_ID
    if self.commandId != None:
      commandId = self.commandId
    else:
      commandId = objectify.ObjectPath(commandId_path).find(objectify.fromstring(self.response.content)).text    
      self.commandId = commandId
	  
    sub_body=ET.Element(WSMAN_Constants.RECEIVE_TAG , nsmap={"rsp": WSMAN_Constants.SHELL})
    sub_body.attrib["SequenceId"]=str(sequence)
    desiredStream = ET.SubElement(sub_body, WSMAN_Constants.DESIRED_STREAM_TAG)
    desiredStream.attrib["CommandId"]=commandId 
    desiredStream.text ="stdout stderr"     
    
    root=self.generate_message(WSMAN_Constants.RECEIVE_ACTION, self.host, WSMAN_Constants.CMD , uuid.uuid4(), sub_body, self.get_shell_sub_header())
    receive_msg = ET.tostring(root)
    r = self.session.post(self.host, auth=self.auth, data=receive_msg, headers=self.headers, timeout=self.timeout)
    
    try:
      self.check_response(r)	
    except WSManFault_NoShellOutput:
      self.current_action = States.FETCH_OUTPUT['action']
      self.next_state()
    
  def parse_shell_output(self):   
    stdout = ""
    stderr = ""  
    state = ""
    sequence = 0
        
    while(state != "Done"):  
      
      xml=objectify.fromstring(self.response.content)
      stream_path=objectify.ObjectPath(WSMAN_Constants.STREAM)
      stream_el = stream_path.find(xml)
      
      for stream in stream_el:
        if stream.attrib["Name"] == "stdout":          
          if stream.text:             	  
            stdout += base64.b64decode(stream.text)
        if stream.attrib["Name"] == "stderr":
          if stream.text:
            stderr += base64.b64decode(stream.text)	
      
      command_state_path=objectify.ObjectPath(WSMAN_Constants.COMMAND_STATE)
      command_state_el=command_state_path.find(xml)
      state = command_state_el.attrib["State"].split("/")[-1]  
      sequence += 1

      if state != "Done":
        self.shell_fetch_output(sequence)
		
    self.output = {"stdout": stdout, "stderr": stderr}    
    self.current_action = "ReceiveDone"
    self.next_state()
	
  def delete_shell(self):
    root=self.generate_message(WSMAN_Constants.DELETE_ACTION, self.host, WSMAN_Constants.CMD , uuid.uuid4(), sub_header=self.get_shell_sub_header())
    delete_msg = ET.tostring(root)
    r=self.session.post(self.host, auth=self.auth, data=delete_msg, headers=self.headers, timeout=self.timeout)
    self.check_response(r)   

  def shell_terminate_signal(self):
   
    sub_body=ET.Element(WSMAN_Constants.SIGNAL_TAG , nsmap={"rsp": WSMAN_Constants.SHELL})
    sub_body.attrib["CommandId"]=self.commandId
    code = ET.SubElement(sub_body, WSMAN_Constants.CODE_TAG)
    code.text =WSMAN_Constants.SIGNAL
    root=self.generate_message(WSMAN_Constants.SIGNAL_ACTION, self.host, WSMAN_Constants.CMD , uuid.uuid4(), sub_body= sub_body,  sub_header=self.get_shell_sub_header())
    signal_msg = ET.tostring(root)
    r=self.session.post(self.host, auth=self.auth, data=signal_msg, headers=self.headers, timeout=self.timeout)
    self.current_action = "SignalResponse"
    self.check_response(r)  
  
