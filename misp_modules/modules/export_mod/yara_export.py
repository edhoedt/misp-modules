import json
import base64
import six
import zipfile
import re
if six.PY3:
    import io
    import urllib.parse as urlparse
else:
    import StringIO as io
    import urlparse

misperrors = {'error': 'Error'}
inputSource = ['event']
outputFileExtension = 'zip'
responseType = 'application/zip'

moduleinfo = {  'version': '0.1',
                'author': 'edhoedt',
                'description': 'Export IDS-ready IOCs as yara rules',
                'module-type': ['export']}

# config fields that your code expects from the site admin
# moduleconfig = ['Group_by_event']
moduleconfig = ['optional_host_url']

attributes_with_special_processing={
    'yara': 'yara_rule_rule',
    'hex': 'single_hex_rule',
    'md5': 'hash_rule',
    'sha1': 'hash_rule',
    'sha256': 'hash_rule',
    'impash': 'hash_rule',
    'filename|md5': 'hash_rule',
    'filename|sha1': 'hash_rule',
    'filename|sha256': 'hash_rule',
    'filename|impash': 'hash_rule',
    'filename': 'filename_rule',
    ##'size-in-bytes': filesize_rule,
    # partial support
    'filename|sha224': 'filename_partial_rule',
    'filename|sha384': 'filename_partial_rule',
    'filename|sha512': 'filename_partial_rule',
    'filename|sha512/224': 'filename_partial_rule',
    'filename|sha512/256': 'filename_partial_rule',
    # unsupported
    'sha224': 'ignore_rule_unsupported',
    'sha384': 'ignore_rule_unsupported',
    'sha512': 'ignore_rule_unsupported',
    'sha512/224': 'ignore_rule_unsupported',
    'sha512/256': 'ignore_rule_unsupported',
    # irrelevant
    'snort': 'ignore_rule_irrelevant',
    'port' : 'ignore_rule_irrelevant',
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request['config'] if 'config' in request and request['config'] else {'optional_host_url':None}
    server_url = config['optional_host_url'] if config['optional_host_url'] else ''
    data = request['data']
    generated_yara = ''
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as response:
        for ev in data:
            event_uuid = ev['Event']['uuid']
            event_info = ev['Event']['info']
            event_link = server_url+'/event/view/'+event_uuid
            event = ev["Attribute"]
            for attr in event:
                if attr['to_ids']:
                    attr_type = attr['type']
                    if attr_type == 'yara':
                        response.writestr(attr['uuid']+'.yar', attr['value'])
                    elif attr_type in attributes_with_special_processing:
                        processing_func = globals()[attributes_with_special_processing[attr_type]]
                        generated_yara+='\r\n\r\n'+processing_func(attr, extra_meta={'event_uuid':event_uuid, 'event_info':event_info, 'event_link':event_link})
                    else:
                        generated_yara+='\r\n\r\n'+single_hex_or_string_rule(attr, extra_meta={'event_uuid':event_uuid, 'event_info':event_info, 'event_link':event_link})
        response.writestr('q', q)
        response.writestr('_generated_from_IOCs.yar', generated_yara)
        #r={'data':base64.b64encode(generated_yara.encode('utf-8')).decode('utf-8')}
    zip_buffer.seek(0)
    zip_as_bytes = zip_buffer.read()
    r={'data':base64.b64encode(zip_as_bytes).decode('utf-8')}
    return r


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup['responseType'] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup['outputFileExtension'] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

# -----HELPERS FOR RULES CONSTRUCTION ------------------------------------------
def basic_rule(attribute, strings_stmts, condition_stmts, **kwargs):
    if 'modules' not in kwargs or not kwargs['modules']:
        modules = []
    elif isinstance(kwargs['modules'], six.string_types) :
        modules = [kwargs['modules']]
    else:
        modules = kwargs['modules']
    if isinstance(strings_stmts, six.string_types) :
        strings_stmts = [strings_stmts]
    if isinstance(condition_stmts, six.string_types) :
        condition_stmts = [condition_stmts]
    meta_dict={
        'attribute_uuid': attribute['uuid'],
        'category': attribute['category'],
        'type': attribute['type'],
        'comment': attribute['comment'].replace('\n', ' ').replace('\r', ' ')
    }


    if 'extra_meta' in kwargs and kwargs['extra_meta']:
        meta_dict.update(kwargs['extra_meta'])
    rulename = 'attr_{}'.format(re.sub(r'\W+', '_', attribute['uuid']))
    meta='\r\n\t\t'.join([(key+' = '+text_str(meta_dict[key])) for key in meta_dict])
    strings='\r\n\t\t'.join(strings_stmts) if strings_stmts else ''
    condition='\r\n\t\t'.join(condition_stmts) if condition_stmts else ''

    imports_section = '\r\n'.join(['import "{}"'.format(m) for m in modules]) if modules else ''
    rule_start_section = 'rule '+rulename+'{'
    meta_section = '\tmeta:\r\n\t\t' + meta
    strings_section = ('\tstrings:\r\n\t\t'+strings) if strings else ''
    condition_section = ('\tcondition:\r\n\t\t'+condition) if condition else ''
    rule_end_section = '}'

    return '\r\n'.join([imports_section,
                        rule_start_section,
                        meta_section,
                        strings_section,
                        condition_section,
                        rule_end_section])

def text_str(string_ioc):
    return u'"{}"'.format(string_ioc.replace('"','\\"'))

def hex_str(hex_ioc):
    trimmed_ioc = re.sub(r'\s', '', hex_ioc)
    trimmed_ioc = trimmed_ioc.strip('}"{\'')
    if all(c.lower() in '0123456789abcdef' for c in trimmed_ioc):
        return '{'+trimmed_ioc+'}'
    else:
        raise ValueError('hex_str expects a string in hex format possibly surrounded by curly brackets, spaces or quotes')

def hash_cond(hashtype, hashvalue):
    if hashtype in ['md5','sha1','sha256']:
        condition_stmt = 'hash.{}(0, filesize) == {}'.format(hashtype, text_str(hashvalue.lower()))
        required_module = 'hash'
    elif hashtype is 'imphash':
        condition_stmt = 'pe.imphash() == ' + text_str(hashvalue.lower())
        required_module = 'pe'
    else:
        condition_stmt = ''
        required_module = None
        raise Warning('Hash type "{}" unsupported'.format(hashtype))
    return condition_stmt, required_module

def pe_filename_cond(filename):
    return 'pe.version_info["OriginalFilename"] == '+text_str(filename)


# ----- FUNCTIONS TO CONVERT ATTRIBUTES TO YARA RULES ACCORDING TO THEIR TYPE --

def yara_rule_rule(attribute, **kwargs):
    return attribute['value']

def single_string_rule(attribute,**kwargs):
    strings_stmt = '$ioc = '+text_str(attribute['value'])
    condition_stmt = '$ioc'
    return basic_rule(attribute,strings_stmt,condition_stmt, **kwargs)

def single_hex_rule(attribute, **kwargs):
    strings_stmt = '$ioc = '+hex_str(attribute['value'])
    condition_stmt = '$ioc'
    return basic_rule(attribute,strings_stmt,condition_stmt, **kwargs)

def single_hex_or_string_rule(attribute, **kwargs):
    str_value = text_str(attribute['value'])
    try:
        hex_value = hex_str(attribute['value'])
        strings_stmt = ['$ioc_str = '+str_value, '$ioc_hex = '+hex_value]
        condition_stmt = '$ioc_str or $ioc_hex'
    except ValueError as e:
        strings_stmt = '$ioc = '+ str_value
        condition_stmt = '$ioc'
    return basic_rule(attribute,strings_stmt,condition_stmt, **kwargs)

def hash_rule(attribute, **kwargs):
    if attribute['type'].startswith('filename|'):
        _, hashtype = attribute['type'].rsplit('|', 1)
        filename, hashvalue = attribute['value'].rsplit('|', 1)
        condition_stmt, required_module = hash_cond(hashtype, hashvalue)
        condition_stmt = condition_stmt + ' or '+pe_filename_cond(filename)
        if required_module is not 'pe':
            required_module = [required_module, 'pe']
    else:
        hashtype = attribute['type']
        hashvalue = attribute['value']
        condition_stmt, required_module = hash_cond(hashtype, hashvalue)
    return basic_rule(attribute,None,condition_stmt, modules=required_module, **kwargs)

def filename_rule(attribute, **kwargs):
    condition_stmt = pe_filename_cond(attribute['value'])
    return basic_rule(attribute,None,condition_stmt, modules='pe', **kwargs)

def filename_partial_rule(attribute, **kwargs):
    filename, _ = attribute['value'].lsplit('|', 1)
    condition_stmt = pe_filename_cond(filename)
    return basic_rule(attribute,None,condition_stmt, modules='pe', **kwargs)

def ignore_rule(attribute, **kwargs):
    ignore_reason = ('//\t'+kwargs['ignore_reason']) if 'ignore_reason' in kwargs else ''
    return '// Ignored attribute\r\n\
            //\tType: {}\r\n//\tuuid: {}\r\n{}'.format(attribute['type'], attribute['uuid'], ignore_reason)

def ignore_rule_unsupported(attribute, **kwargs):
    reason = 'IOC type "{}" is not supported by yara or any of its native modules'.format(attribute['type'])
    return ignore_rule(attribute, ignore_reason=reason, **kwargs)

def ignore_rule_irrelevant(attribute, **kwargs):
    reason = 'Creating a yara IOC from a "{}" attribute does not make sense'.format(attribute['type'])
    return ignore_rule(attribute, ignore_reason=reason, **kwargs)



#def ip_rule(event_info, event_uuid, attribute)
#    parse_res = urlparse(attribute['value'])
#    ip = parse_res.netloc
#    is_ipv6 =
#
#    strings_stmt = '$ip="{}" $ip_port="{}"'.format(ip, attribute['value'])
#    condition_stmt = '$a'
#    return basic_rule(event_info,event_uuid,attribute,strings_stmt,condition_stmt)
