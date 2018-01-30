from mitmproxy import http
from string import ascii_letters, digits
from random import choice
from json import loads
import sqlite3

DEFAULT_ACTION='PERMIT'

csp_report_path='/csp-report-' + ''.join([choice(ascii_letters + digits) for _ in range(32)])
csp_blockd_path=csp_report_path.replace('report', 'blocked')
db_conn=sqlite3.connect('profile.db')
db_cursor=db_conn.cursor()

def get_csp_policy(flow: http.HTTPFlow) -> None:
    directive_dict={
        'report-uri':'https://example.org' + csp_blockd_path
    }
    def add_directive(directive, resource_domain):
        if not directive in directive_dict.keys(): directive_dict[directive]=''
        directive_dict[directive]+=resource_domain + ' '
        print('DIRECTIVE[{}]={}'.format(directive, directive_dict[directive]))
    print('Getting CSP for document_domain='+flow.request.host)
    for (directive, resource_domain, action) in db_cursor.execute('SELECT directive, resource_domain, action FROM known_relations WHERE document_domain=?', (flow.request.host,)):
        print((directive, resource_domain, action))
        if action=='PERMIT':
            add_directive(directive, resource_domain)
#    if 'Content-Security-Policy' in flow.response.headers:
#        for directive in flow.response.headers['Content-Security-Policy'].split(';'):
#            directive_key=directive.strip().split(' ')[0]
#            if not directive_key.startswith('report') and directive_key!='':
#                for domain in directive.strip().split(' ')[1:]:
#                    add_directive(directive_key, domain)
    policy='; '.join([k + ' ' + directive_dict[k].strip() for k in directive_dict.keys()])
    print('POLICY={}'.format(policy))
    return policy


def response(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith(csp_report_path) or flow.request.pretty_url.endswith(csp_blockd_path):
        flow.response = http.HTTPResponse.make(
            200,
            b'Reported' if flow.request.pretty_url.endswith(csp_report_path) else 'BLOCKED')
        report=loads(flow.request.text)['csp-report']
        violated_filter=report['violated-directive'].split(' ')[0]
        if report['blocked-uri']=='self' and 'script-sample' in report.keys():
            report['blocked-uri']='Unsafe inline "{}"'.format(''.join(report['script-sample'].split('\n')).strip())
        elif flow.request.pretty_url.endswith(csp_report_path):
            document_domain='/'.join(report['document-uri'].split('/')[2:3])
            resource_domain='/'.join(report['blocked-uri'].split('/')[2:3])
            if '' not in [document_domain,resource_domain]:
                db_cursor.execute('SELECT 1 FROM known_relations WHERE directive=? AND document_domain=? AND resource_domain=?', (violated_filter,document_domain,resource_domain))
                if db_cursor.fetchone() is None:
                   db_cursor.execute('INSERT INTO known_relations VALUES (1, ?, ?, ?, ?)', (violated_filter,document_domain,resource_domain,DEFAULT_ACTION if violated_filter!='default-src' else 'REGISTER'))
                else:
                   db_cursor.execute('UPDATE known_relations SET hit_count=hit_count+1 WHERE directive=? AND document_domain=? AND resource_domain=?', (violated_filter,document_domain,resource_domain))
                db_conn.commit()
#                print(('{}: "{}" reported loading "{}"' if flow.request.pretty_url.endswith(csp_report_path) else '{}: "{}" blocked loading "{}"').format(violated_filter, report['document-uri'], report['blocked-uri']))
    else:
        flow.response.headers['Content-Security-Policy-Report-Only']="default-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; script-src 'none'; report-uri https://example.org{}".format(csp_report_path)
        flow.response.headers['Content-Security-Policy']=get_csp_policy(flow)

db_cursor.execute('CREATE TABLE IF NOT EXISTS known_relations (hit_count INT, directive TEXT, document_domain TEXT, resource_domain TEXT, action TEXT)')
db_conn.commit()
