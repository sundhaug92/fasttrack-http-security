import sqlite3,sys

db_conn=sqlite3.connect('profile.db')
db_cursor=db_conn.cursor()

def get_csp_policy(document_domain):
    directive_dict={
        'report-uri':'https://example.org/CSP-REPORT-URI'
    }
    def add_directive(directive, resource_domain):
        if not directive in directive_dict.keys(): directive_dict[directive]=''
        directive_dict[directive]+=resource_domain + ' '
    for (directive, resource_domain, action) in db_cursor.execute('SELECT directive, resource_domain, action FROM known_relations WHERE document_domain=?', (document_domain,)):
        if action=='PERMIT':
            add_directive(directive, resource_domain)
    policy='; '.join([k + ' ' + directive_dict[k].strip() for k in directive_dict.keys()])
    return policy

for document_domain in sorted((set(sys.argv[1:]))):
    print('{}: {}'.format(document_domain, get_csp_policy(document_domain)))

