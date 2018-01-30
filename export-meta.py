import sqlite3
import sys

db_conn = sqlite3.connect('profile.db')
db_cursor = db_conn.cursor()


def get_csp_policy(document_domain):
    directive_dict = {
        'report-uri': 'https://example.org/CSP-REPORT-URI',
        'default-src': "'none' ",
        'style-src': "'none' ",
        'img-src': "'none' ",
        'frame-src': "'none' ",
        'frame-ancestors': "'none' ",
        'media-src': "'none' ",
        'manifest-src': "'none' ",
        'connect-src': "'none' ",
        'worker-src': "'none' ",
        'font-src': "'none' ",
        'script-src': "'none' "
    }

    def add_directive(directive, resource_domain):
        if not directive in directive_dict.keys() or "'none'" in directive_dict[directive]:
            directive_dict[directive] = ''
        directive_dict[directive] += resource_domain + ' '
    for (directive, resource_domain, action) in db_cursor.execute('SELECT directive, resource_domain, action FROM known_relations WHERE document_domain=?', (document_domain,)):
        if action == 'PERMIT':
            add_directive(directive, resource_domain)
    policy = '; '.join([k + ' ' + directive_dict[k].strip()
                        for k in directive_dict.keys()])
    return policy


def get_sri_hashes(resource_domain):
    return sorted(set(db_cursor.execute('SELECT resource_uri,sha256,sha384,sha512 FROM sri_hashes WHERE resource_domain=?', (resource_domain,)).fetchall()))


if '*' in sys.argv:
    sys.argv = sorted(set([_[0] for _ in
                           db_cursor.execute('SELECT document_domain FROM known_relations').fetchall() +
                           db_cursor.execute('SELECT resource_domain FROM known_relations').fetchall() +
                           db_cursor.execute('SELECT resource_domain FROM sri_hashes').fetchall()]))

for document_domain in sorted((set(sys.argv[1:]))):
    print('CSP {}: {}'.format(document_domain, get_csp_policy(document_domain)))
    for sri_hash_result in get_sri_hashes(document_domain):
        print('SRI {}: {}'.format(document_domain, ' '.join(sri_hash_result)))
