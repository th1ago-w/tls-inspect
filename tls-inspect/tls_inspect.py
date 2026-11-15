"""Inspeção de certificados TLS com a biblioteca padrão do Python."""
import argparse
import ipaddress
import json
import math
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone


def normalize_host(host):
    if not host or any(c.isspace() for c in host) or any(c in host for c in '/@?#'):
        raise ValueError('Informe somente o domínio ou IP, sem URL, porta ou caminho.')
    host = host.rstrip('.')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if ':' in host:
        raise ValueError('Informe a porta separadamente com --port.')
    host = host.encode('idna').decode('ascii').lower()
    labels = host.split('.')
    if len(host) > 253 or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or not all(c.isascii() and (c.isalnum() or c == '-') for c in label) for label in labels):
        raise ValueError('Domínio inválido.')
    return host


def distinguished_name(groups):
    return ', '.join(f'{key}={value}' for group in groups for key, value in group)


def certificate_report(host, port, cert, version, cipher, warn_days=30, now=None, demo=False):
    now = now or datetime.now(timezone.utc)
    start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notBefore']), timezone.utc)
    end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
    remaining = (end - now).total_seconds()
    state = 'expirado' if remaining <= 0 else ('ainda não válido' if now < start else ('vence em breve' if remaining <= warn_days * 86400 else 'dentro do prazo'))
    return dict(host=host, port=port, demo=demo, checked_at=now.isoformat(),
                validation='simulada' if demo else 'aprovada', validity=state,
                subject=distinguished_name(cert.get('subject', ())),
                issuer=distinguished_name(cert.get('issuer', ())),
                not_before=start.isoformat(), not_after=end.isoformat(),
                days_remaining=math.floor(remaining / 86400),
                subject_alt_names=[{'type': key, 'value': value} for key, value in cert.get('subjectAltName', ())],
                tls_version=version, cipher=cipher, warning_days=warn_days)


def inspect(host, port=443, timeout=10, warn_days=30):
    host = normalize_host(host)
    context = ssl.create_default_context()
    # check_hostname e CERT_REQUIRED continuam ativos; não há modo inseguro.
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secure:
            cipher = secure.cipher()
            return certificate_report(host, port, secure.getpeercert(), secure.version(), cipher[0] if cipher else None, warn_days)


def demo_report(warn_days=30):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fmt = '%b %d %H:%M:%S %Y GMT'
    cert = {'subject': ((('commonName', 'exemplo.test'),),),
            'issuer': ((('commonName', 'Autoridade fictícia de demonstração'),),),
            'notBefore': (now - timedelta(days=60)).strftime(fmt),
            'notAfter': (now + timedelta(days=14)).strftime(fmt),
            'subjectAltName': (('DNS', 'exemplo.test'), ('DNS', 'www.exemplo.test'))}
    return certificate_report('exemplo.test', 443, cert, 'TLSv1.3 (simulado)', 'TLS_AES_256_GCM_SHA384 (simulado)', warn_days, now, True)


def display(report):
    if report['demo']:
        print('DEMONSTRAÇÃO OFFLINE: certificado e conexão fictícios.\n')
    print('TLS Inspect')
    print(f"Destino: {report['host']}:{report['port']}")
    print(f"Validação TLS: {report['validation']}")
    if not report['demo']:
        print('Cadeia de confiança e nome do destino aceitos pelo ambiente Python.')
    print(f"Situação: {report['validity']}")
    print(f"Dias restantes (completos): {report['days_remaining']}")
    print(f"Válido desde (UTC): {report['not_before']}")
    print(f"Válido até (UTC): {report['not_after']}")
    print(f"Titular: {report['subject']}")
    print(f"Emissor: {report['issuer']}")
    print(f"Protocolo negociado: {report['tls_version']}")
    print(f"Cifra negociada: {report['cipher']}")
    print('Nomes alternativos:')
    for item in report['subject_alt_names']:
        print(f"  {item['type']}: {item['value']}")
    print('\nUm handshake válido não garante que um site seja confiável ou livre de vulnerabilidades.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Consulta um certificado TLS e verifica sua validade.')
    parser.add_argument('host', nargs='?', help='Domínio ou IP, sem https://')
    parser.add_argument('--port', type=int, default=443, help='Porta TLS (padrão: 443).')
    parser.add_argument('--timeout', type=float, default=10, help='Timeout de rede em segundos (padrão: 10).')
    parser.add_argument('--warn-days', type=int, default=30, help='Prazo de alerta de vencimento em dias (padrão: 30).')
    parser.add_argument('--json', dest='output', help='Salva relatório JSON sem sobrescrever arquivos existentes.')
    parser.add_argument('--demo', action='store_true', help='Exemplo fictício sem conexão de rede.')
    args = parser.parse_args(argv)
    if bool(args.host) == args.demo:
        parser.error('Informe um domínio ou use --demo, sem combinar os dois.')
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 120 or args.warn_days < 0:
        parser.error('Porta: 1–65535; timeout: maior que 0 e até 120; warn-days: zero ou mais.')
    try:
        report = demo_report(args.warn_days) if args.demo else inspect(args.host, args.port, args.timeout, args.warn_days)
        display(report)
        if args.output:
            with open(args.output, 'x', encoding='utf-8') as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
            print(f'Relatório salvo: {args.output}')
        return 1 if report['validity'] != 'dentro do prazo' else 0
    except ssl.SSLCertVerificationError as error:
        print(f'Validação TLS reprovada: {error.verify_message}.\nA conexão foi recusada; os dados do certificado não foram aceitos.', file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError) as error:
        print(f'Erro: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
