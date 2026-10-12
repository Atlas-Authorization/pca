"""
Cross-check pca-ap2 against Google's official AP2 Python SDK (github.com/google-agentic-commerce/AP2).

Setup (outside the repo; deleted afterwards):
    uv venv py && uv pip install --python py/bin/python cryptography==46.0.5 jwcrypto==1.5.6 \
        pydantic==2.12.5 sd-jwt==0.10.4
    git fetch --depth 1 origin e1ea56db72a6385bce3e5c1112b3a56ce60acb43   # sparse: code/sdk/python
Run:
    AP2_SRC=<checkout>/code/sdk/python py/bin/python -I crosscheck/ap2_sdk.py

Direction 1: the tokens in fixtures/crosscheck/mine.json (made by pca-ap2) are verified by the SDK's own
MandateClient / PaymentMandateChain / CheckoutMandateChain.
Direction 2: the SDK issues a complete purchase (open checkout + payment, closed checkout + payment); the
tokens, public keys and expected values are written to fixtures/crosscheck/official-sdk.json for the
TypeScript test-suite to verify with pca-ap2.
Also records two probes of SDK behaviour that pca-ap2 deliberately does not copy.
"""
import json, os, sys, time, importlib.metadata as md
from pathlib import Path

sys.path.insert(0, os.environ['AP2_SRC'])
HERE = Path(__file__).resolve().parent
FIX = HERE.parent / 'fixtures' / 'crosscheck'
mine = json.loads((FIX / 'mine.json').read_text())

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK
from jwcrypto import jws
from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt.common import parse_token, compute_sd_hash
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.constraints import MandateContext
from ap2.sdk.utils import compute_sha256_b64url
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import AllowedMerchants, Item, LineItemRequirements, LineItems, OpenCheckoutMandate
from ap2.sdk.generated.open_payment_mandate import AllowedPayees, AmountRange, Budget, AgentRecurrence, Frequency, OpenPaymentMandate, PaymentReference
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument

NOW = mine['now']
client = MandateClient()
results = {
    'sdk': {
        'repo': 'https://github.com/google-agentic-commerce/AP2',
        'commit': mine['ap2_commit'],
        'python': sys.version.split()[0],
        'deps': {d: md.version(d) for d in ['cryptography', 'jwcrypto', 'pydantic', 'sd-jwt']},
    },
}

# ---------------------------------------------------------------- direction 1
issuer = JWK(**mine['keys']['issuer'])
provider = lambda token: issuer

def verify_checkout(token, aud, nonce, now=NOW):
    payloads = client.verify(token, provider, expected_aud=aud, expected_nonce=nonce, current_time=now)
    chain = CheckoutMandateChain.parse(payloads)
    v = chain.verify(expected_checkout_hash=chain.closed_mandate.checkout_hash, checkout_jwt=chain.closed_mandate.checkout_jwt)
    return payloads, chain, v

mc = mine['checkout']
payloads, cchain, cviol = verify_checkout(mc['token'], mc['aud'], mc['nonce'])
assert cchain.closed_mandate.checkout_hash == compute_sha256_b64url(cchain.closed_mandate.checkout_jwt)
mp = mine['payment']
ppayloads = client.verify(mp['token'], provider, expected_aud=mp['aud'], expected_nonce=mp['nonce'], current_time=NOW)
pchain = PaymentMandateChain.parse(ppayloads)
pviol = pchain.verify(expected_transaction_id=cchain.closed_mandate.checkout_hash, expected_open_checkout_hash=mc['open_hash'],
                      mandate_context=MandateContext(total_amount=0, total_uses=0))
results['mine_verified_by_official_sdk'] = {
    'checkout_chain': {'violations': cviol, 'checkout_hash': cchain.closed_mandate.checkout_hash},
    'payment_chain': {'violations': pviol, 'transaction_id': pchain.closed_mandate.transaction_id,
                      'amount': pchain.closed_mandate.payment_amount.amount, 'currency': pchain.closed_mandate.payment_amount.currency},
    'x_pca_ignored_by_pydantic': 'x_pca' not in pchain.open_mandate.model_dump(),
}
assert cviol == [] and pviol == [], (cviol, pviol)
assert pchain.closed_mandate.transaction_id == cchain.closed_mandate.checkout_hash == mine['transaction_id']

# negative controls through the SDK itself
def rejects(f):
    try:
        f(); return False
    except Exception as e:
        return type(e).__name__
results['sdk_rejects_tampering'] = {
    'wrong_nonce': rejects(lambda: client.verify(mp['token'], provider, expected_aud=mp['aud'], expected_nonce='x', current_time=NOW)),
    'wrong_aud': rejects(lambda: client.verify(mp['token'], provider, expected_aud='x', expected_nonce=mp['nonce'], current_time=NOW)),
    'flipped_char': rejects(lambda: client.verify(mp['token'][:-12] + ('A' if mp['token'][-12] != 'A' else 'B') + mp['token'][-11:], provider, expected_aud=mp['aud'], expected_nonce=mp['nonce'], current_time=NOW)),
}

# probes: behaviour of the SDK that pca-ap2 is stricter about
probes = {}
for name, p in mine['probes'].items():
    try:
        _, ch, viol = verify_checkout(p['token'], mc['aud'], mc['nonce'])
        probes[name] = {'sdk_accepts': viol == [], 'sdk_violations': viol, 'description': p['description']}
    except Exception as e:
        probes[name] = {'sdk_accepts': False, 'sdk_error': f'{type(e).__name__}: {e}', 'description': p['description']}
results['probes'] = probes

# thumbprints (RFC 7638) from jwcrypto
results['thumbprints'] = [{'jwk': t['jwk'], 'jkt': JWK(**t['jwk']).thumbprint(), 'mine': t['jkt']} for t in mine['thumbprints']]
assert all(t['jkt'] == t['mine'] for t in results['thumbprints'])

# ---------------------------------------------------------------- direction 2
# Upstream finding: the SDK cannot issue an open payment mandate that carries payment.agent_recurrence:
# model_dump() leaves the Frequency enum member in place and the SD-JWT issuer's json.dumps rejects it.
try:
    client.create(payloads=[OpenPaymentMandate(constraints=[AgentRecurrence(frequency=Frequency.ON_DEMAND), PaymentReference(conditional_transaction_id='x')],
                                               cnf={'jwk': json.loads(JWK.from_pyca(ec.generate_private_key(ec.SECP256R1())).export_public())})],
                  issuer_key=JWK.from_pyca(ec.generate_private_key(ec.SECP256R1())))
    results['sdk_cannot_issue_agent_recurrence'] = None
except TypeError as e:
    results['sdk_cannot_issue_agent_recurrence'] = f'TypeError: {e}'
def mk_key(kid=None):
    k = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    d = json.loads(k.export())
    if kid: d['kid'] = kid
    return JWK.from_json(json.dumps(d))
pub = lambda k: json.loads(k.export_public())

provider_key, agent_key, merchant_key = mk_key('agent-provider-key-1'), mk_key(), mk_key('merchant-key-1')
merchant = Merchant(id='merchant_1', name='Demo Merchant', website='https://demo-merchant.example')
ISSUED = NOW - 30
EXP = ISSUED + 3600

open_checkout = client.create(
    payloads=[OpenCheckoutMandate(
        constraints=[LineItems(items=[LineItemRequirements(id='line_1', acceptable_items=[Item(id='sku-1', title='Widget'), Item(id='sku-2', title='Widget Pro')], quantity=2)]),
                     AllowedMerchants(allowed=[merchant])],
        cnf={'jwk': pub(agent_key)}, iat=ISSUED, exp=EXP)],
    issuer_key=provider_key)
open_checkout_hash = compute_sd_hash(parse_token(open_checkout))
open_payment = client.create(
    payloads=[OpenPaymentMandate(
        constraints=[AmountRange(currency='USD', min=0, max=50000), AllowedPayees(allowed=[merchant]), PaymentReference(conditional_transaction_id=open_checkout_hash),
                     Budget(max=1000.0, currency='USD')],
        cnf={'jwk': pub(agent_key)}, iat=ISSUED, exp=EXP)],
    issuer_key=provider_key)

checkout_payload = {
    'id': 'chk_sdk_0001', 'merchant': json.loads(merchant.model_dump_json(exclude_none=True)), 'status': 'ready_for_complete', 'currency': 'USD',
    'line_items': [{'id': 'li_1', 'item': {'id': 'sku-1', 'title': 'Widget', 'price': 2000}, 'quantity': 2, 'totals': [{'type': 'subtotal', 'amount': 4000}]}],
    'totals': [{'type': 'subtotal', 'amount': 4000}, {'type': 'total', 'amount': 4000}],
    'links': [{'type': 'terms', 'url': 'https://demo-merchant.example/terms'}],
}
tok = jws.JWS(json.dumps(checkout_payload).encode())
tok.add_signature(merchant_key, alg='ES256', protected=json.dumps({'alg': 'ES256', 'typ': 'JWT', 'kid': 'merchant-key-1'}))
sig = json.loads(tok.serialize())
checkout_jwt = f"{sig['protected']}.{sig['payload']}.{sig['signature']}"
checkout_hash = compute_sha256_b64url(checkout_jwt)

closed_checkout = client.present(holder_key=agent_key, mandate_token=open_checkout, payloads=[CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash)],
                                 nonce='sdk-nonce-checkout', aud='merchant')
closed_payment = client.present(holder_key=agent_key, mandate_token=open_payment,
                                payloads=[PaymentMandate(transaction_id=checkout_hash, payee=merchant, payment_amount=Amount(amount=4000, currency='USD'),
                                                          payment_instrument=PaymentInstrument(id='card_4242', type='card', description='Card 4242'))],
                                nonce='sdk-nonce-payment', aud='credential-provider')
# the SDK must accept its own output (sanity)
sk_payloads = client.verify(closed_checkout, lambda t: provider_key, expected_aud='merchant', expected_nonce='sdk-nonce-checkout', current_time=NOW)
assert CheckoutMandateChain.parse(sk_payloads).verify(checkout_jwt=checkout_jwt) == []

results['sdk_issued'] = {
    'now': NOW,
    'keys': {'issuer': pub(provider_key), 'merchant': pub(merchant_key), 'agent': pub(agent_key)},
    'checkout': {'token': closed_checkout, 'aud': 'merchant', 'nonce': 'sdk-nonce-checkout', 'checkout_jwt': checkout_jwt, 'open_hash': open_checkout_hash},
    'payment': {'token': closed_payment, 'aud': 'credential-provider', 'nonce': 'sdk-nonce-payment'},
    'transaction_id': checkout_hash, 'amount_minor': 4000,
    'open_checkout_token': open_checkout, 'open_payment_token': open_payment,
}
(FIX / 'official-sdk.json').write_text(json.dumps(results, indent=1) + '\n')
print(json.dumps({k: results[k] for k in ['mine_verified_by_official_sdk', 'sdk_rejects_tampering', 'probes', 'sdk_cannot_issue_agent_recurrence']}, indent=1))
