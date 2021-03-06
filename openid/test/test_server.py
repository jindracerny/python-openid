"""Tests for openid.server.
"""
from __future__ import unicode_literals

import unittest
import warnings
from functools import partial

import six
from mock import sentinel
from six.moves.urllib.parse import parse_qs, parse_qsl, urlparse
from testfixtures import LogCapture, ShouldWarn, StringComparison

from openid import association, cryptutil, oidutil
from openid.consumer.consumer import DiffieHellmanSHA256ConsumerSession
from openid.message import IDENTIFIER_SELECT, OPENID1_NS, OPENID1_URL_LIMIT, OPENID2_NS, OPENID_NS, Message, no_default
from openid.server import server
from openid.store import memstore

# In general, if you edit or add tests here, try to move in the direction
# of testing smaller units.  For testing the external interfaces, we'll be
# developing an implementation-agnostic testing suite.

# for more, see /etc/ssh/moduli

ALT_MODULUS = int('1423261515703355186607439952816216983770573549498844689430217675736088990483613604225135575535147900'
                  '4551229946895343158530081254885941985717109436635815890343316791551733211386105974742540867014420109'
                  '9811846875730766487278261498262568348338476437200556998366087779709990807518291581860338635288400119'
                  '293970087')
ALT_GEN = 5


# Example values to be used in tests
EXAMPLE_IDENTITY = 'http://id.example.cz/'
EXAMPLE_CLAIMED_ID = 'http://claimed.example.cz/'


def make_checkid_request(identity=EXAMPLE_IDENTITY, claimed_id=EXAMPLE_CLAIMED_ID,
                         trust_root='http://realm.example.cz/', return_to='http://realm.example.cz/return_to/',
                         op_endpoint='http://op.example.cz/', immediate=False, message=None):
    """Create a simple CheckIDRequest."""
    message = message or Message(OPENID2_NS)
    return server.CheckIDRequest(identity=identity, claimed_id=claimed_id, trust_root=trust_root, return_to=return_to,
                                 op_endpoint=op_endpoint, immediate=immediate, message=message)


class TestOpenIDRequest(unittest.TestCase):
    """Test OpenID request base class."""

    def test_init_default_message(self):
        # Test empty OpenID 2.0 message is create if not provided.
        request = server.OpenIDRequest()
        self.assertTrue(request.message)
        self.assertEqual(request.message.getOpenIDNamespace(), OPENID2_NS)

    def test_namespace(self):
        # Test deprecated namespace property
        request = server.OpenIDRequest()
        warning_msg = ('The "namespace" attribute of OpenIDRequest objects is deprecated. Use '
                       '"message.getOpenIDNamespace()" instead')
        with ShouldWarn(DeprecationWarning(warning_msg)):
            warnings.simplefilter('always')
            self.assertEqual(request.namespace, OPENID2_NS)


class TestProtocolError(unittest.TestCase):
    def test_browserWithReturnTo(self):
        return_to = "http://rp.unittest/consumer"
        # will be a ProtocolError raised by Decode or CheckIDRequest.answer
        args = Message.fromPostArgs({
            'openid.mode': 'monkeydance',
            'openid.identity': 'http://wagu.unittest/',
            'openid.return_to': return_to,
        })
        e = server.ProtocolError(args, "plucky")
        self.assertTrue(e.hasReturnTo())
        expected_args = {
            'openid.mode': ['error'],
            'openid.error': ['plucky'],
        }

        rt_base, result_args = e.encodeToURL().split('?', 1)
        result_args = parse_qs(result_args)
        self.assertEqual(result_args, expected_args)

    def test_browserWithReturnTo_OpenID2_GET(self):
        return_to = "http://rp.unittest/consumer"
        # will be a ProtocolError raised by Decode or CheckIDRequest.answer
        args = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.mode': 'monkeydance',
            'openid.identity': 'http://wagu.unittest/',
            'openid.claimed_id': 'http://wagu.unittest/',
            'openid.return_to': return_to,
        })
        e = server.ProtocolError(args, "plucky")
        self.assertTrue(e.hasReturnTo())
        expected_args = {
            'openid.ns': [OPENID2_NS],
            'openid.mode': ['error'],
            'openid.error': ['plucky'],
        }

        rt_base, result_args = e.encodeToURL().split('?', 1)
        result_args = parse_qs(result_args)
        self.assertEqual(result_args, expected_args)

    def test_browserWithReturnTo_OpenID2_POST(self):
        return_to = "http://rp.unittest/consumer" + ('x' * OPENID1_URL_LIMIT)
        # will be a ProtocolError raised by Decode or CheckIDRequest.answer
        args = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.mode': 'monkeydance',
            'openid.identity': 'http://wagu.unittest/',
            'openid.claimed_id': 'http://wagu.unittest/',
            'openid.return_to': return_to,
        })
        e = server.ProtocolError(args, "plucky")
        self.assertTrue(e.hasReturnTo())
        self.assertEqual(e.whichEncoding(), server.ENCODE_HTML_FORM)
        self.assertEqual(e.toFormMarkup(), e.toMessage().toFormMarkup(args.getArg(OPENID_NS, 'return_to')))

    def test_browserWithReturnTo_OpenID1_exceeds_limit(self):
        return_to = "http://rp.unittest/consumer" + ('x' * OPENID1_URL_LIMIT)
        # will be a ProtocolError raised by Decode or CheckIDRequest.answer
        args = Message.fromPostArgs({
            'openid.mode': 'monkeydance',
            'openid.identity': 'http://wagu.unittest/',
            'openid.return_to': return_to,
        })
        e = server.ProtocolError(args, "plucky")
        self.assertTrue(e.hasReturnTo())
        expected_args = {
            'openid.mode': ['error'],
            'openid.error': ['plucky'],
        }

        self.assertEqual(e.whichEncoding(), server.ENCODE_URL)

        rt_base, result_args = e.encodeToURL().split('?', 1)
        result_args = parse_qs(result_args)
        self.assertEqual(result_args, expected_args)

    def test_noReturnTo(self):
        # will be a ProtocolError raised by Decode or CheckIDRequest.answer
        args = Message.fromPostArgs({
            'openid.mode': 'zebradance',
            'openid.identity': 'http://wagu.unittest/',
        })
        e = server.ProtocolError(args, "waffles")
        self.assertFalse(e.hasReturnTo())
        expected = """error:waffles
mode:error
"""
        self.assertEqual(e.encodeToKVForm(), expected)

    def test_noMessage(self):
        e = server.ProtocolError(None, "no moar pancakes")
        self.assertFalse(e.hasReturnTo())
        self.assertIsNone(e.whichEncoding())


class TestDecode(unittest.TestCase):
    def setUp(self):
        self.claimed_id = 'http://de.legating.de.coder.unittest/'
        self.id_url = "http://decoder.am.unittest/"
        self.rt_url = "http://rp.unittest/foobot/?qux=zam"
        self.tr_url = "http://rp.unittest/"
        self.assoc_handle = "{assoc}{handle}"
        self.op_endpoint = 'http://endpoint.unittest/encode'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)
        self.decode = self.server.decoder.decode
        self.decode = server.Decoder(self.server).decode

    def test_none(self):
        args = {}
        r = self.decode(args)
        self.assertIsNone(r)

    def test_irrelevant(self):
        args = {
            'pony': 'spotted',
            'sreg.mutant_power': 'decaffinator',
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_bad(self):
        args = {
            'openid.mode': 'twos-compliment',
            'openid.pants': 'zippered',
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_dictOfLists(self):
        args = {
            'openid.mode': ['checkid_setup'],
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
        }
        with six.assertRaisesRegex(self, TypeError, 'values'):
            self.decode(args)

    def test_checkidImmediate(self):
        args = {
            'openid.mode': 'checkid_immediate',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
            # should be ignored
            'openid.some.extension': 'junk',
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckIDRequest)
        self.assertEqual(r.mode, "checkid_immediate")
        self.assertTrue(r.immediate)
        self.assertEqual(r.identity, self.id_url)
        self.assertEqual(r.trust_root, self.tr_url)
        self.assertEqual(r.return_to, self.rt_url)
        self.assertEqual(r.assoc_handle, self.assoc_handle)

    def test_checkidSetup(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': self.tr_url,
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckIDRequest)
        self.assertEqual(r.mode, "checkid_setup")
        self.assertFalse(r.immediate)
        self.assertEqual(r.identity, self.id_url)
        self.assertEqual(r.trust_root, self.tr_url)
        self.assertEqual(r.return_to, self.rt_url)

    def test_checkidSetupOpenID2(self):
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.claimed_id': self.claimed_id,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.realm': self.tr_url,
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckIDRequest)
        self.assertEqual(r.mode, "checkid_setup")
        self.assertFalse(r.immediate)
        self.assertEqual(r.identity, self.id_url)
        self.assertEqual(r.claimed_id, self.claimed_id)
        self.assertEqual(r.trust_root, self.tr_url)
        self.assertEqual(r.return_to, self.rt_url)

    def test_checkidSetupNoClaimedIDOpenID2(self):
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.realm': self.tr_url,
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_checkidSetupNoIdentityOpenID2(self):
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.realm': self.tr_url,
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckIDRequest)
        self.assertEqual(r.mode, "checkid_setup")
        self.assertFalse(r.immediate)
        self.assertIsNone(r.identity)
        self.assertEqual(r.trust_root, self.tr_url)
        self.assertEqual(r.return_to, self.rt_url)

    def test_checkidSetupNoReturnOpenID1(self):
        """Make sure an OpenID 1 request cannot be decoded if it lacks
        a return_to.
        """
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.trust_root': self.tr_url,
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_checkidSetupNoReturnOpenID2(self):
        """Make sure an OpenID 2 request with no return_to can be
        decoded, and make sure a response to such a request raises
        NoReturnToError.
        """
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.claimed_id': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.realm': self.tr_url,
        }
        self.assertIsInstance(self.decode(args), server.CheckIDRequest)

        req = self.decode(args)
        self.assertRaises(server.NoReturnToError, req.answer, False)
        self.assertRaises(server.NoReturnToError, req.encodeToURL, 'bogus')
        self.assertRaises(server.NoReturnToError, req.getCancelURL)

    def test_checkidSetupRealmRequiredOpenID2(self):
        """Make sure that an OpenID 2 request which lacks return_to
        cannot be decoded if it lacks a realm.  Spec: This value
        (openid.realm) MUST be sent if openid.return_to is omitted.
        """
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_checkidSetupBadReturn(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': 'not a url',
        }
        with self.assertRaises(server.ProtocolError) as catch:
            self.decode(args)
        self.assertTrue(catch.exception.openid_message)

    def test_checkidSetupUntrustedReturn(self):
        args = {
            'openid.mode': 'checkid_setup',
            'openid.identity': self.id_url,
            'openid.assoc_handle': self.assoc_handle,
            'openid.return_to': self.rt_url,
            'openid.trust_root': 'http://not-the-return-place.unittest/',
        }
        with self.assertRaises(server.UntrustedReturnURL) as catch:
            self.decode(args)
        self.assertTrue(catch.exception.openid_message)

    def test_checkAuth(self):
        args = {
            'openid.mode': 'check_authentication',
            'openid.assoc_handle': '{dumb}{handle}',
            'openid.sig': 'sigblob',
            'openid.signed': 'identity,return_to,response_nonce,mode',
            'openid.identity': 'signedval1',
            'openid.return_to': 'signedval2',
            'openid.response_nonce': 'signedval3',
            'openid.baz': 'unsigned',
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckAuthRequest)
        self.assertEqual(r.mode, 'check_authentication')
        self.assertEqual(r.message.getArg(OPENID_NS, 'sig'), 'sigblob')

    def test_checkAuthMissingSignature(self):
        args = {
            'openid.mode': 'check_authentication',
            'openid.assoc_handle': '{dumb}{handle}',
            'openid.signed': 'foo,bar,mode',
            'openid.foo': 'signedval1',
            'openid.bar': 'signedval2',
            'openid.baz': 'unsigned',
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_checkAuthAndInvalidate(self):
        args = {
            'openid.mode': 'check_authentication',
            'openid.assoc_handle': '{dumb}{handle}',
            'openid.invalidate_handle': '[[SMART_handle]]',
            'openid.sig': 'sigblob',
            'openid.signed': 'identity,return_to,response_nonce,mode',
            'openid.identity': 'signedval1',
            'openid.return_to': 'signedval2',
            'openid.response_nonce': 'signedval3',
            'openid.baz': 'unsigned',
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.CheckAuthRequest)
        self.assertEqual(r.invalidate_handle, '[[SMART_handle]]')

    def test_associateDH(self):
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "Rzup9265tw==",
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.AssociateRequest)
        self.assertEqual(r.mode, "associate")
        self.assertEqual(r.session.session_type, "DH-SHA1")
        self.assertEqual(r.assoc_type, "HMAC-SHA1")
        self.assertTrue(r.session.consumer_pubkey)

    def test_associateDHMissingKey(self):
        """Trying DH assoc w/o public key"""
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
        }
        # Using DH-SHA1 without supplying dh_consumer_public is an error.
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_associateDHpubKeyNotB64(self):
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "donkeydonkeydonkey",
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_associateDHModGen(self):
        # test dh with non-default but valid values for dh_modulus and dh_gen
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "Rzup9265tw==",
            'openid.dh_modulus': cryptutil.longToBase64(ALT_MODULUS),
            'openid.dh_gen': cryptutil.longToBase64(ALT_GEN),
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.AssociateRequest)
        self.assertEqual(r.mode, "associate")
        self.assertEqual(r.session.session_type, "DH-SHA1")
        self.assertEqual(r.assoc_type, "HMAC-SHA1")
        self.assertEqual(r.session.dh.modulus, ALT_MODULUS)
        self.assertEqual(r.session.dh.generator, ALT_GEN)
        self.assertTrue(r.session.consumer_pubkey)

    def test_associateDHCorruptModGen(self):
        # test dh with non-default but valid values for dh_modulus and dh_gen
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "Rzup9265tw==",
            'openid.dh_modulus': 'pizza',
            'openid.dh_gen': 'gnocchi',
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_associateDHMissingModGen(self):
        # test dh with non-default but valid values for dh_modulus and dh_gen
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "Rzup9265tw==",
            'openid.dh_modulus': 'pizza',
        }
        self.assertRaises(server.ProtocolError, self.decode, args)


#     def test_associateDHInvalidModGen(self):
#         # test dh with properly encoded values that are not a valid
#         #   modulus/generator combination.
#         args = {
#             'openid.mode': 'associate',
#             'openid.session_type': 'DH-SHA1',
#             'openid.dh_consumer_public': "Rzup9265tw==",
#             'openid.dh_modulus': cryptutil.longToBase64(9),
#             'openid.dh_gen': cryptutil.longToBase64(27) ,
#             }
#         self.assertRaises(server.ProtocolError, self.decode, args)
#     test_associateDHInvalidModGen.todo = "low-priority feature"

    def test_associateWeirdSession(self):
        args = {
            'openid.mode': 'associate',
            'openid.session_type': 'FLCL6',
            'openid.dh_consumer_public': "YQ==\n",
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_associatePlain(self):
        args = {
            'openid.mode': 'associate',
        }
        r = self.decode(args)
        self.assertIsInstance(r, server.AssociateRequest)
        self.assertEqual(r.mode, "associate")
        self.assertEqual(r.session.session_type, "no-encryption")
        self.assertEqual(r.assoc_type, "HMAC-SHA1")

    def test_nomode(self):
        args = {
            'openid.session_type': 'DH-SHA1',
            'openid.dh_consumer_public': "my public keeey",
        }
        self.assertRaises(server.ProtocolError, self.decode, args)

    def test_invalidns(self):
        args = {'openid.ns': 'Tuesday',
                'openid.mode': 'associate'}

        with six.assertRaisesRegex(self, server.ProtocolError, 'Tuesday') as catch:
            self.decode(args)
        self.assertTrue(catch.exception.openid_message)


class TestEncode(unittest.TestCase):
    def setUp(self):
        self.encoder = server.Encoder()
        self.encode = self.encoder.encode
        self.op_endpoint = 'http://endpoint.unittest/encode'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)

    def test_id_res_OpenID2_GET(self):
        """
        Check that when an OpenID 2 response does not exceed the
        OpenID 1 message size, a GET response (i.e., redirect) is
        issued.
        """
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'ns': OPENID2_NS,
            'mode': 'id_res',
            'identity': request.identity,
            'claimed_id': request.identity,
            'return_to': request.return_to,
        })

        self.assertFalse(response.renderAsForm())
        self.assertEqual(response.whichEncoding(), server.ENCODE_URL)
        webresponse = self.encode(response)
        self.assertIn('location', webresponse.headers)

    def test_id_res_OpenID2_POST(self):
        """
        Check that when an OpenID 2 response exceeds the OpenID 1
        message size, a POST response (i.e., an HTML form) is
        returned.
        """
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'ns': OPENID2_NS,
            'mode': 'id_res',
            'identity': request.identity,
            'claimed_id': request.identity,
            'return_to': 'x' * OPENID1_URL_LIMIT,
        })

        self.assertTrue(response.renderAsForm())
        self.assertGreater(len(response.encodeToURL()), OPENID1_URL_LIMIT)
        self.assertEqual(response.whichEncoding(), server.ENCODE_HTML_FORM)
        webresponse = self.encode(response)
        self.assertIn(response.toFormMarkup(), webresponse.body)

    def test_toFormMarkup(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'ns': OPENID2_NS,
            'mode': 'id_res',
            'identity': request.identity,
            'claimed_id': request.identity,
            'return_to': 'x' * OPENID1_URL_LIMIT,
        })

        form_markup = response.toFormMarkup({'foo': 'bar'})
        self.assertIn(' foo="bar"', form_markup)

    def test_toHTML(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'ns': OPENID2_NS,
            'mode': 'id_res',
            'identity': request.identity,
            'claimed_id': request.identity,
            'return_to': 'x' * OPENID1_URL_LIMIT,
        })
        html = response.toHTML()
        self.assertIn('<html>', html)
        self.assertIn('</html>', html)
        self.assertIn('<body onload=', html)
        self.assertIn('<form', html)
        self.assertIn(EXAMPLE_IDENTITY, html)

    def test_id_res_OpenID1_exceeds_limit(self):
        """
        Check that when an OpenID 1 response exceeds the OpenID 1
        message size, a GET response is issued.  Technically, this
        shouldn't be permitted by the library, but this test is in
        place to preserve the status quo for OpenID 1.
        """
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'identity': request.identity,
            'return_to': 'x' * OPENID1_URL_LIMIT,
        })

        self.assertFalse(response.renderAsForm())
        self.assertGreater(len(response.encodeToURL()), OPENID1_URL_LIMIT)
        self.assertEqual(response.whichEncoding(), server.ENCODE_URL)
        webresponse = self.encode(response)
        self.assertEqual(webresponse.headers['location'], response.encodeToURL())

    def test_id_res(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'identity': request.identity,
            'return_to': request.return_to,
        })
        webresponse = self.encode(response)
        self.assertEqual(webresponse.code, server.HTTP_REDIRECT)
        self.assertIn('location', webresponse.headers)

        location = webresponse.headers['location']
        self.assertTrue(location.startswith(request.return_to),
                        "%s does not start with %s" % (location, request.return_to))
        # argh.
        q2 = dict(parse_qsl(urlparse(location)[4]))
        expected = response.fields.toPostArgs()
        self.assertEqual(q2, expected)

    def test_cancel(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'mode': 'cancel',
        })
        webresponse = self.encode(response)
        self.assertEqual(webresponse.code, server.HTTP_REDIRECT)
        self.assertIn('location', webresponse.headers)

    def test_cancelToForm(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'mode': 'cancel',
        })
        form = response.toFormMarkup()
        self.assertTrue(form)

    def test_assocReply(self):
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID2_NS, 'session_type', 'no-encryption')
        msg.setArg(OPENID2_NS, 'assoc_type', 'HMAC-SHA1')
        request = server.AssociateRequest.fromMessage(msg)
        response = server.OpenIDResponse(request)
        response.fields = Message.fromPostArgs(
            {'openid.assoc_handle': "every-zig"})
        webresponse = self.encode(response)
        body = """assoc_handle:every-zig
"""
        self.assertEqual(webresponse.code, server.HTTP_OK)
        self.assertEqual(webresponse.headers, {})
        self.assertEqual(webresponse.body, body)

    def test_checkauthReply(self):
        request = server.CheckAuthRequest('a_sock_monkey', 'siggggg')
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'is_valid': 'true',
            'invalidate_handle': 'xXxX:xXXx'
        })
        body = """invalidate_handle:xXxX:xXXx
is_valid:true
"""
        webresponse = self.encode(response)
        self.assertEqual(webresponse.code, server.HTTP_OK)
        self.assertEqual(webresponse.headers, {})
        self.assertEqual(webresponse.body, body)

    def test_unencodableError(self):
        args = Message.fromPostArgs({
            'openid.identity': 'http://limu.unittest/',
        })
        e = server.ProtocolError(args, "wet paint")
        self.assertRaises(server.EncodingError, self.encode, e)

    def test_encodableError(self):
        args = Message.fromPostArgs({
            'openid.mode': 'associate',
            'openid.identity': 'http://limu.unittest/',
        })
        body = "error:snoot\nmode:error\n"
        webresponse = self.encode(server.ProtocolError(args, "snoot"))
        self.assertEqual(webresponse.code, server.HTTP_ERROR)
        self.assertEqual(webresponse.headers, {})
        self.assertEqual(webresponse.body, body)


class TestSigningEncode(unittest.TestCase):
    def setUp(self):
        self._dumb_key = server.Signatory._dumb_key
        self._normal_key = server.Signatory._normal_key
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, "http://signing.unittest/enc")
        self.request = make_checkid_request()
        self.response = server.OpenIDResponse(self.request)
        self.response.fields = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'identity': self.request.identity,
            'return_to': self.request.return_to,
        })
        self.signatory = server.Signatory(self.store)
        self.encoder = server.SigningEncoder(self.signatory)
        self.encode = self.encoder.encode

    def test_idres(self):
        assoc_handle = '{bicycle}{shed}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1'))
        self.request.assoc_handle = assoc_handle
        webresponse = self.encode(self.response)
        self.assertEqual(webresponse.code, server.HTTP_REDIRECT)
        self.assertIn('location', webresponse.headers)

        location = webresponse.headers['location']
        query = parse_qs(urlparse(location)[4])
        self.assertIn('openid.sig', query)
        self.assertIn('openid.assoc_handle', query)
        self.assertIn('openid.signed', query)

    def test_idresDumb(self):
        webresponse = self.encode(self.response)
        self.assertEqual(webresponse.code, server.HTTP_REDIRECT)
        self.assertIn('location', webresponse.headers)

        location = webresponse.headers['location']
        query = parse_qs(urlparse(location)[4])
        self.assertIn('openid.sig', query)
        self.assertIn('openid.assoc_handle', query)
        self.assertIn('openid.signed', query)

    def test_forgotStore(self):
        self.encoder.signatory = None
        self.assertRaises(ValueError, self.encode, self.response)

    def test_cancel(self):
        request = make_checkid_request()
        response = server.OpenIDResponse(request)
        response.fields.setArg(OPENID_NS, 'mode', 'cancel')
        webresponse = self.encode(response)
        self.assertEqual(webresponse.code, server.HTTP_REDIRECT)
        self.assertIn('location', webresponse.headers)
        location = webresponse.headers['location']
        query = parse_qs(urlparse(location)[4])
        self.assertNotIn('openid.sig', query, response.fields.toPostArgs())

    def test_assocReply(self):
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID2_NS, 'session_type', 'no-encryption')
        msg.setArg(OPENID2_NS, 'assoc_type', 'HMAC-SHA1')
        request = server.AssociateRequest.fromMessage(msg)
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({'assoc_handle': "every-zig"})
        webresponse = self.encode(response)
        body = """assoc_handle:every-zig
"""
        self.assertEqual(webresponse.code, server.HTTP_OK)
        self.assertEqual(webresponse.headers, {})
        self.assertEqual(webresponse.body, body)

    def test_alreadySigned(self):
        self.response.fields.setArg(OPENID_NS, 'sig', 'priorSig==')
        self.assertRaises(server.AlreadySigned, self.encode, self.response)


class TestCheckID(unittest.TestCase):
    def setUp(self):
        self.op_endpoint = 'http://endpoint.unittest/'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)
        self.request = make_checkid_request(op_endpoint=self.op_endpoint)

    def test_openid2_requires_provider(self):
        with six.assertRaisesRegex(self, ValueError, 'CheckIDRequest requires op_endpoint'):
            server.CheckIDRequest(sentinel.identity, sentinel.return_to, claimed_id=sentinel.claimed_id,
                                  message=Message(OPENID2_NS))

    def test_trustRootInvalid(self):
        self.request.trust_root = "http://foo.unittest/17"
        self.request.return_to = "http://foo.unittest/39"
        self.assertFalse(self.request.trustRootValid())

    def test_trustRootValid(self):
        self.request.trust_root = "http://foo.unittest/"
        self.request.return_to = "http://foo.unittest/39"
        self.assertTrue(self.request.trustRootValid())

    def test_malformedTrustRoot(self):
        self.request.trust_root = "invalid://trust*root/"
        self.request.return_to = "http://foo.unittest/39"
        sentinel = object()
        self.request.message = sentinel
        with self.assertRaises(server.MalformedTrustRoot) as catch:
            self.request.trustRootValid()
        self.assertEqual(catch.exception.openid_message, sentinel)

    def test_trustRootValidNoReturnTo(self):
        request = server.CheckIDRequest(
            identity='http://bambam.unittest/',
            claimed_id=EXAMPLE_CLAIMED_ID,
            trust_root='http://bar.unittest/',
            return_to=None,
            immediate=False,
            op_endpoint=self.server.op_endpoint,
        )

        self.assertTrue(request.trustRootValid())

    def test_returnToVerified_callsVerify(self):
        """Make sure that verifyReturnTo is calling the trustroot
        function verifyReturnTo
        """
        def withVerifyReturnTo(new_verify, callable):
            old_verify = server.verifyReturnTo
            try:
                server.verifyReturnTo = new_verify
                return callable()
            finally:
                server.verifyReturnTo = old_verify

        # Ensure that exceptions are passed through
        sentinel = Exception()

        def vrfyExc(trust_root, return_to):
            self.assertEqual(trust_root, self.request.trust_root)
            self.assertEqual(return_to, self.request.return_to)
            raise sentinel

        with self.assertRaises(Exception) as catch:
            withVerifyReturnTo(vrfyExc, self.request.returnToVerified)
        self.assertEqual(catch.exception, sentinel)

        # Ensure that True and False are passed through unchanged
        def constVerify(val):
            def verify(trust_root, return_to):
                self.assertEqual(trust_root, self.request.trust_root)
                self.assertEqual(return_to, self.request.return_to)
                return val
            return verify

        for val in [True, False]:
            self.assertEqual(withVerifyReturnTo(constVerify(val), self.request.returnToVerified), val)

    def _expectAnswer(self, answer, identity=None, claimed_id=None):
        expected_list = [
            ('mode', 'id_res'),
            ('return_to', self.request.return_to),
            ('op_endpoint', self.op_endpoint),
        ]
        if identity:
            expected_list.append(('identity', identity))
            if claimed_id:
                expected_list.append(('claimed_id', claimed_id))
            else:
                expected_list.append(('claimed_id', identity))

        for k, expected in expected_list:
            actual = answer.fields.getArg(OPENID_NS, k)
            self.assertEqual(actual, expected, "%s: expected %s, got %s" % (k, expected, actual))

        self.assertTrue(answer.fields.hasKey(OPENID_NS, 'response_nonce'))
        self.assertEqual(answer.fields.getOpenIDNamespace(), OPENID2_NS)

        # One for nonce, one for ns
        self.assertEqual(len(answer.fields.toPostArgs()), len(expected_list) + 2)

    def test_answerAllow(self):
        """Check the fields specified by "Positive Assertions"

        including mode=id_res, identity, claimed_id, op_endpoint, return_to
        """
        answer = self.request.answer(True)
        self.assertEqual(answer.request, self.request)
        self._expectAnswer(answer, self.request.identity, EXAMPLE_CLAIMED_ID)

    def test_answerAllowDelegatedIdentity(self):
        self.request.claimed_id = 'http://delegating.unittest/'
        answer = self.request.answer(True)
        self._expectAnswer(answer, self.request.identity,
                           self.request.claimed_id)

    def test_answerAllowDelegatedIdentity2(self):
        # This time with the identity argument explicitly passed in to
        # answer()
        self.request.claimed_id = 'http://delegating.unittest/'
        answer = self.request.answer(True, identity=EXAMPLE_IDENTITY)
        self._expectAnswer(answer, self.request.identity,
                           self.request.claimed_id)

    def test_answerAllowWithoutIdentityReally(self):
        self.request.identity = None
        answer = self.request.answer(True)
        self.assertEqual(answer.request, self.request)
        self._expectAnswer(answer)

    def test_answerAllowAnonymousFail(self):
        self.request.identity = None
        # XXX - Check on this, I think this behavior is legal in OpenID 2.0?
        self.assertRaises(ValueError, self.request.answer, True, identity="=V")

    def test_answerAllowWithIdentity(self):
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        answer = self.request.answer(True, identity=selected_id)
        self._expectAnswer(answer, selected_id)

    def test_answerAllowWithDelegatedIdentityOpenID2(self):
        """Answer an IDENTIFIER_SELECT case with a delegated identifier.
        """
        # claimed_id delegates to selected_id here.
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        claimed_id = 'http://monkeyhat.unittest/'
        answer = self.request.answer(True, identity=selected_id,
                                     claimed_id=claimed_id)
        self._expectAnswer(answer, selected_id, claimed_id)

    def test_answerAllowWithDelegatedIdentityOpenID1(self):
        """claimed_id parameter doesn't exist in OpenID 1.
        """
        self.request.message = Message(OPENID1_NS)
        # claimed_id delegates to selected_id here.
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        claimed_id = 'http://monkeyhat.unittest/'
        self.assertRaises(server.VersionError, self.request.answer, True, identity=selected_id, claimed_id=claimed_id)

    def test_answerAllowWithAnotherIdentity(self):
        # XXX - Check on this, I think this behavior is legal in OpenID 2.0?
        self.assertRaises(ValueError, self.request.answer, True, identity="http://pebbles.unittest/")

    def test_answerAllowWithIdentityNormalization(self):
        # The RP has sent us a non-normalized value for openid.identity,
        # and the library user is passing an explicit value for identity
        # to CheckIDRequest.answer.
        non_normalized = 'http://bambam.unittest'
        normalized = non_normalized + '/'

        self.request.identity = non_normalized
        self.request.claimed_id = non_normalized

        answer = self.request.answer(True, identity=normalized)

        # Expect the values that were sent in the request, even though
        # they're not normalized.
        self._expectAnswer(answer, identity=non_normalized,
                           claimed_id=non_normalized)

    def test_answerAllowNoIdentityOpenID1(self):
        self.request.message = Message(OPENID1_NS)
        self.request.identity = None
        self.assertRaises(ValueError, self.request.answer, True, identity=None)

    def test_answerAllowForgotEndpoint(self):
        self.request.op_endpoint = None
        self.assertRaises(RuntimeError, self.request.answer, True)

    def test_checkIDWithNoIdentityOpenID1(self):
        msg = Message(OPENID1_NS)
        msg.setArg(OPENID_NS, 'return_to', 'bogus')
        msg.setArg(OPENID_NS, 'trust_root', 'bogus')
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')

        self.assertRaises(server.ProtocolError, server.CheckIDRequest.fromMessage, msg, self.op_endpoint)

    def test_fromMessageClaimedIDWithoutIdentityOpenID2(self):
        name = 'https://example.myopenid.com'

        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'return_to', 'http://invalid:8000/rt')
        msg.setArg(OPENID_NS, 'claimed_id', name)

        self.assertRaises(server.ProtocolError, server.CheckIDRequest.fromMessage, msg, self.op_endpoint)

    def test_fromMessageIdentityWithoutClaimedIDOpenID2(self):
        name = 'https://example.myopenid.com'

        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'return_to', 'http://invalid:8000/rt')
        msg.setArg(OPENID_NS, 'identity', name)

        self.assertRaises(server.ProtocolError, server.CheckIDRequest.fromMessage, msg, self.op_endpoint)

    def test_trustRootOpenID1(self):
        """Ignore openid.realm in OpenID 1"""
        msg = Message(OPENID1_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'trust_root', 'http://real_trust_root/')
        msg.setArg(OPENID_NS, 'realm', 'http://fake_trust_root/')
        msg.setArg(OPENID_NS, 'return_to', 'http://real_trust_root/foo')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        self.assertEqual(result.trust_root, 'http://real_trust_root/')

    def test_trustRootOpenID2(self):
        """Ignore openid.trust_root in OpenID 2"""
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'realm', 'http://real_trust_root/')
        msg.setArg(OPENID_NS, 'trust_root', 'http://fake_trust_root/')
        msg.setArg(OPENID_NS, 'return_to', 'http://real_trust_root/foo')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')
        msg.setArg(OPENID_NS, 'claimed_id', 'george')

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        self.assertEqual(result.trust_root, 'http://real_trust_root/')

    def test_answerAllowNoTrustRoot(self):
        self.request.trust_root = None
        answer = self.request.answer(True)
        self.assertEqual(answer.request, self.request)
        self._expectAnswer(answer, self.request.identity, EXAMPLE_CLAIMED_ID)

    def test_fromMessageWithoutTrustRoot(self):
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'return_to', 'http://real_trust_root/foo')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')
        msg.setArg(OPENID_NS, 'claimed_id', 'george')

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        self.assertEqual(result.trust_root, 'http://real_trust_root/foo')

    def test_fromMessageWithEmptyTrustRoot(self):
        return_to = u'http://someplace.invalid/?go=thing'
        msg = Message.fromPostArgs({
            u'openid.assoc_handle': u'{blah}{blah}{OZivdQ==}',
            u'openid.claimed_id': u'http://delegated.invalid/',
            u'openid.identity': u'http://op-local.example.com/',
            u'openid.mode': u'checkid_setup',
            u'openid.ns': u'http://openid.net/signon/1.0',
            u'openid.return_to': return_to,
            u'openid.trust_root': u''})

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        self.assertEqual(result.trust_root, return_to)

    def test_fromMessageWithoutTrustRootOrReturnTo(self):
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')
        msg.setArg(OPENID_NS, 'claimed_id', 'george')

        self.assertRaises(server.ProtocolError, server.CheckIDRequest.fromMessage, msg, self.server.op_endpoint)

    def test_answerAllowNoEndpointOpenID1(self):
        """Test .allow() with an OpenID 1.x Message on a CheckIDRequest
        built without an op_endpoint parameter.
        """
        identity = 'http://bambam.unittest/'
        reqmessage = Message.fromOpenIDArgs({
            'mode': 'checkid_setup',
            'identity': identity,
            'trust_root': 'http://bar.unittest/',
            'return_to': 'http://bar.unittest/999',
        })
        self.request = server.CheckIDRequest.fromMessage(reqmessage, None)
        answer = self.request.answer(True)

        expected_list = [
            ('mode', 'id_res'),
            ('return_to', self.request.return_to),
            ('identity', identity),
        ]

        for k, expected in expected_list:
            actual = answer.fields.getArg(OPENID_NS, k)
            self.assertEqual(actual, expected, "%s: expected %s, got %s" % (k, expected, actual))

        self.assertTrue(answer.fields.hasKey(OPENID_NS, 'response_nonce'))
        self.assertEqual(answer.fields.getOpenIDNamespace(), OPENID1_NS)
        self.assertTrue(answer.fields.namespaces.isImplicit(OPENID1_NS))

        # One for nonce (OpenID v1 namespace is implicit)
        self.assertEqual(len(answer.fields.toPostArgs()), len(expected_list) + 1)

    def test_answerImmediateDenyOpenID2(self):
        """Look for mode=setup_needed in checkid_immediate negative
        response in OpenID 2 case.

        See specification Responding to Authentication Requests /
        Negative Assertions / In Response to Immediate Requests.
        """
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        self.request.claimed_id = 'http://claimed-id.test/'
        server_url = "http://setup-url.unittest/"
        # crappiting setup_url, you dirty my interface with your presence!
        answer = self.request.answer(False, server_url=server_url)
        self.assertEqual(answer.request, self.request)
        self.assertEqual(len(answer.fields.toPostArgs()), 3, answer.fields)
        self.assertEqual(answer.fields.getOpenIDNamespace(), OPENID2_NS)
        self.assertEqual(answer.fields.getArg(OPENID_NS, 'mode'), 'setup_needed')

        usu = answer.fields.getArg(OPENID_NS, 'user_setup_url')
        expected_substr = 'openid.claimed_id=http%3A%2F%2Fclaimed-id.test%2F'
        self.assertIn(expected_substr, usu)

    def test_answerImmediateDenyOpenID1(self):
        """Look for user_setup_url in checkid_immediate negative
        response in OpenID 1 case."""
        self.request.message = Message(OPENID1_NS)
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        server_url = "http://setup-url.unittest/"
        # crappiting setup_url, you dirty my interface with your presence!
        answer = self.request.answer(False, server_url=server_url)
        self.assertEqual(answer.request, self.request)
        self.assertEqual(len(answer.fields.toPostArgs()), 2, answer.fields)
        self.assertEqual(answer.fields.getOpenIDNamespace(), OPENID1_NS)
        self.assertTrue(answer.fields.namespaces.isImplicit(OPENID1_NS))
        self.assertEqual(answer.fields.getArg(OPENID_NS, 'mode'), 'id_res')
        self.assertTrue(answer.fields.getArg(OPENID_NS, 'user_setup_url', '').startswith(server_url))

    def test_answerSetupDeny(self):
        answer = self.request.answer(False)
        self.assertEqual(answer.fields.getArgs(OPENID_NS), {'mode': 'cancel'})

    def test_encodeToURL(self):
        server_url = 'http://openid-server.unittest/'
        result = self.request.encodeToURL(server_url)

        # How to check?  How about a round-trip test.
        base, result_args = result.split('?', 1)
        result_args = dict(parse_qsl(result_args))
        message = Message.fromPostArgs(result_args)
        rebuilt_request = server.CheckIDRequest.fromMessage(message,
                                                            self.server.op_endpoint)
        # argh, lousy hack
        self.request.message = message
        self.assertEqual(rebuilt_request.__dict__, self.request.__dict__)

    def test_getCancelURL(self):
        url = self.request.getCancelURL()
        rt, query_string = url.split('?')
        self.assertEqual(self.request.return_to, rt)
        query = dict(parse_qsl(query_string))
        self.assertEqual(query, {'openid.mode': 'cancel', 'openid.ns': OPENID2_NS})

    def test_getCancelURLimmed(self):
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        self.assertRaises(ValueError, self.request.getCancelURL)


class TestCheckIDExtension(unittest.TestCase):

    def setUp(self):
        self.op_endpoint = 'http://endpoint.unittest/ext'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)
        self.request = make_checkid_request(op_endpoint=self.op_endpoint)
        self.response = server.OpenIDResponse(self.request)
        self.response.fields.setArg(OPENID_NS, 'mode', 'id_res')
        self.response.fields.setArg(OPENID_NS, 'blue', 'star')

    def test_addField(self):
        namespace = 'something:'
        self.response.fields.setArg(namespace, 'bright', 'potato')
        self.assertEqual(self.response.fields.getArgs(OPENID_NS), {'blue': 'star', 'mode': 'id_res'})
        self.assertEqual(self.response.fields.getArgs(namespace), {'bright': 'potato'})

    def test_addFields(self):
        namespace = 'mi5:'
        args = {'tangy': 'suspenders',
                'bravo': 'inclusion'}
        self.response.fields.updateArgs(namespace, args)
        self.assertEqual(self.response.fields.getArgs(OPENID_NS), {'blue': 'star', 'mode': 'id_res'})
        self.assertEqual(self.response.fields.getArgs(namespace), args)


class MockSignatory(object):
    isValid = True

    def __init__(self, assoc):
        self.assocs = [assoc]

    def verify(self, assoc_handle, message):
        assert message.hasKey(OPENID_NS, "sig")
        if (True, assoc_handle) in self.assocs:
            return self.isValid
        else:
            return False

    def getAssociation(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            # This isn't a valid implementation for many uses of this
            # function, mind you.
            return True
        else:
            return None

    def invalidate(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            self.assocs.remove((dumb, assoc_handle))


class TestCheckAuth(unittest.TestCase):
    def setUp(self):
        self.assoc_handle = 'mooooooooo'
        self.message = Message.fromPostArgs({
            'openid.sig': 'signarture',
            'one': 'alpha',
            'two': 'beta',
        })
        self.request = server.CheckAuthRequest(
            self.assoc_handle, self.message)

        self.signatory = MockSignatory((True, self.assoc_handle))

    def test_valid(self):
        r = self.request.answer(self.signatory)
        self.assertEqual(r.fields.getArgs(OPENID_NS), {'is_valid': 'true'})
        self.assertEqual(r.request, self.request)

    def test_invalid(self):
        self.signatory.isValid = False
        r = self.request.answer(self.signatory)
        self.assertEqual(r.fields.getArgs(OPENID_NS), {'is_valid': 'false'})

    def test_replay(self):
        """Don't validate the same response twice.

        From "Checking the Nonce"::

            When using "check_authentication", the OP MUST ensure that an
            assertion has not yet been accepted with the same value for
            "openid.response_nonce".

        In this implementation, the assoc_handle is only valid once.  And
        nonces are a signed component of the message, so they can't be used
        with another handle without breaking the sig.
        """
        r = self.request.answer(self.signatory)
        r = self.request.answer(self.signatory)
        self.assertEqual(r.fields.getArgs(OPENID_NS), {'is_valid': 'false'})

    def test_invalidatehandle(self):
        self.request.invalidate_handle = "bogusHandle"
        r = self.request.answer(self.signatory)
        self.assertEqual(r.fields.getArgs(OPENID_NS), {'is_valid': 'true', 'invalidate_handle': "bogusHandle"})
        self.assertEqual(r.request, self.request)

    def test_invalidatehandleNo(self):
        assoc_handle = 'goodhandle'
        self.signatory.assocs.append((False, 'goodhandle'))
        self.request.invalidate_handle = assoc_handle
        r = self.request.answer(self.signatory)
        self.assertEqual(r.fields.getArgs(OPENID_NS), {'is_valid': 'true'})


class TestAssociate(unittest.TestCase):
    # TODO: test DH with non-default values for modulus and gen.
    # (important to do because we actually had it broken for a while.)

    def setUp(self):
        self.request = server.AssociateRequest.fromMessage(
            Message.fromPostArgs({}))
        self.store = memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)

    def test_dhSHA1(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA1')
        from openid.dh import DiffieHellman
        from openid.server.server import DiffieHellmanSHA1ServerSession
        consumer_dh = DiffieHellman.fromDefaults()
        cpub = cryptutil.base64ToLong(consumer_dh.public_key)
        server_dh = DiffieHellman.fromDefaults()
        session = DiffieHellmanSHA1ServerSession(server_dh, cpub)
        self.request = server.AssociateRequest(session, 'HMAC-SHA1')
        response = self.request.answer(self.assoc)

        rfg = partial(response.fields.getArg, OPENID_NS)
        self.assertEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.assertEqual(rfg("assoc_handle"), self.assoc.handle)
        self.assertFalse(rfg("mac_key"))
        self.assertEqual(rfg("session_type"), "DH-SHA1")
        self.assertTrue(rfg("enc_mac_key"))
        self.assertTrue(rfg("dh_server_public"))

        enc_key = oidutil.fromBase64(rfg("enc_mac_key"))
        spub = cryptutil.base64ToLong(rfg("dh_server_public"))
        secret = consumer_dh.xorSecret(spub, enc_key, cryptutil.sha1)
        self.assertEqual(secret, self.assoc.secret)

    def test_dhSHA256(self):
        self.assoc = self.signatory.createAssociation(
            dumb=False, assoc_type='HMAC-SHA256')
        from openid.dh import DiffieHellman
        from openid.server.server import DiffieHellmanSHA256ServerSession
        consumer_dh = DiffieHellman.fromDefaults()
        cpub = cryptutil.base64ToLong(consumer_dh.public_key)
        server_dh = DiffieHellman.fromDefaults()
        session = DiffieHellmanSHA256ServerSession(server_dh, cpub)
        self.request = server.AssociateRequest(session, 'HMAC-SHA256')
        response = self.request.answer(self.assoc)

        rfg = partial(response.fields.getArg, OPENID_NS)
        self.assertEqual(rfg("assoc_type"), "HMAC-SHA256")
        self.assertEqual(rfg("assoc_handle"), self.assoc.handle)
        self.assertFalse(rfg("mac_key"))
        self.assertEqual(rfg("session_type"), "DH-SHA256")
        self.assertTrue(rfg("enc_mac_key"))
        self.assertTrue(rfg("dh_server_public"))

        enc_key = oidutil.fromBase64(rfg("enc_mac_key"))
        spub = cryptutil.base64ToLong(rfg("dh_server_public"))
        secret = consumer_dh.xorSecret(spub, enc_key, cryptutil.sha256)
        self.assertEqual(secret, self.assoc.secret)

    def test_protoError256(self):
        s256_session = DiffieHellmanSHA256ConsumerSession()

        invalid_s256 = {'openid.assoc_type': 'HMAC-SHA1', 'openid.session_type': 'DH-SHA256'}
        invalid_s256.update(s256_session.getRequest())

        invalid_s256_2 = {'openid.assoc_type': 'MONKEY-PIRATE', 'openid.session_type': 'DH-SHA256'}
        invalid_s256_2.update(s256_session.getRequest())

        bad_request_argss = [
            invalid_s256,
            invalid_s256_2,
        ]

        for request_args in bad_request_argss:
            message = Message.fromPostArgs(request_args)
            self.assertRaises(server.ProtocolError, server.AssociateRequest.fromMessage, message)

    def test_protoError(self):
        from openid.consumer.consumer import DiffieHellmanSHA1ConsumerSession

        s1_session = DiffieHellmanSHA1ConsumerSession()

        invalid_s1 = {'openid.assoc_type': 'HMAC-SHA256', 'openid.session_type': 'DH-SHA1'}
        invalid_s1.update(s1_session.getRequest())

        invalid_s1_2 = {'openid.assoc_type': 'ROBOT-NINJA', 'openid.session_type': 'DH-SHA1'}
        invalid_s1_2.update(s1_session.getRequest())

        bad_request_argss = [
            {'openid.assoc_type': 'Wha?'},
            invalid_s1,
            invalid_s1_2,
        ]

        for request_args in bad_request_argss:
            message = Message.fromPostArgs(request_args)
            self.assertRaises(server.ProtocolError, server.AssociateRequest.fromMessage, message)

    def test_protoErrorFields(self):

        contact = 'user@example.invalid'
        reference = 'Trac ticket number MAX_INT'
        error = 'poltergeist'

        openid1_args = {
            'openid.identitiy': 'invalid',
            'openid.mode': 'checkid_setup',
        }

        openid2_args = dict(openid1_args)
        openid2_args.update({'openid.ns': OPENID2_NS})

        # Check presence of optional fields in both protocol versions

        openid1_msg = Message.fromPostArgs(openid1_args)
        p = server.ProtocolError(openid1_msg, error,
                                 contact=contact, reference=reference)
        reply = p.toMessage()

        self.assertEqual(reply.getArg(OPENID_NS, 'reference'), reference)
        self.assertEqual(reply.getArg(OPENID_NS, 'contact'), contact)

        openid2_msg = Message.fromPostArgs(openid2_args)
        p = server.ProtocolError(openid2_msg, error,
                                 contact=contact, reference=reference)
        reply = p.toMessage()

        self.assertEqual(reply.getArg(OPENID_NS, 'reference'), reference)
        self.assertEqual(reply.getArg(OPENID_NS, 'contact'), contact)

    def assertExpiresIn(self, msg, expected_expires_in):
        expires_in_str = msg.getArg(OPENID_NS, 'expires_in', no_default)
        expires_in = int(expires_in_str)

        # Slop is necessary because the tests can sometimes get run
        # right on a second boundary
        slop = 1  # second
        difference = expected_expires_in - expires_in

        error_message = ('"expires_in" value not within %s of expected: '
                         'expected=%s, actual=%s' %
                         (slop, expected_expires_in, expires_in))
        self.assertTrue(0 <= difference <= slop, error_message)

    def test_plaintext(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA1')
        response = self.request.answer(self.assoc)

        rfg = partial(response.fields.getArg, OPENID_NS)

        self.assertEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.assertEqual(rfg("assoc_handle"), self.assoc.handle)

        self.assertExpiresIn(response.fields, self.signatory.SECRET_LIFETIME)

        self.assertEqual(rfg("mac_key"), oidutil.toBase64(self.assoc.secret))
        self.assertFalse(rfg("session_type"))
        self.assertFalse(rfg("enc_mac_key"))
        self.assertFalse(rfg("dh_server_public"))

    def test_plaintext_v2(self):
        # The main difference between this and the v1 test is that
        # session_type is always returned in v2.
        args = {
            'openid.ns': OPENID2_NS,
            'openid.mode': 'associate',
            'openid.assoc_type': 'HMAC-SHA1',
            'openid.session_type': 'no-encryption',
        }
        self.request = server.AssociateRequest.fromMessage(
            Message.fromPostArgs(args))

        self.assertFalse(self.request.message.isOpenID1())

        self.assoc = self.signatory.createAssociation(
            dumb=False, assoc_type='HMAC-SHA1')
        response = self.request.answer(self.assoc)

        rfg = partial(response.fields.getArg, OPENID_NS)

        self.assertEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.assertEqual(rfg("assoc_handle"), self.assoc.handle)

        self.assertExpiresIn(response.fields, self.signatory.SECRET_LIFETIME)

        self.assertEqual(rfg("mac_key"), oidutil.toBase64(self.assoc.secret))

        self.assertEqual(rfg("session_type"), "no-encryption")
        self.assertFalse(rfg("enc_mac_key"))
        self.assertFalse(rfg("dh_server_public"))

    def test_plaintext256(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA256')
        response = self.request.answer(self.assoc)

        rfg = partial(response.fields.getArg, OPENID_NS)

        self.assertEqual(rfg("assoc_type"), "HMAC-SHA1")
        self.assertEqual(rfg("assoc_handle"), self.assoc.handle)

        self.assertExpiresIn(response.fields, self.signatory.SECRET_LIFETIME)

        self.assertEqual(rfg("mac_key"), oidutil.toBase64(self.assoc.secret))
        self.assertFalse(rfg("session_type"))
        self.assertFalse(rfg("enc_mac_key"))
        self.assertFalse(rfg("dh_server_public"))

    def test_unsupportedPrefer(self):
        allowed_assoc = 'COLD-PET-RAT'
        allowed_sess = 'FROG-BONES'
        message = 'This is a unit test'

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        self.request.message = Message(OPENID2_NS)

        response = self.request.answerUnsupported(
            message=message,
            preferred_session_type=allowed_sess,
            preferred_association_type=allowed_assoc,
        )

        rfg = partial(response.fields.getArg, OPENID_NS)
        self.assertEqual(rfg('error_code'), 'unsupported-type')
        self.assertEqual(rfg('assoc_type'), allowed_assoc)
        self.assertEqual(rfg('error'), message)
        self.assertEqual(rfg('session_type'), allowed_sess)

    def test_unsupported(self):
        message = 'This is a unit test'

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        self.request.message = Message(OPENID2_NS)

        response = self.request.answerUnsupported(message)

        rfg = partial(response.fields.getArg, OPENID_NS)
        self.assertEqual(rfg('error_code'), 'unsupported-type')
        self.assertIsNone(rfg('assoc_type'))
        self.assertEqual(rfg('error'), message)
        self.assertIsNone(rfg('session_type'))


class Counter(object):
    def __init__(self):
        self.count = 0

    def inc(self):
        self.count += 1


class TestServer(unittest.TestCase):
    def setUp(self):
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, "http://server.unittest/endpt")

    def test_dispatch(self):
        monkeycalled = Counter()

        def monkeyDo(request):
            monkeycalled.inc()
            r = server.OpenIDResponse(request)
            return r
        self.server.openid_monkeymode = monkeyDo
        request = server.OpenIDRequest(Message(OPENID1_NS))
        request.mode = "monkeymode"
        self.server.handleRequest(request)
        self.assertEqual(monkeycalled.count, 1)

    def test_associate(self):
        request = server.AssociateRequest.fromMessage(Message.fromPostArgs({}))
        response = self.server.openid_associate(request)
        self.assertTrue(response.fields.hasKey(OPENID_NS, "assoc_handle"),
                        "No assoc_handle here: %s" % (response.fields,))

    def test_associate2(self):
        """Associate when the server has no allowed association types

        Gives back an error with error_code and no fallback session or
        assoc types."""
        self.server.negotiator.setAllowedTypes([])

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        msg = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.session_type': 'no-encryption',
            'openid.assoc_type': 'HMAC-SHA1',
        })

        request = server.AssociateRequest.fromMessage(msg)

        response = self.server.openid_associate(request)
        self.assertTrue(response.fields.hasKey(OPENID_NS, "error"))
        self.assertTrue(response.fields.hasKey(OPENID_NS, "error_code"))
        self.assertFalse(response.fields.hasKey(OPENID_NS, "assoc_handle"))
        self.assertFalse(response.fields.hasKey(OPENID_NS, "assoc_type"))
        self.assertFalse(response.fields.hasKey(OPENID_NS, "session_type"))

    def test_associate3(self):
        """Request an assoc type that is not supported when there are
        supported types.

        Should give back an error message with a fallback type.
        """
        self.server.negotiator.setAllowedTypes([('HMAC-SHA256', 'DH-SHA256')])

        msg = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.session_type': 'no-encryption',
            'openid.assoc_type': 'HMAC-SHA1',
        })

        request = server.AssociateRequest.fromMessage(msg)
        response = self.server.openid_associate(request)

        self.assertTrue(response.fields.hasKey(OPENID_NS, "error"))
        self.assertTrue(response.fields.hasKey(OPENID_NS, "error_code"))
        self.assertFalse(response.fields.hasKey(OPENID_NS, "assoc_handle"))
        self.assertEqual(response.fields.getArg(OPENID_NS, "assoc_type"), 'HMAC-SHA256')
        self.assertEqual(response.fields.getArg(OPENID_NS, "session_type"), 'DH-SHA256')

    def test_associate4(self):
        """DH-SHA256 association session"""
        self.server.negotiator.setAllowedTypes(
            [('HMAC-SHA256', 'DH-SHA256')])
        query = {
            'openid.dh_consumer_public':
            'ALZgnx8N5Lgd7pCj8K86T/DDMFjJXSss1SKoLmxE72kJTzOtG6I2PaYrHX'
            'xku4jMQWSsGfLJxwCZ6280uYjUST/9NWmuAfcrBfmDHIBc3H8xh6RBnlXJ'
            '1WxJY3jHd5k1/ZReyRZOxZTKdF/dnIqwF8ZXUwI6peV0TyS/K1fOfF/s',
            'openid.assoc_type': 'HMAC-SHA256',
            'openid.session_type': 'DH-SHA256',
        }
        message = Message.fromPostArgs(query)
        request = server.AssociateRequest.fromMessage(message)
        response = self.server.openid_associate(request)
        self.assertTrue(response.fields.hasKey(OPENID_NS, "assoc_handle"))

    def test_missingSessionTypeOpenID2(self):
        """Make sure session_type is required in OpenID 2"""
        msg = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
        })

        self.assertRaises(server.ProtocolError, server.AssociateRequest.fromMessage, msg)

    def test_missingAssocTypeOpenID2(self):
        """Make sure assoc_type is required in OpenID 2"""
        msg = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.session_type': 'no-encryption',
        })

        self.assertRaises(server.ProtocolError, server.AssociateRequest.fromMessage, msg)

    def test_checkAuth(self):
        request = server.CheckAuthRequest('arrrrrf', '0x3999')
        response = self.server.openid_check_authentication(request)
        self.assertTrue(response.fields.hasKey(OPENID_NS, "is_valid"))


class TestSignatory(unittest.TestCase):
    def setUp(self):
        self.store = memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)
        self._dumb_key = self.signatory._dumb_key
        self._normal_key = self.signatory._normal_key

    def test_sign(self):
        request = server.OpenIDRequest(Message(OPENID1_NS))
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1'))
        request.assoc_handle = assoc_handle
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
        })
        with LogCapture() as logbook:
            sresponse = self.signatory.sign(response)
        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'assoc_handle'), assoc_handle)
        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'signed'), 'assoc_handle,azu,bar,foo,signed')
        self.assertTrue(sresponse.fields.getArg(OPENID_NS, 'sig'))
        self.assertEqual(logbook.records, [])

    def test_signDumb(self):
        request = server.OpenIDRequest()
        request.assoc_handle = None
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
            'ns': OPENID2_NS,
        })
        with LogCapture() as logbook:
            sresponse = self.signatory.sign(response)
        assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        self.assertTrue(assoc_handle)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.assertTrue(assoc)
        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'signed'), 'assoc_handle,azu,bar,foo,ns,signed')
        self.assertTrue(sresponse.fields.getArg(OPENID_NS, 'sig'))
        self.assertEqual(logbook.records, [])

    def test_signExpired(self):
        """Sign a response to a message with an expired handle (using invalidate_handle).

        From "Verifying with an Association"::

            If an authentication request included an association handle for an
            association between the OP and the Relying party, and the OP no
            longer wishes to use that handle (because it has expired or the
            secret has been compromised, for instance), the OP will send a
            response that must be verified directly with the OP, as specified
            in Section 11.3.2. In that instance, the OP will include the field
            "openid.invalidate_handle" set to the association handle that the
            Relying Party included with the original request.
        """
        request = server.OpenIDRequest()
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(-10, assoc_handle, b'sekrit', 'HMAC-SHA1'))
        self.assertTrue(self.store.getAssociation(self._normal_key, assoc_handle))

        request.assoc_handle = assoc_handle
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
        })
        with LogCapture() as logbook:
            sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        self.assertTrue(new_assoc_handle)
        self.assertNotEqual(new_assoc_handle, assoc_handle)

        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'invalidate_handle'), assoc_handle)

        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'signed'),
                         'assoc_handle,azu,bar,foo,invalidate_handle,signed')
        self.assertTrue(sresponse.fields.getArg(OPENID_NS, 'sig'))

        # make sure the expired association is gone
        self.assertFalse(self.store.getAssociation(self._normal_key, assoc_handle),
                         "expired association is still retrievable.")

        # make sure the new key is a dumb mode association
        self.assertTrue(self.store.getAssociation(self._dumb_key, new_assoc_handle))
        self.assertFalse(self.store.getAssociation(self._normal_key, new_assoc_handle))
        logbook.check(('openid.server.server', 'INFO', StringComparison('requested .* key .* is expired .*')))

    def test_signInvalidHandle(self):
        request = server.OpenIDRequest()
        assoc_handle = '{bogus-assoc}{notvalid}'

        request.assoc_handle = assoc_handle
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo': 'amsigned',
            'bar': 'notsigned',
            'azu': 'alsosigned',
        })
        with LogCapture() as logbook:
            sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        self.assertTrue(new_assoc_handle)
        self.assertNotEqual(new_assoc_handle, assoc_handle)

        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'invalidate_handle'), assoc_handle)

        self.assertEqual(sresponse.fields.getArg(OPENID_NS, 'signed'),
                         'assoc_handle,azu,bar,foo,invalidate_handle,signed')
        self.assertTrue(sresponse.fields.getArg(OPENID_NS, 'sig'))

        # make sure the new key is a dumb mode association
        self.assertTrue(self.store.getAssociation(self._dumb_key, new_assoc_handle))
        self.assertFalse(self.store.getAssociation(self._normal_key, new_assoc_handle))
        self.assertEqual(logbook.records, [])

    def test_verify(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'openid.foo': 'bar',
            'openid.apple': 'orange',
            'openid.assoc_handle': assoc_handle,
            'openid.signed': 'apple,assoc_handle,foo,signed',
            'openid.sig': 'uXoT1qm62/BB09Xbj98TQ8mlBco=',
        })

        with LogCapture() as logbook:
            verified = self.signatory.verify(assoc_handle, signed)
        self.assertEqual(logbook.records, [])
        self.assertTrue(verified)

    def test_verifyBadSig(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'openid.foo': 'bar',
            'openid.apple': 'orange',
            'openid.assoc_handle': assoc_handle,
            'openid.signed': 'apple,assoc_handle,foo,signed',
            'openid.sig': 'invalid/BB09Xbj98TQ8mlBco=',
        })

        with LogCapture() as logbook:
            verified = self.signatory.verify(assoc_handle, signed)
        self.assertEqual(logbook.records, [])
        self.assertFalse(verified)

    def test_verifyBadHandle(self):
        assoc_handle = '{vroom}{zoom}'
        signed = Message.fromPostArgs({
            'foo': 'bar',
            'apple': 'orange',
            'openid.sig': "Ylu0KcIR7PvNegB/K41KpnRgJl0=",
        })

        with LogCapture() as logbook:
            verified = self.signatory.verify(assoc_handle, signed)
        self.assertFalse(verified)
        logbook.check(('openid.server.server', 'ERROR', StringComparison('failed to get assoc with handle .*')))

    def test_verifyAssocMismatch(self):
        """Attempt to validate sign-all message with a signed-list assoc."""
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'foo': 'bar',
            'apple': 'orange',
            'openid.sig': "d71xlHtqnq98DonoSgoK/nD+QRM=",
        })

        with LogCapture() as logbook:
            verified = self.signatory.verify(assoc_handle, signed)
        self.assertFalse(verified)
        logbook.check(('openid.server.server', 'ERROR', StringComparison('Error in verifying .*')))

    def test_getAssoc(self):
        assoc_handle = self.makeAssoc(dumb=True)
        with LogCapture() as logbook:
            assoc = self.signatory.getAssociation(assoc_handle, True)
        self.assertTrue(assoc)
        self.assertEqual(assoc.handle, assoc_handle)
        self.assertEqual(logbook.records, [])

    def test_getAssocExpired(self):
        assoc_handle = self.makeAssoc(dumb=True, lifetime=-10)
        with LogCapture() as logbook:
            assoc = self.signatory.getAssociation(assoc_handle, True)
        self.assertFalse(assoc)
        logbook.check(('openid.server.server', 'INFO', StringComparison('requested .* key .* is expired .*')))

    def test_getAssocInvalid(self):
        ah = 'no-such-handle'
        with LogCapture() as logbook:
            self.assertIsNone(self.signatory.getAssociation(ah, dumb=False))
        self.assertEqual(logbook.records, [])

    def test_getAssocDumbVsNormal(self):
        """getAssociation(dumb=False) cannot get a dumb assoc"""
        assoc_handle = self.makeAssoc(dumb=True)
        with LogCapture() as logbook:
            self.assertIsNone(self.signatory.getAssociation(assoc_handle, dumb=False))
        self.assertEqual(logbook.records, [])

    def test_getAssocNormalVsDumb(self):
        """getAssociation(dumb=True) cannot get a shared assoc

        From "Verifying Directly with the OpenID Provider"::

            An OP MUST NOT verify signatures for associations that have shared
            MAC keys.
        """
        assoc_handle = self.makeAssoc(dumb=False)
        with LogCapture() as logbook:
            self.assertIsNone(self.signatory.getAssociation(assoc_handle, dumb=True))
        self.assertEqual(logbook.records, [])

    def test_createAssociation(self):
        with LogCapture() as logbook:
            assoc = self.signatory.createAssociation(dumb=False)
        self.assertTrue(self.signatory.getAssociation(assoc.handle, dumb=False))
        self.assertEqual(logbook.records, [])

    def makeAssoc(self, dumb, lifetime=60):
        assoc_handle = '{bling}'
        assoc = association.Association.fromExpiresIn(lifetime, assoc_handle, b'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation((dumb and self._dumb_key) or self._normal_key, assoc)
        return assoc_handle

    def test_invalidate(self):
        assoc_handle = '-squash-'
        assoc = association.Association.fromExpiresIn(60, assoc_handle, b'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.assertTrue(assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.assertTrue(assoc)
        with LogCapture() as logbook:
            self.signatory.invalidate(assoc_handle, dumb=True)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.assertFalse(assoc)
        self.assertEqual(logbook.records, [])


if __name__ == '__main__':
    unittest.main()
