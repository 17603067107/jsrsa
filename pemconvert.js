/**
 * Glue to parse PEM format files into RSA keys.
 *
 * @author Sven Schwedas
 *
 * Copyright (c) 2012 Sven Schwedas
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

function pem_import (pem) {
	var reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;
	var der = reHex.test(pem) ? Hex.decode(pem) : Base64.unarmor(pem);
	var asn1 = ASN1.decode (der);
	var key = new RSAKey();
	if (pem_is_private (pem)) {
		key.setPrivateEx (asn1.sub[1].content().toString(16),
			asn1.sub[2].content().toString(16),
			asn1.sub[3].content().toString(16),
			asn1.sub[4].content().toString(16),
			asn1.sub[5].content().toString(16),
			asn1.sub[6].content().toString(16),
			asn1.sub[7].content().toString(16),
			asn1.sub[8].content().toString(16));
	} else {
		asn1 = asn1.sub[1].sub[0];
		key.setPublic (asn1.sub[0].content().toString(16),asn1.sub[1].content().toString(16));
	}
	return key;
}

function pem_is_private (pem) {
	return pem.indexOf ("PRIVATE KEY") >= 0;
}

// Copied from PHPJS, see http://phpjs.org/pages/license
function bin2hex (s)
{
	var i, f = 0,
		a = [];

	s += '';
	f = s.length;

	for (i = 0; i < f; i++) {
		a[i] = s.charCodeAt(i).toString(16).replace(/^([\da-f])$/, "0$1");
	}

	return a.join('');
}

// Copied from StackOverflow ( http://stackoverflow.com/questions/7695450/how-to-program-hex2bin-in-javascript )
// Copyright SO user 2astalavista
function hex2bin(hex)
{
	var bytes = [], str;

	for(var i=0; i< hex.length-1; i+=2)
		bytes.push(parseInt(hex.substr(i, 2), 16));

	return String.fromCharCode.apply(String, bytes);
}
