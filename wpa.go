/*  Package containing functions to calculate keys used in WPA1/2 PSK
    Copyright (C) 2013 Marco 'don' Kaulea

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

package wpa

import "code.google.com/p/go.crypto/pbkdf2"
import "crypto/sha1"
import "crypto/md5"
import "crypto/hmac"

func DeriveWPAPMK(passphrase, ssid string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, 32, sha1.New)
}

func PRF(pmk []byte, app_identifier string, data []byte, keyLen int) []byte {
	prf := hmac.New(sha1.New, pmk)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var null = make([]byte, 1)
	null[0] = byte(0)
	var r []byte
	for n := 0; n < numBlocks; n++ {
		prf.Reset()
		prf.Write([]byte(app_identifier))
		prf.Write(null)
		prf.Write(data)
		appendix := make([]byte, 1)
		appendix[0] = byte(n)
		prf.Write(appendix)
		r = prf.Sum(r)
	}
	return r[:keyLen]
}

func CalculateMICValue(ptk, data []byte, keyLen int) []byte {
	prf := hmac.New(md5.New, ptk)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var r []byte
	for n := 0; n < numBlocks; n++ {
		prf.Reset()
		prf.Write(data)
		r = prf.Sum(r)
	}
	return r[:keyLen]
}
