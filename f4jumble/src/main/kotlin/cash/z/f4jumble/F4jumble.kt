/**
* This Package provides a mechanism for "jumbling" byte slices in a reversible way.
*
* Many byte encodings such as [Base64] and [Bech32] do not have "cascading" behaviour:
* changing an input byte at one position has no effect on the encoding of bytes at
* distant positions. This can be a problem if users generally check the correctness of
* encoded strings by eye, as they will tend to only check the first and/or last few
* characters of the encoded string. In some situations (for example, a hardware device
* displaying on its screen an encoded string provided by an untrusted computer), it is
* potentially feasible for an adversary to change some internal portion of the encoded
* string in a way that is beneficial to them, without the user noticing.
*
* The function F4Jumble (and its inverse function, F4Jumble⁻¹) are length-preserving
* transformations can be used to trivially introduce cascading behaviour to existing
* encodings:
* - Prepare the raw `message` bytes.
* - Pass `message` through [F4jumble] to obtain the jumbled bytes.
* - Encode the jumbled bytes with the encoding scheme.
*
* Changing any byte of `message` will result in a completely different sequence of
* jumbled bytes. Specifically, F4Jumble uses an unkeyed 4-round Feistel construction to
* approximate a random permutation.
*
* [Diagram of 4-round unkeyed Feistel construction](https:*zips.z.cash/zip-0316-f4.png)
*
* [Base64]: https:*en.wikipedia.org/wiki/Base64
* [Bech32]: https:*github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Bech32
*/
package cash.z.f4jumble

import com.rfksystems.blake2b.Blake2b
import kotlin.jvm.JvmStatic
import kotlin.math.min

private const val MIN_LEN_M = 48
private const val MAX_LEN_M = 4194368
private const val LEN_H = 64

public object F4jumble {
    private fun ceilDiv(
        num: Int,
        den: Int,
    ): Int {
        return (num + den - 1) / den
    }

    private fun hPers(i: Int): ByteArray {
        return byteArrayOf(
            85,
            65,
            95,
            70,
            52,
            74,
            117,
            109,
            98,
            108,
            101,
            95,
            72,
            i.toByte(),
            0,
            0,
        )
    }

    private fun gPers(
        i: Int,
        j: Int,
    ): ByteArray {
        return byteArrayOf(
            85,
            65,
            95,
            70,
            52,
            74,
            117,
            109,
            98,
            108,
            101,
            95,
            71,
            i.toByte(),
            (j and 0xff).toByte(),
            (j shr 8).toByte(),
        )
    }

    private fun xor(
        x: ByteArray,
        y: ByteArray,
    ): ByteArray {
        val result = ByteArray(x.size)
        for (i in x.indices) {
            if (i < y.size) {
                result.set(i, (x.get(i).toUByte() xor y.get(i).toUByte()).toByte())
            }
        }
        return result
    }

    private fun gRound(
        i: Int,
        u: ByteArray,
        lenR: Int,
    ): ByteArray {
        fun inner(j: Int): ByteArray {
            val g = Blake2b(null, LEN_H, null, gPers(i, j))

            g.update(u, 0, u.size)

            val out = ByteArray(64)
            g.digest(out, 0)
            return out
        }

        val result = mutableListOf<Byte>()
        for (j in 0 until ceilDiv(lenR, LEN_H)) {
            val hash = inner(j)
            result.addAll(hash.toList())
        }
        return result.toByteArray().copyOf(lenR)
    }

    private fun hRound(
        i: Int,
        u: ByteArray,
        lenL: Int,
    ): ByteArray {
        val h = Blake2b(null, lenL, null, hPers(i))

        h.update(u, 0, u.size)

        val out = ByteArray(lenL)
        h.digest(out, 0)

        return out
    }

    /**
     * Encodes the given ByteArray using F4Jumble, and returns the encoded message as []byte.
     * Returns an error if the message is an invalid length.
     */
    @JvmStatic
    fun f4Jumble(m: ByteArray): ByteArray {
        val lenM = m.size
        if (lenM < MIN_LEN_M || lenM > MAX_LEN_M) {
            throw IllegalArgumentException("Invalid message length")
        }

        val lenL = min(LEN_H, lenM / 2)
        val lenR = lenM - lenL

        val a = m.copyOfRange(0, lenL)
        val b = m.copyOfRange(lenL, m.size)

        val x = xor(b, gRound(0, a, lenR))
        val y = xor(a, hRound(0, x, lenL))
        val d = xor(x, gRound(1, y, lenR))
        val c = xor(y, hRound(1, d, lenL))

        return (c + d)
    }

    /**
     * Inverts the F4Jumble operation, returning the original un-jumbled bytes.
     * Returns an error if the message is an invalid length.
     */
    @JvmStatic
    fun f4JumbleInv(m: ByteArray): ByteArray {
        val lenM = m.size
        if (lenM < MIN_LEN_M || lenM > MAX_LEN_M) {
            throw IllegalArgumentException("Invalid message length")
        }
        val lenL = min(LEN_H, lenM / 2)
        val lenR = lenM - lenL

        val c = m.copyOfRange(0, lenL)
        val d = m.copyOfRange(lenL, m.size)

        val y = xor(c, hRound(1, d, lenL))
        val x = xor(d, gRound(1, y, lenR))
        val a = xor(y, hRound(0, x, lenL))
        val b = xor(x, gRound(0, a, lenR))

        return (a + b)
    }
}
