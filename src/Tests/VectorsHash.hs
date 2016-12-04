{-# LANGUAGE OverloadedStrings, Safe #-}

module VectorsHash
	( hashTestVectors
	, findHashTestVectors
	) where

import HexUtils
import qualified Data.ByteString as B

-- test vector froms nettle

-- MD5 collisions:
--  /* Collisions, reported by Xiaoyun Wang1, Dengguo Feng2, Xuejia
--     Lai3, Hongbo Yu1, http://eprint.iacr.org/2004/199. */
--  /* Note: The checksum in the paper, 1f160396 efc71ff4 bcff659f
--     bf9d0fa3, is incorrect. */ (md5H0)
--  /* Note: Also different from the checksum in the paper */ (md5H1)

--                                                   vv                                                          vv                               vv
md5M0 = hs "d131dd02 c5e6eec4 693d9a06 98aff95c 2fcab5 87 12467eab 4004583e b8fb7f89 55ad3406 09f4b302 83e48883 25 71 415a 085125e8 f7cdc99f d91dbd f2 80373c5b"
md5M1 = hs "d131dd02 c5e6eec4 693d9a06 98aff95c 2fcab5 07 12467eab 4004583e b8fb7f89 55ad3406 09f4b302 83e48883 25 f1 415a 085125e8 f7cdc99f d91dbd 72 80373c5b"
md5N0 = hs "960b1dd1 dc417b9c e4d897f4 5a6555d5 35739a c7 f0ebfd0c 3029f166 d109b18f 75277f79 30d55ceb 22e8adba 79 cc 155c ed74cbdd 5fc5d36d b19b0a d8 35cca7e3"
md5N1 = hs "960b1dd1 dc417b9c e4d897f4 5a6555d5 35739a 47 f0ebfd0c 3029f166 d109b18f 75277f79 30d55ceb 22e8adba 79 4c 155c ed74cbdd 5fc5d36d b19b0a 58 35cca7e3"
md5N2 = hs "d8823e31 56348f5b ae6dacd4 36c919c6 dd53e2 b4 87da03fd 02396306 d248cda0 e99f3342 0f577ee8 ce54b670 80 a8 0d1e c69821bc b6a88393 96f965 2b 6ff72a70"
md5N3 = hs "d8823e31 56348f5b ae6dacd4 36c919c6 dd53e2 34 87da03fd 02396306 d248cda0 e99f3342 0f577ee8 ce54b670 80 28 0d1e c69821bc b6a88393 96f965 ab 6ff72a70"
md5H0 = "a4c0d35c 95a63a80 5915367d cfe6b751"
md5H1 = "79054025 255fb1a2 6e4bc422 aef54eb4"


hashTestVectors :: [(String, [(B.ByteString, String)])]
hashTestVectors =
	[ ( "GOSTHAST94",
-- /* Using test vectors from Wikipedia article on GOST */
		[ ("The quick brown fox jumps over the lazy dog", "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294")
		, ("message digest", "ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d")
		, ("a", "d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd")
		, ("", "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d")
		])
	, ( "MD2",
--  /* Testcases from RFC 1319 */
		[ ("", "8350e5a3e24c153df2275c9f80692773")
		, ("a", "32ec01ec4a6dac72c0ab96fb34c0b5d1")
		, ("abc", "da853b0d3f88d99b30283a69e6ded6bb")
		, ("message digest", "ab4f496bfb2a530b219ff33031fe06b0")
		, ("abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "da33def2a42df13975352846c30338cd")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "d5976f79d83d3a0dc9806c3c66f3efd8")
		])
	, ( "MD4",
--  /* Testcases from RFC 1320 */
		[ ("", "31d6cfe0d16ae931b73c59d7e0c089c0")
		, ("a", "bde52cb31de33e46245e05fbdbd6fb24")
		, ("abc", "a448017aaf21d8525fc10ae87aa6729d")
		, ("message digest", "d9130a8164549fe818874806e1c7014b")
		, ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("38", "ae9c7ebfb68ea795483d270f5934b71d")
		, ("abc", "a448017aaf21d8525fc10ae87aa6729d")
		, ("message digest", "d9130a8164549fe818874806e1c7014b")
		, ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")
		])
	, ( "MD5",
		[ ("", "D41D8CD98F00B204 E9800998ECF8427E")
		, ("a", "0CC175B9C0F1B6A8 31C399E269772661")
		, ("abc", "900150983cd24fb0 D6963F7D28E17F72")
		, ("message digest", "F96B697D7CB7938D 525A2F31AAF161D0")
		, ("abcdefghijklmnopqrstuvwxyz", "C3FCD3D76192E400 7DFB496CCA67E13B")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "D174AB98D277D9F5 A5611C2C9F419D9F")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57EDF4A22BE3C955 AC49DA2E2107B67A")
--  /* Additional test vector, from Daniel Kahn Gillmor */
		, ("38", "a5771bce93e200c3 6f7cd9dfd0e5deaa")
-- collisions
		, (B.append md5M0 md5N0, md5H0)
		, (B.append md5M1 md5N1, md5H0)
		, (B.append md5M0 md5N2, md5H1)
		, (B.append md5M1 md5N3, md5H1)
		])
	, ( "RIPEMD160",
		[ ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31")
		, ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")
		, ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
		, ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
		, ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb")
--  /* Additional test vector, from Daniel Kahn Gillmor */
		, ("38", "6b2d075b1cd34cd1c3e43a995f110c55649dad0e")
		])
	, ( "SHA1",
		[ ("", "DA39A3EE5E6B4B0D 3255BFEF95601890 AFD80709")
		, ("a", "86F7E437FAA5A7FC E15D1DDCB9EAEAEA 377667B8")
		, ("abc", "A9993E364706816A BA3E25717850C26C 9CD0D89D")
		, ("abcdefghijklmnopqrstuvwxyz", "32D10C7B8CF96570 CA04CE37F2A19D84 240D3A89")
		, ("message digest", "C12252CEDA8BE899 4D5FA0290A47231C 1D16AAE3")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "761C457BF73B14D2 7E9E9265C46F4B4D DA11F940")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "50ABF5706A150990 A08B2C5EA40FA0E5 85554732")
--  /* Additional test vector, from Daniel Kahn Gillmor */
		, ("38", "5b384ce32d8cdef02bc3a139d4cac0a22bb029e8")
		])
	, ( "SHA224",
--  /* From FIPS180-2 addendum
--     (http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf) */
		[ ("abc", "23097d22 3405d822 8642a477 bda255b32aadbce4 bda0b3f7 e36c9da7")
		, ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16 512776cc 5dba5da1 fd890150b0c6455c b4f58b19 52522525")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("", "d14a028c2a3a2bc9 476102bb288234c415a2b01f828ea62a c5b3e42f")
		, ("a", "abd37534c7d9a2ef b9465de931cd7055ffdb8879563ae980 78d6d6d5")
		, ("38", "4cfca6da32da6471 98225460722b7ea1284f98c4b179e8db ae3f93d5")
		, ("message digest", "2cb21c83ae2f004d e7e81c3c7019cbcb65b71ab656b22d6d 0c39b8eb")
		, ("abcdefghijklmnopqrstuvwxyz", "45a5f72c39c5cff2 522eb3429799e49e5f44b356ef926bcf 390dccc2")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "bff72b4fcb7d75e5 632900ac5f90d219e05e97a7bde72e74 0db393d9")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "b50aecbe4e9bb0b5 7bc5f3ae760a8e01db24f203fb3cdcd1 3148046e")
		])
	, ( "SHA256",
--  /* From FIPS180-2 */
		[ ("abc", "ba7816bf8f01cfea 414140de5dae2223b00361a396177a9c b410ff61f20015ad")
		, ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8 e5c026930c3e6039a33ce45964ff2167 f6ecedd419db06c1")
		, ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380 036ce59e7b0492370b249b11e8f07a51 afac45037afee9d1")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("", "e3b0c44298fc1c14 9afbf4c8996fb92427ae41e4649b934c a495991b7852b855")
		, ("a", "ca978112ca1bbdca fac231b39a23dc4da786eff8147c4e72 b9807785afee48bb")
		, ("38", "aea92132c4cbeb26 3e6ac2bf6c183b5d81737f179f21efdc 5863739672f0f470")
		, ("message digest", "f7846f55cf23e14e ebeab5b4e1550cad5b509e3348fbc4ef a3a1413d393cb650")
		, ("abcdefghijklmnopqrstuvwxyz", "71c480df93d6ae2f 1efad1447c66c9525e316218cf51fc8d 9ed832f2daf18b73")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "db4bfcbd4da0cd85 a60c3c37d3fbd8805c77f15fc6b1fdfe 614ee0a7c8fdb4c0")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "f371bc4a311f2b00 9eef952dd83ca80e2b60026c8e935592 d0f9c308453c813e")
		])
	, ( "SHA384",
		[ ("abc", "cb00753f45a35e8b b5a03d699ac65007272c32ab0eded163 1a8b605a43ff5bed8086072ba1e7cc23 58baeca134c825a7")
		, ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330c33f71147e8 3d192fc782cd1b4753111b173b3b05d2 2fa08086e3b0f712fcc7c71a557e2db9 66c3e9fa91746039")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("", "38b060a751ac9638 4cd9327eb1b1e36a21fdb71114be0743 4c0cc7bf63f6e1da274edebfe76f65fb d51ad2f14898b95b")
		, ("a", "54a59b9f22b0b808 80d8427e548b7c23abd873486e1f035d ce9cd697e85175033caa88e6d57bc35e fae0b5afd3145f31")
		, ("38", "c071d202ad950b6a 04a5f15c24596a993af8b212467958d5 70a3ffd4780060638e3a3d06637691d3 012bd31122071b2c")
		, ("message digest", "473ed35167ec1f5d 8e550368a3db39be54639f828868e945 4c239fc8b52e3c61dbd0d8b4de1390c2 56dcbb5d5fd99cd5")
		, ("abcdefghijklmnopqrstuvwxyz", "feb67349df3db6f5 924815d6c3dc133f091809213731fe5c 7b5f4999e463479ff2877f5f2936fa63 bb43784b12f3ebb4")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1761336e3f7cbfe5 1deb137f026f89e01a448e3b1fafa640 39c1464ee8732f11a5341a6f41e0c202 294736ed64db1a84")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "b12932b0627d1c06 0942f5447764155655bd4da0c9afa6dd 9b9ef53129af1b8fb0195996d2de9ca0 df9d821ffee67026")
		])
	, ( "SHA512",
		[ ("abc", "ddaf35a193617aba cc417349ae20413112e6fa4e89a97ea2 0a9eeee64b55d39a2192992a274fc1a8 36ba3c23a3feebbd454d4423643ce80e 2a9ac94fa54ca49f")
		, ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da 8cf4f72814fc143f8f7779c6eb9f7fa1 7299aeadb6889018501d289e4900f7e4 331b99dec4b5433ac7d329eeb6dd2654 5e96e55b874be909")
--  /* NESSIE, Set 1, vector #6 */
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1E07BE23C26A86EA37EA810C8EC7809352515A970E9253C26F536CFC7A9996C45C8370583E0A78FA4A90041D71A4CEAB7423F19C71B9D5A3E01249F0BEBD5894")
--  /* NESSIE, Set 1, vector #7 */
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "72EC1EF1124A45B047E8B7C75A932195135BB61DE24EC0D1914042246E0AEC3A2354E093D76F3048B456764346900CB130D2A4FD5DD16ABB5E30BCB850DEE843")
--  /* Variants longer than one block (128 bytes), to test varying alignment. */
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "5338370f5655f4da14572d4fb471539b201485ecfb3d3204048dc6b83e61fab505bcbbd73e644a1a5d159a32a0889cf3c9591b69b26d31be56c68838ce3cd63d")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", "33f8901b053e4cc677d3cb4122d96ad9b96b13bf76194cf962488bb4de4998a71455cb31582db527adf77a485b81cf5b722a5e8638eb6be487400f3aec006e7c")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("", "cf83e1357eefb8bd f1542850d66d8007d620e4050b5715dc 83f4a921d36ce9ce47d0d13c5d85f2b0 ff8318d2877eec2f63b931bd47417a81 a538327af927da3e")
		, ("a", "1f40fc92da241694 750979ee6cf582f2d5d7d28e18335de0 5abc54d0560e0f5302860c652bf08d56 0252aa5e74210546f369fbbbce8c12cf c7957b2652fe9a75")
		, ("38", "caae34a5e8103126 8bcdaf6f1d8c04d37b7f2c349afb705b 575966f63e2ebf0fd910c3b05160ba08 7ab7af35d40b7c719c53cd8b947c9611 1f64105fd45cc1b2")
		, ("message digest", "107dbf389d9e9f71 a3a95f6c055b9251bc5268c2be16d6c1 3492ea45b0199f3309e16455ab1e9611 8e8a905d5597b72038ddb372a8982604 6de66687bb420e7c")
		, ("abcdefghijklmnopqrstuvwxyz", "4dbff86cc2ca1bae 1e16468a05cb9881c97f1753bce36190 34898faa1aabe429955a1bf8ec483d74 21fe3c1646613a59ed5441fb0f321389 f77f48a879c7b1f1")
		, ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1e07be23c26a86ea 37ea810c8ec7809352515a970e9253c2 6f536cfc7a9996c45c8370583e0a78fa 4a90041d71a4ceab7423f19c71b9d5a3 e01249f0bebd5894")
		, ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "72ec1ef1124a45b0 47e8b7c75a932195135bb61de24ec0d1 914042246e0aec3a2354e093d76f3048 b456764346900cb130d2a4fd5dd16abb 5e30bcb850dee843")
		])
	, ( "SHA3-224",
--  /* Extracted from ShortMsgKAT_224.txt using sha3.awk. */
		[
		])
	, ( "SHA3-256",
--  /* Extracted from ShortMsgKAT_256.txt using sha3.awk. */
		[])
	, ( "SHA3-384",
--  /* Extracted from ShortMsgKAT_384.txt using sha3.awk. */
		[])
	, ( "SHA3-512",
--  /* Extracted from ShortMsgKAT512.txt using sha3.awk. */
		[])
	]

findHashTestVectors :: Monad m => String -> m [(B.ByteString, String)]
findHashTestVectors key = case filter ((key == ) . fst) hashTestVectors of
	[] -> fail $ "unknown Hash: " ++ key
	l -> return $ concatMap snd l
