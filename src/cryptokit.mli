(***********************************************************************)
(*                                                                     *)
(*                      The Cryptokit library                          *)
(*                                                                     *)
(*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         *)
(*                                                                     *)
(*  Copyright 2002 Institut National de Recherche en Informatique et   *)
(*  en Automatique.  All rights reserved.  This file is distributed    *)
(*  under the terms of the GNU Library General Public License, with    *)
(*  the special exception on linking described in file LICENSE.        *)
(*                                                                     *)
(***********************************************************************)

(** The Cryptokit library provides a variety of cryptographic primitives
    that can be used to implement cryptographic protocols in
    security-sensitive applications.  The primitives provided include:
    - Symmetric-key ciphers: AES, DES, Triple-DES, ARCfour,
      in ECB, CBC, CFB and OFB modes.
    - Public-key cryptography: RSA encryption, Diffie-Hellman key agreement.
    - Hash functions and MACs: SHA-1, SHA-256, SHA-512. SHA-3, RIPEMD-160, MD5,
      and MACs based on AES and DES.
    - Random number generation.
    - Encodings and compression: base 64, hexadecimal, Zlib compression.
*)

(** {1 General-purpose abstract interfaces} *)

(** A <I>transform</I> is an arbitrary mapping from sequences of characters
    to sequences of characters.  Examples of transforms include
    ciphering, deciphering, compression, decompression, and encoding
    of binary data as text.  Input data to a transform is provided
    by successive calls to the methods [put_substring], [put_string],
    [put_char] or [put_byte].  The result of transforming the input
    data is buffered internally, and can be obtained via the
    [get_string], [get_substring], [get_char] and [get_byte] methods. *)
class type transform =
  object

    method put_substring: bytes -> int -> int -> unit
      (** [put_substring b pos len] processes [len] characters of
          byte sequence [b], starting at character number [pos],
          through the transform. *)

    method put_string: string -> unit
      (** [put_string str] processes all characters of string [str]
          through the transform. *)

    method put_char: char -> unit
      (** [put_char c] processes character [c] through the transform. *)

    method put_byte: int -> unit
      (** [put_byte b] processes the character having code [b]
          through the transform. [b] must be between [0] and [255]
          inclusive. *)

    method finish: unit
      (** Call method [finish] to indicate that no further data will
          be processed through the transform.  This causes the transform
          to flush its internal buffers and perform all appropriate
          finalization actions, e.g. add final padding.  Raise [Error
          Wrong_data_length] if the total length of input data
          provided via the [put_*] methods is not an integral number
          of the input block size (see
          {!Cryptokit.transform.input_block_size}).  After calling
          [finish], the transform can no longer accept additional
          data.  Hence, do not call any of the [put_*] methods nor
          [flush] after calling [finish]. *)

    method flush: unit
      (** [flush] causes the transform to flush its internal buffers
          and make all output processed up to this point available through
          the [get_*] methods.  
          Raise [Error Wrong_data_length] if the total length
          of input data provided via the [put_*] methods is not
          an integral number of the input block size
          (see {!Cryptokit.transform.input_block_size}).
          (For padded block ciphers, the input block size used here
          is that of the underlying block cipher, without the padding.)
          Unlike method [finish], method [flush] does not add final
          padding and leaves the transform in a state where it can
          still accept more input. *)

    method available_output: int
      (** Return the number of characters of output currently available.
          The output can be recovered with the [get_*] methods. *)

    method get_string: string
      (** Return a character string containing all output characters
          available at this point.  The internal output buffer is emptied;
          in other terms, all currently available output is consumed
          (and returned to the caller) by a call to [get_string]. *)

    method get_substring: bytes * int * int
      (** Return a triple [(buf,pos,len)], where [buf] is the internal
          output buffer for the transform, [pos] the position of the
          first character of available output, and [len] the number of
          characters of available output.  The byte array [buf] will be
          modified later, so the caller must immediately copy
          characters [pos] to [pos+len-1] of [buf] to some other
          location.  The internal output buffer is emptied;
          in other terms, all currently available output is consumed
          (and returned to the caller) by a call to [get_substring]. *)

    method get_char: char
      (** Return the first character of output, and remove it from the
          internal output buffer.  Raise [End_of_file] if no output
          is currently available. *)

    method get_byte: int
      (** Return the code of the first character of output,
          and remove it from the internal output buffer.
          Raise [End_of_file] if no output is currently available. *)

    method input_block_size: int
      (** Some transforms (e.g. unpadded block ciphers) process
          input data by blocks of several characters.  This method
          returns the size of input blocks for the current transform.
          If [input_block_size > 1], the user of the transform
          must ensure that the total length of input data provided
          between calls to [flush] and [finish] is an integral
          multiple of [input_block_size].
          If [input_block_size = 1], the transform can accept
          input data of arbitrary length. *)

    method output_block_size: int
      (** Some transforms (e.g. block ciphers) always produce output
          data by blocks of several characters.  This method
          returns the size of output blocks for the current transform.
          If [output_block_size > 1], the total length of output data
          produced by the transform is always an integral multiple
          of [output_block_size].
          If [output_block_size = 1], the transform produces output data
          of arbitrary length. *)

    method wipe: unit
      (** Erase all internal buffers and data structures of this transform,
          overwriting them with zeroes.  A transform may contain sensitive
          data such as secret key-derived material, or parts of the
          input or output data.  Calling [wipe] ensures that this sensitive
          data will not remain in memory longer than strictly necessary,
          thus making invasive attacks more difficult.
          It is thus prudent practice to call [wipe] on every
          transform that the program no longer needs.
          After calling [wipe], the transform is no longer in a working
          state: do not call any other methods after calling [wipe]. *)
  end

val transform_string: transform -> string -> string
  (** [transform_string t s] runs the string [s] through the
      transform [t] and returns the transformed string.
      The transform [t] is wiped before returning, hence can
      no longer be used for further transformations. *)

val transform_channel:
       transform -> ?len:int -> in_channel -> out_channel -> unit
  (** [transform_channel t ic oc] reads characters from input channel [ic],
      runs them through the transform [t], and writes the transformed
      data to the output channel [oc].  If the optional [len] argument
      is provided, exactly [len] characters are read from [ic] and
      transformed; [End_of_file] is raised if [ic] does not contain
      at least [len] characters.  If [len] is not provided, [ic] is
      read all the way to end of file. 
      The transform [t] is wiped before returning, hence can
      no longer be used for further transformations. *)

val compose: transform -> transform -> transform
  (** Compose two transforms, feeding the output of the first transform
      to the input of the second transform. *)

(** A <I>hash</I> is a function that maps arbitrarily-long character
    sequences to small, fixed-size strings.  *)
class type hash =
  object

    method add_substring: bytes -> int -> int -> unit
      (** [add_substring b pos len] adds [len] characters from byte array
          [b], starting at character number [pos], to the running
          hash computation. *)

    method add_string: string -> unit
      (** [add_string str] adds all characters of string [str]
          to the running hash computation. *)

    method add_char: char -> unit
      (** [add_char c] adds character [c] to the running hash computation. *)

    method add_byte: int -> unit
      (** [add_byte b] adds the character having code [b]
          to the running hash computation.  [b] must be between [0] and [255]
          inclusive. *)

    method result: string
      (** Terminate the hash computation and return the hash value for
          the input data provided via the [add_*] methods.  The hash
          value is a string of length [hash_size] characters.
          After calling [result], the hash can no longer accept
          additional data.  Hence, do not call any of the [add_*] methods
          after [result]. *)

    method hash_size: int
      (** Return the size of hash values produced by this hash function,
          in bytes. *)

    method wipe: unit
      (** Erase all internal buffers and data structures of this hash,
          overwriting them with zeroes.  See {!Cryptokit.transform.wipe}. *)
  end

val hash_string: hash -> string -> string
  (** [hash_string h s] runs the string [s] through the hash function [h]
      and returns the hash value of [s].  
      The hash [h] is wiped before returning, hence can
      no longer be used for further hash computations. *)

val hash_channel: hash -> ?len:int -> in_channel -> string
  (** [hash_channel h ic] reads characters from the input channel [ic],
      computes their hash value and returns it.
      If the optional [len] argument is provided, exactly [len] characters
      are read from [ic] and hashed; [End_of_file] is raised if [ic]
      does not contain at least [len] characters.
      If [len] is not provided, [ic] is read all the way to end of file.      
      The hash [h] is wiped before returning, hence can
      no longer be used for further hash computations. *)

(** {1 Utilities: random numbers and padding schemes} *)

(** The [Random] module provides random and pseudo-random number generators
    suitable for generating cryptographic keys, nonces, or challenges. *)
module Random : sig

  class type rng =
    object

      method random_bytes: bytes -> int -> int -> unit
        (** [random_bytes buf pos len] stores [len] random bytes
            in byte array [buf], starting at position [pos]. *)

      method wipe: unit
        (** Erases the internal state of the generator.
            Do not call [random_bytes] after calling [wipe]. *)
    end
    (** Generic interface for a random number generator. *)

  val string: rng -> int -> string
    (** [string rng len] returns a string of [len] random bytes
        read from the generator [rng]. *)

  val secure_rng: rng
    (** A high-quality random number generator, using hard-to-predict
        system data to generate entropy.  This generator either uses
        the OS-provided RNG, if any, or reads from
        [/dev/random] on systems that supports it, or interrogates
        the EGD daemon otherwise (see [http://egd.sourceforge.net/]).
        For EGD, the following paths are tried to locate the Unix socket
        used to communicate with EGD:
        - the value of the environment variable [EGD_SOCKET];
        - [$HOME/.gnupg/entropy];
        - [/var/run/egd-pool]; [/dev/egd-pool]; [/etc/egd-pool].

        The method [secure_rng#random_bytes] fails
        if no suitable RNG is available.
        [secure_rng#random_bytes] may block until enough entropy
        has been gathered.  Do not use for generating large quantities
        of random data, otherwise you could exhaust the entropy sources
        of the system. *)

  val system_rng: unit -> rng
    (** [system_rng ()] returns a random number generator derived
        from the OS-provided RNG.  It raises [Error No_entropy_source]
        if the OS does not provide a secure RNG.  Currently, this function
        is supported under Win32, and always fails under Unix. *)

  val device_rng: string -> rng
    (** [device_rng devicename] returns a random number generator
        that reads from the special file [devicename], e.g.
        [/dev/random] or [/dev/urandom]. *)

  val egd_rng: string -> rng
    (** [egd_rng egd_socket] returns a random number generator
        that uses the Entropy Gathering Daemon ([http://egd.sourceforge.net/]).
        [egd_socket] is the path to the Unix socket that EGD uses for
        communication.  *)

  val hardware_rng: unit -> rng
    (** A hardware random number generator based on the [RDRAND] instruction
        of the x86 architecture.  Available only on recent Intel and AMD
        x86 processors in 64-bit mode.  Raises [Error No_entropy_source]
        if not available. *)

  val pseudo_rng: string -> rng
    (** [pseudo_rng seed] returns a pseudo-random number generator
        seeded by the string [seed].  [seed] must contain at least
        16 characters, and can be arbitrarily longer than this,
        except that only the first 32 characters are used.
        The seed is used as a key for the Chacha20 stream cipher.
        The generated pseudo-random data is the result of encrypting
        the all-zero input with Chacha20.
        While this generator is believed to have very good statistical
        properties, it still does not generate ``true'' randomness:
        the entropy of the byte strings it produces cannot exceed the
        entropy contained in the seed.  As a typical use,
        [Random.pseudo_rng (Random.string Random.secure_rng 20)] returns a
        generator that can generate arbitrarily long strings of pseudo-random
        data without delays, and with a total entropy of approximately
        160 bits. *)

  val pseudo_rng_aes_ctr: string -> rng
    (** This is another pseudo-random number generator, based on the AES
        block cipher in counter mode.  It is slightly slower than [pseudo_rng]
        while having similar randomness characteristics.
        The only reason to use it instead of [pseudo_rng] is that AES
        has been cryptanalyzed even more than Chacha20.
        The [seed] argument must contain at least 16 characters.  Only the
        first 16 characters are used, as an AES key.  The generated
        pseudo-random data is the result of encrypting the 128-bit integers
        [0, 1, 2, ...] with this key. *)

end        

(** The [Padding] module defines a generic interface
    for padding input data to an integral number of blocks,
    as well as two popular padding schemes. *)
module Padding : sig

  class type scheme =
    object

      method pad: bytes -> int -> unit
        (** [pad buf used] is called with a byte array [buf]
            containing valid input data at positions [0, ..., used-1].
            The [pad] method must write padding characters in positions
            [used] to [Bytes.length str - 1].  It is guaranteed that
            [used < Bytes.length str], so that at least one character of
            padding must be added.  The padding scheme must be unambiguous
            in the following sense: from [buf] after padding, it must be
            possible to determine [used] unambiguously.  (This is what
            method {!Cryptokit.Padding.scheme.strip} does.) *)

      method strip: bytes -> int
        (** This is the converse of the [pad] operation: from a padded
            byte array [buf] as built by method [pad], [strip buf] determines
            and returns the starting position of the padding data,
            or equivalently the length of valid, non-padded input data
            in [buf].  This method must raise [Error Bad_padding] if
            [buf] does not have the format of a padded block as produced
            by [pad]. *)
    end
    (** Generic interface of a padding scheme. *)

  val length: scheme
    (** This padding scheme pads data with [n] copies of the character
        having code [n].  The integer [n] lies between 1 and the block
        size (included).  This constraint ensures non-ambiguity.
        This scheme is defined in RFC 2040 and in PKCS 5 and 7. *)

  val _8000: scheme
    (** This padding scheme pads data with one [0x80] byte, followed
        by as many [0] bytes as needed to fill the block. *)
end

(** {1 Cryptographic primitives (simplified interface)} *)

(** The [Cipher] module implements the AES, DES, Triple-DES, ARCfour
    and Blowfish symmetric ciphers.  Symmetric ciphers are presented
    as transforms parameterized by a secret key and a ``direction''
    indicating whether encryption or decryption is to be performed.
    The same secret key is used for encryption and for decryption. *)
module Cipher : sig

  type direction = Encrypt | Decrypt
    (** Indicate whether the cipher should perform encryption
        (transforming plaintext to ciphertext) or decryption
        (transforming ciphertext to plaintext). *)

  type chaining_mode =
      ECB
    | CBC
    | CFB of int
    | OFB of int
    | CTR
    | CTR_N of int
    (** Block ciphers such as AES or DES map a fixed-sized block of
        input data to a block of output data of the same size.
        A chaining mode indicates how to extend them to multiple blocks
        of data.  The five chaining modes supported in this library are:
        - [ECB]: Electronic Code Book mode.
        - [CBC]: Cipher Block Chaining mode.
        - [CFB n]:  Cipher Feedback Block with [n] bytes.
        - [OFB n]: Output Feedback Block with [n] bytes
        - [CTR]: Counter mode, incrementing all the bytes of the IV
        - [CTR_N n]: Counter mode, incrementing only the final [n]
          bytes of the IV.  For example, [CTR_N 4] increments
          the final 32 bits of the IV, as in NIST Special Publication
          800-38D.

        A detailed description of these modes is beyond the scope of
        this documentation; refer to a good cryptography book.
        [CBC] is a recommended default.  For [CFB n] and [OFB n],
        note that the blocksize is reduced to [n], but encryption
        speed drops by a factor of [blocksize / n], where [blocksize]
        is the block size of the underlying cipher; moreover, [n]
        must be between [1] and [blocksize] included.  For [CTR_N n],
        [n] must be between [1] and [blocksize] included.
        [CTR] is equivalent to [CTR_N blocksize]. *)

(** {2 Recommended ciphers} *)

  val aes: ?mode:chaining_mode -> ?pad:Padding.scheme -> ?iv:string ->
             string -> direction -> transform
    (** AES is the Advanced Encryption Standard, also known as Rijndael.
        This is a modern block cipher, recently standardized.
        It processes data by blocks of 128 bits (16 bytes),
        and supports keys of 128, 192 or 256 bits.
        The string argument is the key; it must have length 16, 24 or 32.
        The direction argument specifies whether encryption or decryption
        is to be performed.

        The optional [mode] argument specifies a
        chaining mode, as described above; [CBC] is used by default.

        The optional [pad] argument specifies a padding scheme to
        pad cleartext to an integral number of blocks.  If no [pad]
        argument is given, no padding is performed and the length
        of the cleartext must be an integral number of blocks.

        The optional [iv] argument is the initialization vector used
        by the chaining mode.  It is ignored in ECB mode.  If
        provided, it must be a string of the same size as the block
        size (16 bytes).  If omitted, the null initialization vector
        (16 zero bytes) is used.

        The [aes] function returns a transform that performs encryption
        or decryption, depending on the direction argument. *)

  val chacha20: ?iv:string -> ?ctr:int64 -> string -> direction -> transform
    (** Chacha20 is a stream cipher proposed by D. J. Bernstein in 2008.

        The Chacha20 cipher is a stream cipher, not a block cipher.
        Hence, its natural block size is 1, and no padding is
        required.  Chaining modes do not apply.  A feature of stream
        ciphers is that the xor of two ciphertexts obtained with the
        same key is the xor of the corresponding plaintexts, which
        allows various attacks.  Hence, the same key must never be
        reused.

        The string argument is the key; its length must be either 16
        or (better) 32.  

        The optional [iv] argument is the initialization vector (also
        called nonce) that can be used to diversify the key.  If present,
        it must be 8 characters long.  If absent, it is taken to be
        eight zero bytes.

        The optional [ctr] argument is the initial value of the internal
        counter.  If absent, it defaults to 0.

        The direction argument is present for consistency with the
        other ciphers only, and is actually ignored: for all stream
        ciphers, decryption is the same function as encryption. *)

(** {2 Weaker, older ciphers, not recommended for new applications} *)

  val des: ?mode:chaining_mode -> ?pad:Padding.scheme -> ?iv:string ->
             string -> direction -> transform
    (** DES is the Data Encryption Standard.  Very popular in the past,
        but now completely insecure owing to its small key size (56 bits)
        which can easily be broken by brute-force enumeration.
        It should therefore be considered as weak encryption.
        Its block size is 64 bits (8 bytes).
        The arguments to the [des] function have the same meaning as
        for the {!Cryptokit.Cipher.aes} function.  The key argument is
        a string of length 8 (64 bits); the least significant bit of
        each key byte is ignored. *)

  val triple_des: ?mode:chaining_mode -> ?pad:Padding.scheme -> ?iv:string ->
             string -> direction -> transform
    (** Triple DES with two or three DES keys.
        This is a popular variant of DES
        where each block is encrypted with a 56-bit key [k1],
        decrypted with another 56-bit key [k2], then re-encrypted with
        either [k1] or a third 56-bit key [k3].
        This results in a 112-bit or 168-bit key length that resists
        brute-force attacks.  However, the three encryptions required
        on each block make this cipher quite slow (4 times slower than
        AES).  Moreover, the small block size (64 bits) opens the way
        to collision-based attacks.  Triple DES should therefore be
        considered as relatively weak encryption.
        The arguments to the [triple_des] function have the
        same meaning as for the {!Cryptokit.Cipher.aes} function.  The
        key argument is a string of length 16 or 24, representing the
        concatenation of the key parts [k1], [k2], and optionally
        [k3].  The least significant bit of each key byte is
        ignored. *)

  val arcfour: string -> direction -> transform
    (** ARCfour (``alleged RC4'') is a fast stream cipher
        that appears to produce equivalent results with the commercial
        RC4 cipher from RSA Data Security Inc.  This company holds the
        RC4 trademark, and sells the real RC4 cipher.  So, it is prudent
        not to use ARCfour in a commercial product.

        ARCfour is popular for its speed: approximately 2 times faster
        than AES.  It accepts any key length up to 2048 bits.  However,
        the security of ARCfour is being questioned owing to several
        statistical biases in its output.  It should not be used for
        new applications.

        The ARCfour cipher is a stream cipher, not a block cipher.
        Hence, its natural block size is 1, and no padding is
        required.  Chaining modes do not apply.  A feature of stream
        ciphers is that the xor of two ciphertexts obtained with the
        same key is the xor of the corresponding plaintexts, which
        allows various attacks.  Hence, the same key must never be
        reused.

        The string argument is the key; its length must be between
        1 and 256 inclusive.  The direction argument is present for
        consistency with the other ciphers only, and is actually
        ignored: for all stream ciphers, decryption is the same
        function as encryption. *)

  val blowfish: ?mode:chaining_mode -> ?pad:Padding.scheme -> ?iv:string ->
             string -> direction -> transform
    (** Blowfish is a fast block cipher proposed by B.Schneier in 1994.
        It processes data by blocks of 64 bits (8 bytes),
        and supports keys of 32 to 448 bits.

        The small block size (64 bits) of Blowfish opens the way to
        some collision-based attacks.  Depending on the application,
        ciphers with larger block size should be preferred.

        The string argument is the key; its length must be between
        4 and 56.

        The direction argument specifies whether encryption or decryption
        is to be performed.

        The optional [mode] argument specifies a
        chaining mode, as described above; [CBC] is used by default.

        The optional [pad] argument specifies a padding scheme to
        pad cleartext to an integral number of blocks.  If no [pad]
        argument is given, no padding is performed and the length
        of the cleartext must be an integral number of blocks.

        The optional [iv] argument is the initialization vector used
        by the chaining mode.  It is ignored in ECB mode.
        If provided, it must be a string of the same size as the block size
        (8 bytes).  If omitted, the null initialization vector
        (8 zero bytes) is used.

        The [blowfish] function returns a transform that performs encryption
        or decryption, depending on the direction argument. *)
end

(** The [Hash] module implements unkeyed cryptographic hashes (SHA-1,
    SHA-256, SHA-512, SHA-3, RIPEMD-160 and MD5), also known as
    message digest functions.
    Hash functions used in cryptography are characterized as being
    <I>one-way</I> (given a hash value, it is computationally
    infeasible to find a text that hashes to this value) and
    <I>collision-resistant</I> (it is computationally infeasible to
    find two different texts that hash to the same value).  Thus, the
    hash of a text can be used as a compact replacement for this text
    for the purposes of ensuring integrity of the text. *)
module Hash : sig

(** {2 Recommended hashes} *)

  val sha3: int -> hash
    (** SHA-3, the latest NIST standard for cryptographic hashing,
        produces hashes of 224, 256, 384 or 512 bits (24, 32, 48 or 64
        bytes).  The parameter is the desired size of the hash, in
        bits.  It must be one of 224, 256, 384 or 512. *)

  val keccak: int -> hash
    (** The Keccak submission for the SHA-3 is very similar to [sha3] but
        uses a slightly different padding.  The parameter is the same as
        that of [sha3]. *)

  val sha2: int -> hash
    (** SHA-2, another NIST standard for cryptographic hashing, produces
        hashes of 224, 256, 384, or 512 bits (24, 32, 48 or 64 bytes).
        The parameter is the desired size of the hash, in
        bits.  It must be one of 224, 256, 384 or 512. *)

  val sha224: unit -> hash
    (** SHA-224 is SHA-2 specialized to 224 bit hashes (24 bytes). *)

  val sha256: unit -> hash
    (** SHA-256 is SHA-2 specialized to 256 bit hashes (32 bytes). *)

  val sha384: unit -> hash
    (** SHA-384 is SHA-2 specialized to 384 bit hashes (48 bytes). *)

  val sha512: unit -> hash
    (** SHA-512 is SHA-2 specialized to 512 bit hashes (64 bytes). *)

  val blake2b: int -> hash
    (** The BLAKE2b hash function produces hashes of length 1 to 64 bytes.
        The parameter is the desired size of the hash, in bits.
        It must be between 8 and 512, and a multiple of 8. *)

  val blake2b512: unit -> hash
    (** BLAKE2b512 is BLAKE2b specialized to 512 bit hashes (64 bytes). *)

  val blake2s: int -> hash
    (** The BLAKE2s hash function produces hashes of length 1 to 32 bytes.
        The parameter is the desired size of the hash, in bits.
        It must be between 8 and 256, and a multiple of 8. *)

  val blake2s256: unit -> hash
    (** BLAKE2s256 is BLAKE2s specialized to 256 bit hashes (32 bytes). *)

  val ripemd160: unit -> hash
    (** RIPEMD-160 produces 160-bit hashes (20 bytes).  *)

(** {2 Weak hashes, not recommended for new applications} *)

  val sha1: unit -> hash
    (** SHA-1 is the Secure Hash Algorithm revision 1.  It is a NIST
        standard, is widely used, and produces 160-bit hashes (20 bytes).
        While popular in many legacy applications, it is now known
        to be insecure.  In particular, it is not collision-resistant. *)

  val md5: unit -> hash
    (** MD5 is an older hash function, producing 128-bit hashes (16 bytes).
        While popular in many legacy applications, it is now known
        to be insecure.  In particular, it is not collision-resistant. *)
end

(** The [MAC] module implements message authentication codes, also
    known as keyed hash functions.  These are hash functions parameterized
    by a secret key.  In addition to being one-way and collision-resistant,
    a MAC has the property that without knowing the secret key, it is
    computationally infeasible to find the hash for a known text,
    even if many pairs of (text, MAC) are known to the attacker.
    Thus, MAC can be used to authenticate the sender of a text:
    the receiver of a (text, MAC) pair can recompute the MAC from the text,
    and if it matches the transmitted MAC, be reasonably certain that
    the text was authentified by someone who possesses the secret key.

    The module [MAC] provides six MAC functions based on the hashes
    BLAKE2b, SHA-1, SHA256, SHA512, RIPEMD160 and MD5,
    and five MAC functions based on the block ciphers AES, DES, and Triple-DES.
*)
module MAC: sig

  val hmac_sha1: string -> hash
    (** [hmac_sha1 key] returns a MAC based on the HMAC construction (RFC2104)
        applied to SHA-1.  The returned hash values are 160 bits (20 bytes)
        long.  The [key] argument is the MAC key; it can have any length,
        but a minimal length of 20 bytes is recommended. *)

  val hmac_sha256: string -> hash
    (** [hmac_sha256 key] returns a MAC based on the HMAC construction
        (RFC2104) applied to SHA-256.  The returned hash values are
        256 bits (32 bytes) long.  The [key] argument is the MAC key;
        it can have any length, but a minimal length of 32 bytes is
        recommended. *)

  val hmac_sha512: string -> hash
    (** [hmac_sha512 key] returns a MAC based on the HMAC construction
        (RFC2104) applied to SHA-512.  The returned hash values are
        512 bits (64 bytes) long.  The [key] argument is the MAC key;
        it can have any length, but a minimal length of 64 bytes is
        recommended. *)

  val hmac_ripemd160: string -> hash
    (** [hmac_ripemd160 key] returns a MAC based on the HMAC
        construction (RFC2104) applied to RIPEMD-160.  The returned
        hash values are 160 bits (20 bytes) long.  The [key] argument
        is the MAC key; it can have any length, but a minimal length
        of 20 bytes is recommended. *)

  val hmac_md5: string -> hash
    (** [hmac_md5 key] returns a MAC based on the HMAC construction (RFC2104)
        applied to MD5.  The returned hash values are 128 bits (16 bytes)
        long.  The [key] argument is the MAC key; it can have any length,
        but a minimal length of 16 bytes is recommended. *)

  val blake2b: int -> string -> hash
    (** [blake2b sz key] is the BLAKE2b keyed hash function.
        The returned hash values have length 1 to 64 bytes.
        The [sz] is the desired size of the hash, in bits.
        It must be between 8 and 512, and a multiple of 8.
        The [key] argument is the MAC key.  It must have length 64 at most.
        A length of 64 bytes is recommended. *)

  val blake2b512: string -> hash
    (** [blake2b512 key] is the BLAKE2b keyed hash function specialized
        to 512 byte hashes (64 bytes).
        The [key] argument is the MAC key.  It must have length 64 at most.
        A length of 64 bytes is recommended. *)

  val blake2s: int -> string -> hash
    (** [blake2s sz key] is the BLAKE2s keyed hash function.
        The returned hash values have length 1 to 32 bytes.
        The [sz] is the desired size of the hash, in bits.
        It must be between 8 and 256, and a multiple of 8.
        The [key] argument is the MAC key.  It must have length 32 at most.
        A length of 32 bytes is recommended. *)

  val blake2s256: string -> hash
    (** [blake2s256 key] is the BLAKE2s keyed hash function specialized
        to 256 byte hashes (32 bytes).
        The [key] argument is the MAC key.  It must have length 32 at most.
        A length of 32 bytes is recommended. *)

  val aes_cmac: ?iv:string -> string -> hash
    (** [aes_cmac key] returns a MAC based on AES encryption in CMAC mode,
        also known as OMAC1 mode.  The input data is encrypted using
        AES in CBC mode, with a special treatment of the final block
        that makes this MAC suitable for input data of variable length.
        The final value of the initialization vector is the MAC value.
        Thus, the returned hash values are 128 bit (16 bytes) long.
        The [key] argument is the MAC key; it must have length 16, 24,
        or 32.  The optional [iv] argument is the first value of the
        initialization vector, and defaults to 0. *)

  val aes: ?iv:string -> ?pad:Padding.scheme -> string -> hash
    (** [aes key] returns a MAC based on AES encryption in CBC mode.
        Unlike [aes_cmac], there is no special treatment for the final
        block, except padding it as per the optional [pad] argument.
        This makes this MAC weak when used with input data of variable
        length.  (It is fine for data of fixed length, though.)
        The returned hash values are 128 bit (16 bytes) long.  The
        [key] argument is the MAC key; it must have length 16, 24, or
        32.  The optional [iv] argument is the first value of the
        initialization vector, and defaults to 0.  The optional [pad]
        argument specifies a padding scheme to pad input to an
        integral number of 16-byte blocks. *)

  val des: ?iv:string -> ?pad:Padding.scheme -> string -> hash
    (** [des key] returns a MAC based on DES encryption in CBC mode.
        The construction is identical to that used for the [aes] MAC.
        The key size is 64 bits (8 bytes), of which only 56 are used.
        The returned hash value has length 8 bytes.
        Due to the small hash size and key size, this MAC is weak. *)

  val triple_des: ?iv:string -> ?pad:Padding.scheme -> string -> hash
    (** [triple_des key] returns a MAC based on triple DES encryption in CBC mode.
        The construction is identical to that used for the [aes] MAC.
        The key size is 16 or 24 bytes.  The returned hash value has
        length 8 bytes.  The key size is sufficient to protect against
        brute-force attacks, but the small hash size means that this
        MAC is not collision-resistant. *)

  val des_final_triple_des: ?iv:string -> ?pad:Padding.scheme -> string -> hash
    (** [des_final_triple_des key] returns a MAC that uses DES CBC
        with the first 8 bytes of [key] as key.  The final initialization
        vector is then DES-decrypted with bytes 8 to 15 of [key],
        and DES-encrypted again with either the last 8 bytes of [key]
        (if a triple-length key is provided) or the first 8 bytes of [key]
        (if a double-length key is provided).
        Thus, the key is 16 or 24 bytes long, of which
        112 or 168 bits are used.  The overall construction has the same
        key size as a triple DES MAC, but runs faster because triple
        encryption is not performed on all data blocks, but only on
        the final MAC. *)
end

(** The [RSA] module implements RSA public-key cryptography.
    Public-key cryptography is asymmetric: two distinct keys are used
    for encrypting a message, then decrypting it.  Moreover, while one of
    the keys must remain secret, the other can be made public, since
    it is computationally very hard to reconstruct the private key
    from the public key.   This feature supports both public-key
    encryption (anyone can encode with the public key, but only the
    owner of the private key can decrypt) and digital signature
    (only the owner of the private key can sign, but anyone can check
    the signature with the public key). *)
module RSA: sig

  type key =
    { size: int;     (** Size of the modulus [n], in bits *)
      n: string;     (** Modulus [n = p.q] *)
      e: string;     (** Public exponent [e] *)
      d: string;     (** Private exponent [d] *)
      p: string;     (** Prime factor [p] of [n] *)
      q: string;     (** The other prime factor [q] of [n] *)
      dp: string;    (** [dp] is [d mod (p-1)] *)
      dq: string;    (** [dq] is [d mod (q-1)] *)
      qinv: string   (** [qinv] is a multiplicative inverse of [q] modulo [p] *)
    }
    (** The type of RSA keys.  Components [size], [n] and [e] define
        the public part of the key.  Components [size], [n] and [d]
        define the private part of the key.  To speed up private key operations
        through the use of the Chinese remainder theorem (CRT), additional
        components [p], [q], [dp], [dq] and [qinv] are provided.  These
        are part of the private key. *)

  val wipe_key: key -> unit
    (** Erase all components of a RSA key. *)

  val new_key: ?rng: Random.rng -> ?e: int -> int -> key
    (** Generate a new, random RSA key.  The non-optional [int]
        argument is the desired size for the modulus, in bits
        (e.g. 2048).  The optional [rng] argument specifies a random
        number generator to use for generating the key; it defaults to
        {!Cryptokit.Random.secure_rng}.  The optional [e] argument
        specifies the public exponent desired.  If not specified, [e]
        is chosen randomly.  Small values of [e] such as
        [e = 65537] significantly speeds up encryption and
        signature checking compared with a random [e].
        Very small values of [e] such as [e = 3] can weaken security
        and are best avoided.
        The result of [new_key] is a complete RSA key with all
        components defined: public, private, and private for use with
        the CRT. *)

  val encrypt: key -> string -> string
    (** [encrypt k msg] encrypts the string [msg] with the public part
        of key [k] (components [n] and [e]).
        [msg] must be smaller than [key.n] when both strings
        are viewed as natural numbers in big-endian notation.
        In practice, [msg] should be of length [key.size / 8 - 1],
        using padding if necessary.  If you need to encrypt longer plaintexts
        using RSA, encrypt them with a symmetric cipher, using a
        randomly-generated key, and encrypt only that key with RSA. *)

  val decrypt: key -> string -> string
    (** [decrypt k msg] decrypts the ciphertext string [msg] with the
        private part of key [k] (components [n] and [d]).  The size of
        [msg] is limited as described for {!Cryptokit.RSA.encrypt}. *)

  val decrypt_CRT: key -> string -> string
    (** [decrypt_CRT k msg] decrypts the ciphertext string [msg] with
        the CRT private part of key [k] (components [n], [p], [q],
        [dp], [dq] and [qinv]).  The use of the Chinese remainder
        theorem (CRT) allows significantly faster decryption than
        {!Cryptokit.RSA.decrypt}, at no loss in security.  The size of
        [msg] is limited as described for {!Cryptokit.RSA.encrypt}. *)

  val sign: key -> string -> string
    (** [sign k msg] encrypts the plaintext string [msg] with the
        private part of key [k] (components [n] and [d]), thus
        performing a digital signature on [msg].
        The size of [msg] is limited as described for {!Cryptokit.RSA.encrypt}.
        If you need to sign longer messages, compute a cryptographic
        hash of the message and sign only the hash with RSA. *)

  val sign_CRT: key -> string -> string
    (** [sign_CRT k msg] encrypts the plaintext string [msg] with the
        CRT private part of key [k] (components [n], [p], [q], [dp],
        [dq] and [qinv]), thus performing a digital signature on
        [msg].  The use of the Chinese remainder theorem (CRT) allows
        significantly faster signature than {!Cryptokit.RSA.sign}, at
        no loss in security.  The size of [msg] is limited as
        described for {!Cryptokit.RSA.encrypt}. *)

  val unwrap_signature: key -> string -> string
    (** [unwrap_signature k msg] decrypts the ciphertext string [msg]
        with the public part of key [k] (components [n] and [d]),
        thus extracting the plaintext that was signed by the sender.
        The size of [msg] is limited as described for
        {!Cryptokit.RSA.encrypt}. *)
end

(** The [DH] module implements Diffie-Hellman key agreement.
  Key agreement is a protocol by which two parties can establish
  a shared secret (typically a key for a symmetric cipher or MAC)
  by exchanging messages, with the guarantee that even if an attacker
  eavesdrop on the messages, he cannot recover the shared secret.
  Diffie-Hellman is one such key agreement protocol, relying on
  the difficulty of computing discrete logarithms.  Notice that 
  the Diffie-Hellman protocol is vulnerable to active attacks
  (man-in-the-middle attacks).

  The protocol executes as follows:
  - Both parties must agree beforehand on a set of public parameters
    (type {!Cryptokit.DH.parameters}).  Suitable parameters
    can be generated by calling {!Cryptokit.DH.new_parameters},
    or fixed parameters taken from the literature can be used.
  - Each party computes a random private secret using the function
    {!Cryptokit.DH.private_secret}.
  - From its private secrets and the public parameters, each party
    computes a message (a string) with the function {!Cryptokit.DH.message},
    and sends it to the other party.
  - Each party recovers the shared secret by applying the function
    {!Cryptokit.DH.shared_secret} to its private secret and to the
    message received from the other party.
  - Fixed-size keys can then be derived from the shared secret
    using the function {!Cryptokit.DH.derive_key}.
*)
module DH: sig

  type parameters =
    { p: string;                 (** Large prime number *)
      g: string;                 (** Generator of [Z/pZ] *)
      privlen: int               (** Length of private secrets in bits *)
    }
    (** The type of Diffie-Hellman parameters.  These parameters
      need to be agreed upon by the two parties before the key agreement
      protocol is run.  The parameters are public and can be reused
      for several runs of the protocol. *)

  val new_parameters: ?rng: Random.rng -> ?privlen: int -> int -> parameters
    (** Generate a new set of Diffie-Hellman parameters.
      The non-optional argument is the size in bits of the [p] parameter.
      It must be large enough that the discrete logarithm problem modulo
      [p] is computationally unsolvable.  2048 is a reasonable value.
      The optional [rng] argument specifies a random number generator
      to use for generating the parameters; it defaults to
      {!Cryptokit.Random.secure_rng}.  The optional [privlen] argument
      is the size in bits of the private secrets that are generated
      during the key agreement protocol; the default is 160. *)

  type private_secret
    (** The abstract type of private secrets generated during key agreement. *)

  val private_secret: ?rng: Random.rng -> parameters -> private_secret
    (** Generate a random private secret.  
      The optional [rng] argument specifies a random number generator
      to use; it defaults to {!Cryptokit.Random.secure_rng}. *)

  val message: parameters -> private_secret -> string
    (** Compute the message to be sent to the other party. *)

  val shared_secret: parameters -> private_secret -> string -> string
    (** Recover the shared secret from the private secret of the
      present party and the message received from the other party.
      The shared secret returned is a string of the same length as
      the [p] parameter. The private secret is destroyed and can no
      longer be used afterwards. *)

  val derive_key: ?diversification: string -> string -> int -> string
    (** [derive_key shared_secret numbytes] derives a secret string
      (typically, a key for symmetric encryption) from the given shared
      secret.  [numbytes] is the desired length for the returned string.
      The optional [diversification] argument is an arbitrary string
      that defaults to the empty string.  Different secret strings can
      be obtained from the same shared secret by supplying different
      [diversification] argument.  The computation of the secret
      string is performed by SHA-1 hashing of the diversification
      string, followed by the shared secret, followed by an integer
      counter.  The hashing is repeated with increasing values of the
      counter until [numbytes] bytes have been obtained. *)
end

(** {1 Advanced, compositional interface to block ciphers 
       and stream ciphers} *)

(** The [Block] module provides classes that implements
    popular block ciphers, chaining modes, and wrapping of a block cipher
    as a general transform or as a hash function.
    The classes can be composed in a Lego-like fashion, facilitating
    the integration of new block ciphers, modes, etc. *)
module Block : sig

  class type block_cipher =
    object

      method blocksize: int
        (** The size in bytes of the blocks manipulated by the cipher. *)

      method transform: bytes -> int -> bytes -> int -> unit
        (** [transform src spos dst dpos] encrypts or decrypts one block
            of data.  The input data is read from byte array [src] at
            positions [spos, ..., spos + blocksize - 1], and the output
            data is stored in byte array [dst] at positions
            [dpos, ..., dpos + blocksize - 1]. *)

      method wipe: unit
        (** Erase the internal state of the block cipher, such as
            all key-dependent material. *)
    end
      (** Abstract interface for a block cipher. *)

  (** {1 Deriving transforms and hashes from block ciphers} *)

  class cipher: block_cipher -> transform
    (** Wraps a block cipher as a general transform.  The transform
        has input block size and output block size equal to the
        block size of the block cipher.  No padding is performed.
        Example: [new cipher (new cbc_encrypt (new aes_encrypt key))]
        returns a transform that performs AES encryption in CBC mode. *)

  class cipher_padded_encrypt: Padding.scheme -> block_cipher -> transform
    (** Like {!Cryptokit.Block.cipher}, but performs padding on the input data
        as specified by the first argument.  The input block size of
        the returned transform is 1; the output block size is the
        block size of the block cipher. *)

  class cipher_padded_decrypt: Padding.scheme -> block_cipher -> transform
    (** Like {!Cryptokit.Block.cipher}, but removes padding on the output data
        as specified by the first argument.  The output block size of
        the returned transform is 1; the input block size is the
        block size of the block cipher. *)

  class mac: ?iv: string -> ?pad: Padding.scheme -> block_cipher -> hash
    (** Build a MAC (keyed hash function) from the given block cipher.
        The block cipher is run in CBC mode, and the MAC value is
        the final value of the initialization vector.
        Thus, the hash size of the resulting
        hash is the block size of the block cipher.
        The optional argument [iv] specifies the first initialization
        vector, with a default of all zeroes.  The optional argument
        [pad] specifies a padding scheme to be applied to the input
        data; if not provided, no padding is performed. *)

  class mac_final_triple: ?iv: string -> ?pad: Padding.scheme ->
                          block_cipher -> block_cipher -> block_cipher -> hash
    (** Build a MAC (keyed hash function) from the given block ciphers
        [c1], [c2] and [c3].  The input is run through [c1] in CBC
        mode, as described for {!Cryptokit.Block.mac}.  The final
        initialization vector is then super-enciphered by [c2], then
        by [c3], to provide the final MAC.  This construction results
        in a MAC that is as nearly as fast as {!Cryptokit.Block.mac}
        [c1], but more resistant against brute-force key search
        because of the additional final encryption through [c2] and
        [c3]. *)

  (** {1 Some block ciphers: AES, DES, triple DES, Blowfish} *)

  class aes_encrypt: string -> block_cipher
    (** The AES block cipher, in encryption mode.  The string argument
        is the key; its length must be 16, 24 or 32 bytes. *)

  class aes_decrypt: string -> block_cipher
    (** The AES block cipher, in decryption mode. *)

  class des_encrypt: string -> block_cipher
    (** The DES block cipher, in encryption mode.  The string argument
        is the key; its length must be 8 bytes. *)

  class des_decrypt: string -> block_cipher
    (** The DES block cipher, in decryption mode. *)

  class triple_des_encrypt: string -> block_cipher
    (** The Triple-DES block cipher, in encryption mode.
        The key argument must have length 16 (two keys) or 24 (three keys). *)

  class triple_des_decrypt: string -> block_cipher
    (** The Triple-DES block cipher, in decryption mode. *)

  class blowfish_encrypt: string -> block_cipher
    (** The Blowfish block cipher, in encryption mode.  The string argument
        is the key; its length must be between 4 and 56. *)

  class blowfish_decrypt: string -> block_cipher
    (** The Blowfish block cipher, in decryption mode. *)

  (** {1 Chaining modes} *)

  class cbc_encrypt: ?iv: string -> block_cipher -> block_cipher
    (** Add Cipher Block Chaining (CBC) to the given block cipher
        in encryption mode.
        Each block of input is xor-ed with the previous output block
        before being encrypted through the given block cipher.
        The optional [iv] argument specifies the string to be xor-ed
        with the first input block, and defaults to all zeroes.
        The returned block cipher has the same block size as the
        underlying block cipher. *)

  class cbc_decrypt: ?iv: string -> block_cipher -> block_cipher
    (** Add Cipher Block Chaining (CBC) to the given block cipher
        in decryption mode.  This works like {!Cryptokit.Block.cbc_encrypt}, 
        except that input blocks are first decrypted by the block
        cipher before being xor-ed with the previous input block. *)

  class cfb_encrypt: ?iv: string -> int -> block_cipher -> block_cipher
    (** Add Cipher Feedback Block (CFB) to the given block cipher
        in encryption mode.  The integer argument [n] is the number of
        bytes processed at a time; it must lie between [1] and
        the block size of the underlying cipher, included.
        The returned block cipher has block size [n]. *)

  class cfb_decrypt: ?iv: string -> int -> block_cipher -> block_cipher
    (** Add Cipher Feedback Block (CFB) to the given block cipher
        in decryption mode.  See {!Cryptokit.Block.cfb_encrypt}. *)

  class ofb: ?iv: string -> int -> block_cipher -> block_cipher
    (** Add Output Feedback Block (OFB) to the given block cipher.
        The integer argument [n] is the number of
        bytes processed at a time; it must lie between [1] and
        the block size of the underlying cipher, included.        
        The returned block cipher has block size [n].
        It is usable both for encryption and decryption. *)

  class ctr: ?iv: string -> ?inc:int -> block_cipher -> block_cipher
    (** Add Counter mode to the given block cipher.  Viewing the IV
        as a [blocksize]-byte integer in big-endian representation,
        the blocks [IV], [IV+1], [IV+2], ... are encrypted using
        the given block cipher, and the result is xor-ed with the
        input blocks to produce the output blocks.  The additions
        [IV+n] are performed modulo 2 to the [8 * inc] power.
        In other words, only the low [inc] bytes of the [IV] are
        subject to incrementation; the high [blocksize - inc] bytes
        are unaffected.  [inc] defaults to [blocksize].
        The returned block cipher has the same block size as
        the underlying block cipher, and is usable both for
        encryption and decryption. *)
end

(** The [Stream] module provides classes that implement
    the ARCfour stream cipher, and the wrapping of a stream cipher
    as a general transform. The classes can be composed in a Lego-like
    fashion, facilitating the integration of new stream ciphers. *)
module Stream : sig

  class type stream_cipher =
    object
      method transform: bytes -> int -> bytes -> int -> int -> unit
        (** [transform src spos dst dpos len] encrypts or decrypts
            [len] characters, read from byte array [src] starting at
            position [spos].  The resulting [len] characters are
            stored in byte array [dst] starting at position [dpos]. *)

      method wipe: unit
        (** Erase the internal state of the stream cipher, such as
            all key-dependent material. *)
    end
      (** Abstract interface for a stream cipher. *)

  class cipher: stream_cipher -> transform
    (** Wraps an arbitrary stream cipher as a transform.
        The transform has input and output block size of 1. *)

  class arcfour: string -> stream_cipher
    (** The ARCfour (``alleged RC4'') stream cipher.
        The argument is the key, and must be of length 1 to 256.
        This stream cipher works by xor-ing the input with the
        output of a key-dependent pseudo random number generator.
        Thus, decryption is the same function as encryption. *)

  class chacha20: ?iv:string -> ?ctr:int64 -> string -> stream_cipher
    (** The Chacha20 stream cipher.
        The string argument is the key, and must be of length 16 or 32.
        The optional [iv] argument is the initialization vector
        (also known as the nonce).  If present, it must be 8 bytes long.
        If absent, it is taken to be eight zero bytes.
        The optional [ctr] argument is the initial value of the internal
        counter.  If absent, it is taken to be 0.
        This stream cipher works by xor-ing the input with the
        output of a key-dependent pseudo random number generator.
        Thus, decryption is the same function as encryption. *)
end

(** {1 Encoding and compression of data} *)

(** The [Base64] module supports the encoding and decoding of
    binary data in base 64 format, using only alphanumeric
    characters that can safely be transmitted over e-mail or
    in URLs. *)
module Base64: sig

  val encode_multiline : unit -> transform
    (** Return a transform that performs base 64 encoding.
        The output is divided in lines of length 76 characters,
        and final [=] characters are used to pad the output,
        as specified in the MIME standard. 
        The output is approximately [4/3] longer than the input. *)

  val encode_compact : unit -> transform
    (** Same as {!Cryptokit.Base64.encode_multiline}, but the output is not
        split into lines, and no final padding is added.
        This is adequate for encoding short strings for
        transmission as part of URLs, for instance. *)

  val encode_compact_pad : unit -> transform
    (** Same as {!Cryptokit.Base64.encode_compact}, but the output is
        padded with [=] characters at the end (if necessary). *)

  val decode : unit -> transform
    (** Return a transform that performs base 64 decoding.
        The input must consist of valid base 64 characters;
        blanks are ignored.  Raise [Error Bad_encoding]
        if invalid base 64 characters are encountered in the input. *)
end

(** The [Hexa] module supports the encoding and decoding of
    binary data as hexadecimal strings.  This is a popular format
    for transmitting keys in textual form. *)
module Hexa: sig

  val encode : unit -> transform
    (** Return a transform that encodes its input in hexadecimal.
        The output is twice as long as the input, and contains
        no spaces or newlines. *)

  val decode : unit -> transform
    (** Return a transform that decodes its input from hexadecimal.
        The output is twice as short as the input.  Blanks
        (spaces, tabs, newlines) in the input are ignored.
        Raise [Error Bad_encoding] if the input contains characters
        other than hexadecimal digits and blanks. *)
end

(** The [Zlib] module supports the compression and decompression
    of data, using the [zlib] library.  The algorithm used is
    Lempel-Ziv compression as in the [gzip] and [zip] compressors.
    While compression itself is not encryption, it is often used prior
    to encryption to hide regularities in the plaintext, and reduce
    the size of the ciphertext. *)
module Zlib: sig

  val compress : ?level:int -> ?write_zlib_header:bool -> unit -> transform
    (** Return a transform that compresses its input.
        The optional [level] argument is an integer between 1 and 9
        specifying how hard the transform should try to compress data:
        1 is lowest but fastest compression, while 9 is highest but
        slowest compression. The default level is 6.
        The optional [write_zlib_header] argument dictates whether the 
        output should be wrapped within a zlib header and checksum.
        The default is false. *)

  val uncompress : ?expect_zlib_header:bool -> unit -> transform
    (** Return a transform that decompresses its input.
        The optional [expect_zlib_header] argument dictates whether the
        input is wrapped within a zlib header and checksum. The default
        is false. *)
end

(** {1 Error reporting} *)

(** Error codes for this library. *)
type error =
  | Wrong_key_size
      (** The key is too long or too short for the given cipher. *)
  | Wrong_IV_size
      (** The initialization vector does not have the same size as
          the block size. *)
  | Wrong_data_length
      (** The total length of the input data for a transform is not an
          integral multiple of the input block size. *)
  | Bad_padding
      (** Incorrect padding bytes were found after decryption. *)
  | Output_buffer_overflow
      (** The output buffer for a transform exceeds the maximal length
          of a Caml string. *)
  | Incompatible_block_size
      (** A combination of two block ciphers was attempted whereby
          the ciphers have different block sizes, while they must have
          the same. *)
  | Number_too_long
      (** Denotes an internal error in RSA key generation or encryption. *)
  | Seed_too_short
      (** The seed given to a pseudo random number generator is too short. *)
  | Message_too_long
      (** The message passed to RSA encryption or decryption is greater
          than the modulus of the RSA key *)
  | Bad_encoding
      (** Illegal characters were found in an encoding of binary data
          such as base 64 or hexadecimal. *)
  | Compression_error of string * string
      (** Error during compression or decompression. *)
  | No_entropy_source
      (** No entropy source (OS, [/dev/random] or EGD) was found for
          {!Cryptokit.Random.secure_rng}. *)
  | Entropy_source_closed
      (** End of file on a device or EGD entropy source. *)
  | Compression_not_supported
      (** The data compression functions are not available. *)

exception Error of error
  (** Exception raised by functions in this library
      to report error conditions. *)

(** {1 Miscellaneous utilities} *)

val wipe_bytes : bytes -> unit
    (** [wipe_bytes b] overwrites [b] with zeroes.  Can be used
        to reduce the memory lifetime of sensitive data. *)

val wipe_string : string -> unit
    (** [wipe_string s] overwrites [s] with zeroes.  Can be used
        to reduce the memory lifetime of sensitive data.
        Note that strings are normally immutable and this operation
        violates this immutability property.  Therefore, this is
        an unsafe operation, and it should be used only by code that
        is the only owner of the string [s].  See {!Bytes.unsafe_of_string}
        for more details on the ownership policy. *)

val string_equal : string -> string -> bool
    (** Constant-time comparison between strings.
        [string_equal s1 s2] returns [true] if the strings [s1] and [s2]
        have the same length and contain the same characters.
        The execution time of this function is determined by the
        lengths of [s1] and [s2], but is independent of their contents. *)

val bytes_equal : bytes -> bytes -> bool
    (** Constant-time comparison between byte sequences.
        Like {!Cryptokit.string_equal}, but for byte sequences. *)

val xor_bytes: bytes -> int -> bytes -> int -> int -> unit
    (** [xor_bytes src spos dst dpos len] performs the xor (exclusive or)
        of characters [spos, ..., spos + len - 1] of [src]
        with characters [dpos, ..., dpos + len - 1] of [dst],
        storing the result in [dst] starting at position [dpos]. *)

val xor_string: string -> int -> bytes -> int -> int -> unit
    (** Same as [xor_bytes], but the source is a string instead of a 
        byte array. *)

val mod_power: string -> string -> string -> string
    (** [mod_power a b c] computes [a^b mod c], where the
        strings [a], [b], [c] and the result are viewed as
        arbitrary-precision integers in big-endian format.
        Requires [a < c].  *)

val mod_mult: string -> string -> string -> string
    (** [mod_mult a b c] computes [a*b mod c], where the
        strings [a], [b], [c] and the result are viewed as
        arbitrary-precision integers in big-endian format. *)
