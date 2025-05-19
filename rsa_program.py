import argparse
import sys


def is_prime(num):
    """
    Checks if an integer number is prime.

    Args:
        num (int): The number to check.

    Returns:
        bool: True if the number is prime, False otherwise.
    """

    if num <= 1:
        return False
    
    i = 2
    while i * i <= num:
        if num % i == 0:
            return False
        i += 1
        
    return True


def gcd(a, b):
    """
    Calculates the Greatest Common Divisor (GCD) of two integers using the Euclidean algorithm.

    Args:
        a (int): The first integer.
        b (int): The second integer.

    Returns:
        int: The GCD of a and b.
    """

    if (a < b):
        return gcd(b, a)

    r1, r2 = a, b

    while r2 > 0:
        q = r1 // r2

        r = r1 - q * r2
        r1 = r2
        r2 = r

    return r1


def find_e(phi):
    """
    Finds smallest integer e such that 1 < e < phi and gcd(phi, e) = 1.

    Args:
        phi (int): The value of the totient function (p-1)*(q-1).

    Returns:
        int or None: The public exponent e, or None if not found.
    """

    for e in range(2, phi):
        if gcd(phi, e) == 1:
            return e
        
    return None


def extended_gcd(a, b):
    """
    Calculates the Extended Euclidean Algorithm.
    Finds integers x, y such that ax + by = gcd(a, b).

    Args:
        a (int): The first integer.
        b (int): The second integer.

    Returns:
        A tuple (gcd, x, y) where gcd is the Greatest Common Divisor of a and b,
            and x, y are integers satisfying the equation ax + by = gcd(a, b).
    """
    
    r1, r2 = a, b
    s1, s2 = 1, 0
    t1, t2 = 0, 1

    while r2 > 0:
        q = r1 // r2

        r = r1 - q * r2
        r1 = r2
        r2 = r

        
        s = s1 - q * s2
        s1 = s2
        s2 = s

        t = t1 - q * t2
        t1 = t2
        t2 = t

    return r1, s1, t1


def find_d(phi, e):
    """
    Finds an integer d such that 1 < d < phi and (e * d) % phi = 1.

    Args:
        e (int): The public exponent.
        phi (int): The value of the totient function (p-1)*(q-1).

    Returns:
        int or None: The private exponent d if it exists, otherwise None.
    """

    gcd, x, y = extended_gcd(phi, e)
    if gcd != 1:
        return None
    else:
        return x % e if x > 0 else (x % e + e) % e


def read_key_file(filepath):
    """
    Reads two arguments from a key file.
    File format should be:
    a=<value>
    b=<value>

    Args:
        filepath (str): The path to the key file.

    Returns:
        A tuple (a, b) read from the file, or (None, None) if error.
    """

    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()

            if len(lines) < 2:
                print("Error: Unsupported key file format")
                return None, None
            
            l1 = lines[0]
            l2 = lines[1]

            if not ('=' in l1) or not ('=' in l2):
                print("Error: Unsupported key file format")
                return None, None

            a = int(l1.split('=')[1])
            b = int(l2.split('=')[1])

            return a, b
    except FileNotFoundError:
        print(f"Error: Key file '{filepath}' not found.")
        return None, None
    except (ValueError, IndexError):
        print(f"Error: Could not parse values in key file '{filepath}'.")
        return None, None


def write_to_file(filepath, lines):
    """
    Writes a list of strings to a file line by line.

    Args:
        filename (str): The name of the file to write to.
        lines (list of str): A list of strings to write to the file.
    """
    
    try:
        with open(filepath, 'w') as file:
            i, n = 1, len(lines)
            for line in lines:
                if (i < n):
                    file.write(line + '\n')
                else:
                    file.write(line)
                i += 1
    except IOError as e:
        print(f"Error writing to a file '{filepath}': {e}")


def generate_keys(p, q):
    """
    Generates RSA public and private keys based on primes p and q.
    Calculates n, phi, e, and d.
    Prints keys to stdout and writes them to files.

    Args:
        p (int): The first prime number.
        q (int): The second prime number.
    """

    if not is_prime(p) or not is_prime(q):
        print("Error: p and q must be prime numbers.")
        sys.exit(1)
    if p == q:
        print(f"Error: p and q cannot be equal.")
        sys.exit(1)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Find the public exponent
    e = find_e(phi)
    if e is None:
        print(f"Error: Could not find a public exponent 'e' for p={p} and q={q}.")
        sys.exit(1)

    # Find the private exponent
    d = find_d(e, phi)
    if d is None or (e * d) % phi != 1:
        print(f"Error: Could not find a private exponent 'd' for e={e} and phi={phi}.")
        sys.exit(1)

    # Print key information
    print(f"RSA key pair generated:")
    print(f"n={n}")
    print(f"e={e}")
    print(f"d={d}")
    print(f"phi={phi}")

    # Write keys to files
    k1 = [
        f"n={n}",
        f"e={e}",
    ]

    k2 = [
        f"n={n}",
        f"d={d}",
    ]
    
    write_to_file("public_key.txt", k1)
    write_to_file("private_key.txt", k2)


def encrypt(plaintext_file, public_key_file, output_file):
    """
    Encrypts the contents of the plaintext_file using the public key.
    Outputs ciphertext to stdout and to output_file.

    Args:
        plaintext_file (str): Path to the file containing the plaintext.
        public_key_file (str): Path to the public key file.
        output_file (str): Path to the file where ciphertext will be written.
    """

    n, e = read_key_file(public_key_file)
    if n is None or e is None:
        sys.exit(1)

    try:
        with open(plaintext_file, 'r') as file:
            plaintext = file.readline().rstrip('\n')
    except FileNotFoundError:
        print(f"Error: Plaintext file '{plaintext_file}' not found.")
        sys.exit(1)
    except IOError as err:
        print(f"Error reading plaintext file '{plaintext_file}': {err}")
        sys.exit(1)

    res = []
    for char in plaintext:
        m = ord(char) # Get ASCII decimal value
        c = pow(m, e, n) # Encrypt: c = m^e mod n
        res.append(hex(c)) # Convert to hex string and add to result

    # Join hex values with space between them
    ciphertext = " ".join(res)

    print(f"Ciphertext: {ciphertext}")

    # Write to the output file
    write_to_file(output_file, [f"{ciphertext}"])


def decrypt(ciphertext_file, private_key_file, output_file):
    """
    Decrypts the contents of the ciphertext_file using the private key.
    Outputs decrypted plaintext to stdout and to output_file.

    Args:
        ciphertext_file (str): Path to the file containing ciphertext.
        private_key_file (str): Path to the private key file.
        output_file (str): Path to the file where decrypted plaintext will be written.
    """

    n, d = read_key_file(private_key_file)
    if n is None or d is None:
        sys.exit(1)

    try:
        with open(ciphertext_file, 'r') as file:
            ciphertext = file.readline().strip()
    except FileNotFoundError:
        print(f"Error: Ciphertext file '{ciphertext_file}' not found.")
        sys.exit(1)
    except IOError as err:
        print(f"Error reading ciphertext file '{ciphertext_file}': {err}")
        sys.exit(1)

    res = []
    values = ciphertext.split(' ') # Split by space

    for hex in values:
        try:
            c = int(hex, 16) # Convert hex string to integer
        except ValueError:
            print(f"Error: Invalid hexadecimal value '{hex}' in ciphertext file.")
            sys.exit(1)

        m = pow(c, d, n) # Decrypt: m = c^d mod n
        try:
            res.append(chr(m)) # Convert ASCII decimal value back to character and add to result
        except ValueError:
             print(f"Error: Decrypted value {m} is not a valid ASCII character.")
             sys.exit(1)


    # Join characters
    plaintext = "".join(res)

    print(f"Decrypted plaintext: {plaintext}")

    # Write to output file
    write_to_file(output_file, [f"{plaintext}"])


def sign(message, private_key_file, signature_file):
    """
    Creates a digital signature for the message using the private key.
    Outputs the signature to stdout and to signature_file.

    Args:
        message (str): The message to sign.
        private_key_file (str): Path to the private key file.
        signature_file (str): Path to the file where the signature will be written.
    """

    n, d = read_key_file(private_key_file)
    if n is None or d is None:
        sys.exit(1)

    res = []
    for char in message:
        m = ord(char) # Get ASCII decimal value
        s = pow(m, d, n) # Sign: s = m^d mod n
        res.append(hex(s)) # Convert to hex string and add to result

    # Join hex values with space between them
    signature = " ".join(res)

    print(f"Signature: {signature}")

    write_to_file(signature_file, [f"{signature}"])


def verify(message, signature_file, public_key_file):
    """
    Verifies a digital signature against a message using the public key.
    Prints the verification result to stdout.

    Args:
        message (str): The message to verify against.
        signature_file (str): Path to the file containing signature.
        public_key_file (str): Path to the public key file.
    """

    n, e = read_key_file(public_key_file)
    if n is None or e is None:
        sys.exit(1)

    try:
        with open(signature_file, 'r') as file:
            signature = file.readline().strip()
    except FileNotFoundError:
        print(f"Error: Signature file '{signature_file}' not found.")
        sys.exit(1)
    except IOError as err:
        print(f"Error reading signature file '{signature_file}': {err}")
        sys.exit(1)

    res = []
    values = signature.split(' ') # Split by space

    for hex in values:
        try:
            s = int(hex, 16) # Convert hex string to integer
        except ValueError:
            print(f"Error: Invalid hexadecimal value '{hex}' in signature file.")
            sys.exit(1)

        m = pow(s, e, n) # Decrypt signature: m = s^e mod n
        try:
            res.append(chr(m)) # Convert ASCII decimal value back to character and add to result
        except ValueError:
             print("Signature is invalid")
             sys.exit(0)

    # Join characters
    decrypted_message = "".join(res)

    # Compare the decrypted message with the original message
    if decrypted_message == message:
        print("Signature is valid")
    else:
        print("Signature is invalid")


def main():
    parser = argparse.ArgumentParser(description="Program for RSA key generation, encryption, decryption, signing, and verification.")
    
    # Subparsers for mode selection
    subparsers = parser.add_subparsers(title='Modes', dest='mode', help='You must select an operation mode', required=True)
    
    # Subparser for '--generate-key' mode
    keygen_parser = subparsers.add_parser('--generate-key', help='Generate RSA key pair.')
    keygen_parser.add_argument('--p', type=int, required=True, help='First prime number (p).')
    keygen_parser.add_argument('--q', type=int, required=True, help='Second prime number (q).')

    # Subparser for '--encrypt' mode
    encrypt_parser = subparsers.add_parser('--encrypt', help='Encrypt a file using a public key.')
    encrypt_parser.add_argument('plaintext_file', help='Path to the <plaintext_file>')
    encrypt_parser.add_argument('--public-key', required=True, help='Path to the <public_key_file>')
    encrypt_parser.add_argument('--output', help='Path to the <output_file> (default is <ciphertext.txt>)', default='ciphertext.txt')

    # Subparser for '--decrypt' mode
    decrypt_parser = subparsers.add_parser('--decrypt', help='Decrypt a file using a private key.')
    decrypt_parser.add_argument('ciphertext_file', help='Path to the <ciphertext_file>')
    decrypt_parser.add_argument('--private-key', required=True, help='Path to the <private_key_file>')
    decrypt_parser.add_argument('--output', help='Path to the <output_file> (default is <decrypted.txt>)', default='decrypted.txt')

    # Subparser for '--sign' mode
    sign_parser = subparsers.add_parser('--sign', help='Sign a message using a private key.')
    sign_parser.add_argument('verification_message', help='The message to sign')
    sign_parser.add_argument('--private-key', required=True, help='Path to the <private_key_file>')
    sign_parser.add_argument('--signature', required=True, help='Path to the <signature_file>')

    # Subparser for '--verify' mode
    verify_parser = subparsers.add_parser('--verify', help='Verify a signature using a public key.')
    verify_parser.add_argument('verification_message', help='The message to verify against')
    verify_parser.add_argument('--signature', required=True, help='Path to the <signature_file>')
    verify_parser.add_argument('--public-key', required=True, help='Path to the <public_key_file>')

    # Check if mode is provided
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    # Get the mode
    mode = sys.argv[1]

    # Execute the chosen mode
    if mode == '--generate-key':
        args = keygen_parser.parse_args(sys.argv[2:])
        generate_keys(args.p, args.q)
    elif mode == '--encrypt':
        args = encrypt_parser.parse_args(sys.argv[2:])
        encrypt(args.plaintext_file, args.public_key, args.output)
    elif mode == '--decrypt':
        args = decrypt_parser.parse_args(sys.argv[2:])
        decrypt(args.ciphertext_file, args.private_key, args.output)
    elif mode == '--sign':
        args = sign_parser.parse_args(sys.argv[2:])
        sign(args.verification_message, args.private_key, args.signature)
    elif mode == '--verify':
        args = verify_parser.parse_args(sys.argv[2:])
        verify(args.verification_message, args.signature, args.public_key)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()