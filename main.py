from Enigma import Enigma
from EnigmaAttack import EnigmaAttack
from PermCipher import PermCipher
import random as rnd
from time import perf_counter


with open("cipher_text.txt", "r", encoding="utf-8") as file:
    cipher_text = file.read().replace("\n", "")



with open("plain_text.txt", "r", encoding="utf-8") as file:
    plain_text = file.read().replace("\n", "")

if __name__ == '__main__':
    print(cipher_text)
    print(plain_text)
    print()

    # QUESTION 1
    t0 = perf_counter()
    enigma_attack = EnigmaAttack(plain_text=plain_text, cipher_text=cipher_text, workers=6)
    enigma_attack.parallel_attack(method="bombe", parallel=True)
    t1 = perf_counter()
    print("\nTime passed:", t0-t1)

    #QUESTION 2 - with fixed plugboard
    print("Randomly selecting S2 for fixed plugboard")
    alphabet_list = [chr(i) for i in range(65, 91)]
    numbers = list(range(len(alphabet_list)))

    rotor_order = rnd.sample([1, 2, 3, 4, 5], 3)
    ring_setting = [rnd.choice(numbers) for _ in range(3)]
    start_key = [rnd.choice(numbers) for _ in range(3)]


    alphabet_dict = {'A': 'A', 'B': 'G', 'C': 'D', 'D': 'C', 'E': 'R', 'F': 'V', 'G': 'B', 'H': 'N', 'I': 'U',
                     'J': 'K', 'K': 'J', 'L': 'M', 'M': 'L', 'N': 'H', 'O': 'P', 'P': 'O', 'Q': 'Q', 'R': 'E',
                     'S': 'S', 'T': 'Y', 'U': 'I', 'V': 'F', 'W': 'W', 'X': 'X', 'Y': 'T', 'Z': 'Z'}

    print(f"S2: Rotor_order: {rotor_order}, Ring setting: {ring_setting}, Start_key: {start_key}, plugboard: {alphabet_dict}")
    print("Encryption result of S2:")
    enigma_run = Enigma(start_key, rotor_order, ring_setting, alphabet_dict, plain_text, cipher_text)
    cipher_text_2 = enigma_run.encrypt(cipher_text, None)
    print(cipher_text_2, "\n")

    t2 = perf_counter()
    enigma_attack = EnigmaAttack(plain_text=plain_text, cipher_text=cipher_text_2, workers=6 )
    enigma_attack.parallel_attack(method="bombe", parallel=True)
    t3 = perf_counter()
    print("\nTime passed:", t2 - t3)

    # # QUESTION 2 - with no plugboard
    print("Question 2 second part with same configurations")
    print("Reencrypt S1 with no plugboard:")
    enigma_run = Enigma(start_key=[23, 1, 2], rotor_order=[1, 2, 3], ring_setting=[0, 4, 5],
                        plugboard=None, plain_text=plain_text, cipher_text=None)
    cipher_text = enigma_run.encrypt_no_plugboard(plain_text, None)
    print(cipher_text, "\n")

    print("Encryption result of S2:")
    enigma_run = Enigma(start_key, rotor_order, ring_setting, alphabet_dict, plain_text, cipher_text)
    cipher_text_2 = enigma_run.encrypt_no_plugboard(cipher_text, None)
    print(cipher_text_2, "\n")

    t4 = perf_counter()
    enigma_attack = EnigmaAttack(plain_text=plain_text, cipher_text=cipher_text_2, workers=6, plugboard=alphabet_dict)
    enigma_attack.parallel_attack(method="noplugboard", parallel=True)
    t5 = perf_counter()
    print("\nTime passed:", t4 - t5)

    # # QUESTION 3 - perm cipher
    print("Permutation cipher with block length 9 using original cipher text")
    perm_cipher = PermCipher(9, [2,8,4,6,5,1,0,3,7], cipher_text)
    s3 = perm_cipher.Encrypt()
    print("Perm ciphered text", s3)

    print("Attack result of S2:")
    t6 = perf_counter()
    enigma_attack = EnigmaAttack(plain_text=plain_text, cipher_text=s3, workers=6, plugboard=alphabet_dict)
    enigma_attack.parallel_attack(method="givenplugboard", parallel=True)
    t7 = perf_counter()
    print("\nTime passed:", t6 - t7)

