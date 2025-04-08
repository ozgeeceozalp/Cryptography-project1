from itertools import combinations, permutations, product
import string
import random as rnd
from collections import Counter
import concurrent.futures

class Enigma:

    def __init__(self, start_key=None, rotor_order=None, ring_setting=None, plugboard=None,
                 plain_text=None, cipher_text=None):
        self.start_key = start_key
        self.rotor_order = rotor_order
        self.ring_setting = ring_setting
        self.plugboard = plugboard
        self.plain_text = plain_text
        self.cipher_text = cipher_text
        self.curr_rotor_pos = start_key

        self.rotors = {1: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", 2: "AJDKSIRUXBLHWTMCQGZNPYFVOE",
                       3: "BDFHJLCPRTXVZNYEIWGAKMUSQO", 4: "ESOVPZJAYQUIRHXLNFTGKDCMWB",
                       5: "VZBRGITYUPSDNHLXAWMJQOFECK"}

        self.reflector_b = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

        self.invrotor = {1: "UWYGADFPVZBECKMTHXSLRINQOJ", 2: "AJPCZWRLFBDKOTYUQGENHXMIVS",
                         3: "TAGBPCSDQEUFVNZHYIXJWLRKOM", 4: "HZWVARTNLGUPXQCEJMBSKDYOIF",
                         5: "QCYLXWENFTZOSMVJUDKGIARPHB"}

        self.notches = {1: "Q", 2: "E", 3: "V", 4: "J", 5: "Z"}

        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def define_rotors(self):
        r1 = self.rotors[self.rotor_order[0]]
        r2 = self.rotors[self.rotor_order[1]]
        r3 = self.rotors[self.rotor_order[2]]

        i1 = self.invrotor[self.rotor_order[0]]
        i2 = self.invrotor[self.rotor_order[1]]
        i3 = self.invrotor[self.rotor_order[2]]

        return r1, r2, r3, i1, i2, i3

    def rotor_step(self):
        if self.alphabet[self.curr_rotor_pos[1]] == self.notches[self.rotor_order[1]]:
            self.curr_rotor_pos[0] = (self.curr_rotor_pos[0] + 1) % 26
            self.curr_rotor_pos[1] = (self.curr_rotor_pos[1] + 1) % 26
        if self.alphabet[self.curr_rotor_pos[2]] == self.notches[self.rotor_order[2]]:
            self.curr_rotor_pos[1] = (self.curr_rotor_pos[1] + 1) % 26
        self.curr_rotor_pos[2] = (self.curr_rotor_pos[2] + 1) % 26  # r3

    def letter_calc(self, letter, s, r_sel):
        offset = self.curr_rotor_pos[r_sel] - self.ring_setting[r_sel]
        letter = s[(self.alphabet.index(letter) + offset) % 26]
        letter = self.alphabet[(self.alphabet.index(letter) - offset) % 26]
        return letter

    def apply_rotors(self, letter, order, r_sel):
        letter = self.letter_calc(letter, order[0], r_sel[0])
        letter = self.letter_calc(letter, order[1], r_sel[1])
        letter = self.letter_calc(letter, order[2], r_sel[2])
        return letter

    def reflect(self, letter):
        letter_i = self.alphabet.index(letter)
        letter = self.reflector_b[letter_i]
        return letter

    def encrypt(self, c_text, p_text):
        r1, r2, r3, i1, i2, i3 = self.define_rotors()
        # steps the rotors
        res = ""
        for i_c, c in enumerate(c_text):
            self.rotor_step()
            plug_out_1 = self.plugboard[c]  # plugboard swap
            # goes through rotors in 2 1 0 order
            letter = self.apply_rotors(plug_out_1, [r3, r2, r1], [2, 1, 0])
            # Reflector
            letter = self.reflect(letter)
            # goes through rotors in 0 1 2 order
            letter = self.apply_rotors(letter, [i1, i2, i3], [0, 1, 2])

            plug_out_2 = self.plugboard[letter]  # plugboard swap again
            res += plug_out_2

            if p_text != None:
                p = p_text[i_c]  # the correct plaintext
                if plug_out_2 != p:
                    return False
        if p_text != None:
            return True
        else:
            return res

    def encrypt_no_plugboard(self, c_text, p_text):
        r1, r2, r3, i1, i2, i3 = self.define_rotors()
        # steps the rotors
        res = ""
        for i_c, c in enumerate(c_text):
            self.rotor_step()
            # goes through rotors in 2 1 0 order
            letter = self.apply_rotors(c, [r3, r2, r1], [2, 1, 0])
            # Reflector
            letter = self.reflect(letter)
            # goes through rotors in 0 1 2 order
            letter = self.apply_rotors(letter, [i1, i2, i3], [0, 1, 2])

            res += letter

            if p_text != None:
                p = p_text[i_c]  # the correct plaintext
                if letter != p:
                    return False
        if p_text != None:
            return True
        else:
            return res















