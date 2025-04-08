from itertools import combinations, permutations, product
import string
from collections import Counter
import concurrent.futures
from Enigma import Enigma
from time import perf_counter


class EnigmaAttack(Enigma):
    def __init__(self, workers=None, start_key=None, rotor_order=None, ring_setting=None, plugboard=None,
                 plain_text=None, cipher_text=None):

        super().__init__(start_key, rotor_order, ring_setting, plugboard, plain_text, cipher_text)

        self.alphabet_lst = [chr(i) for i in range(65, 91)]
        self.alphabet_dct = {chr(i): None for i in range(65, 91)}
        self.all_start_keys = list(product(range(26), repeat=3))
        self.all_rotor_order = list(permutations([1, 2, 3, 4, 5], 3))
        self.all_ring_settings = list(product(range(26), repeat=3))
        self.all_plugboard_comb = list(combinations(string.ascii_uppercase, 2))
        self.plugboard_limit = len(self.all_plugboard_comb) * 2
        self.workers = workers

    def rotor_run(self, letter):
        # Rotors are defined
        r1, r2, r3, i1, i2, i3 = self.define_rotors()
        # goes through rotors in 2 1 0 order
        letter = self.apply_rotors(letter, [r3, r2, r1], [2, 1, 0])
        # Reflector
        letter = self.reflect(letter)
        # goes through rotors in 0 1 2 order
        letter = self.apply_rotors(letter, [i1, i2, i3], [0, 1, 2])

        return letter

    def l2_select(self, l1, alphabet_list, plugboard_dump):
        count = 0
        # SECOND LETTER (l2) SELECTION
        select_new_l1 = False
        for l2 in alphabet_list:
            if len(alphabet_list) <= count:
                select_new_l1 = True
                return select_new_l1, l2

            if ((l1, l2) in plugboard_dump) or ((l2, l1) in plugboard_dump) or (
                    l1 == l2):  # checks if it exists in dump
                count = count + 1
                if len(alphabet_list) <= count:
                    select_new_l1 = True
                    return select_new_l1, l2
                else:
                    continue  # if exists continues to the for loop for next value

            elif ((l1, l2) not in plugboard_dump) and ((l2, l1) not in plugboard_dump and (l1 != l2)):
                return select_new_l1, l2

            else:
                select_new_l1 = True  # if all exists
                return select_new_l1, l2

    def attack(self, perm_chunk):
        counter = Counter(self.cipher_text)
        for idx, rotor_order in enumerate(perm_chunk):
            self.rotor_order = rotor_order
            print("Rotor order:", idx)
            for ifx, ring_setting in enumerate(self.all_ring_settings):
                self.ring_setting = ring_setting
                print("Ring settings", ifx)
                print(self.rotor_order, self.ring_setting)
                for ifs, start_key in enumerate(self.all_start_keys):
                    self.start_key = list(start_key)
                    if ifs == 0:
                        print("Start key", ifs)
                        print()

                    plugboard_check = set()  # this checks if it tried all possible pairs for this config
                    # now lets try to find plugboard starting from most common letter in cipher_text
                    for letter in counter.most_common():  # FIRST LETTER (l1) SELECTION
                        l1 = letter[0]
                        if len(plugboard_check) == self.plugboard_limit:  # checks limit
                            break  # change setting
                        alphabet_list = self.alphabet_lst.copy()  # new alphabet list for every l1 letter
                        alphabet_list.remove(l1)  # removes selected l1 letter

                        # Assign pair letter (l2) iteratively
                        select_new_l1 = False
                        while not select_new_l1:  # checks if we tried every possible config for l1
                            if (len(alphabet_list) == 0):
                                break
                            select_new_l1, l2 = self.l2_select(l1, alphabet_list, plugboard_check)
                            if select_new_l1 == True:
                                break
                            alphabet_list.remove(l2)  # also removes l2 as well

                            pair = (l1, l2)
                            plg_dump = set()  # this keeps all cant be pairs
                            temp_plugboard = self.alphabet_dct.copy()  # new alphabet dict for every (l1, x) pair
                            temp_plugboard[pair[0]] = pair[1]
                            temp_plugboard[pair[1]] = pair[0]
                            plg_dump.update([(pair[0], pair[1]), (pair[1], pair[0])])

                            self.curr_rotor_pos = self.start_key.copy()  # sets rotor start position

                            # Run enigma machine
                            for i_c, c in enumerate(self.cipher_text):
                                self.rotor_step()
                                # it also checks other known plugboard pairs too for quicker process
                                if (c == l1) or (temp_plugboard[c] != None):
                                    plug_c = temp_plugboard[c]
                                    rotor_out = self.rotor_run(plug_c)
                                    p = self.plain_text[i_c]  # plain_tex control

                                    # (rotor_out, p) will be the new plgbrd pair if it satisfies these conditions
                                    if ((rotor_out, p) in plugboard_check) or ((p, rotor_out) in plugboard_check):
                                        plugboard_check.update(plg_dump)
                                        break  # try new l2
                                    if temp_plugboard[rotor_out] == None:  # if its None --> new pair
                                        temp_plugboard[rotor_out] = p
                                        temp_plugboard[p] = rotor_out
                                        plg_dump.add((p, rotor_out))
                                        plg_dump.add((rotor_out, p))
                                    elif temp_plugboard[rotor_out] == p:  # if they are equal it is fine
                                        pass
                                    elif temp_plugboard[rotor_out] != p:  # conflict try new l2
                                        plugboard_check.update(plg_dump)
                                        break

                                    if sum(1 for k, v in temp_plugboard.items() if v is not None and v != k) == 20:
                                        plg_board = {k: k if v is None else v for k, v in temp_plugboard.items()}
                                        temp = self.curr_rotor_pos.copy()
                                        self.curr_rotor_pos = self.start_key.copy()
                                        self.plugboard = plg_board

                                        if self.encrypt(self.cipher_text, self.plain_text) == True:
                                            print(f"Key Found!\n"
                                                  f"Rotor Order: {self.rotor_order} \n"
                                                  f"Ring setting: {self.ring_setting} \n"
                                                  f"Start Key: {self.start_key} \n"
                                                  f"Plugboard: {dict(list(plg_board.items())[:len(plg_board) // 2])} \n"
                                                  f"\t\t{dict(list(plg_board.items())[len(plg_board) // 2:])}")

                                            return True
                                        else:
                                            self.curr_rotor_pos = temp.copy()

        return False

    def attack_given_plugboard(self, perm_chunk):
        print(perm_chunk)
        for idx, rotor_order in enumerate(perm_chunk):
            self.rotor_order = rotor_order
            print("Rotor order:", idx)

            for ifx, ring_setting in enumerate(self.all_ring_settings):
                self.ring_setting = ring_setting
                if ifx % 5000 == 0:
                    print("Ring Setting:", ifx)
                    print(self.rotor_order, self.ring_setting, "\n")

                for ifs, start_key in enumerate(self.all_start_keys):
                    self.start_key = list(start_key)
                    text_count = 0

                    self.curr_rotor_pos = self.start_key.copy()
                    for i_c, c in enumerate(self.cipher_text):
                        self.rotor_step()
                        plug_c = self.plugboard[c]
                        rotor_out = self.rotor_run(plug_c)  # runs thorugh rotors
                        plug_out = self.plugboard[rotor_out]
                        p = self.plain_text[i_c]  # obtain plain_text at the given location

                        if p != plug_out:
                            break
                        else:
                            text_count += 1

                        if text_count == len(self.plain_text):
                            print("Key Found")
                            print(f"Key Found!\n"
                                  f"Rotor Order: {self.rotor_order} \n"
                                  f"Ring setting: {self.ring_setting} \n"
                                  f"Start Key: {self.start_key}")
                            return True
        return False

    def attack_no_plugboard(self, perm_chunk):
        for idx, rotor_order in enumerate(perm_chunk):
            self.rotor_order = rotor_order
            print("Rotor order:", idx)

            for ifx, ring_setting in enumerate(self.all_ring_settings):
                self.ring_setting = ring_setting
                if ifx % 5000 == 0:
                    print("Rotor order:", ifx)
                    print(self.rotor_order, self.ring_setting, "\n")

                for ifs, start_key in enumerate(self.all_start_keys):
                    self.start_key = list(start_key)
                    text_count = 0

                    self.curr_rotor_pos = self.start_key.copy()
                    for i_c, c in enumerate(self.cipher_text):
                        self.rotor_step()
                        rotor_out = self.rotor_run(c)  # runs thorugh rotors
                        p = self.plain_text[i_c]  # obtain plain_text at the given location

                        if p != rotor_out:
                            break
                        else:
                            text_count += 1

                        if text_count == len(self.plain_text):
                            print("Key Found")
                            print(f"Key Found!\n"
                                  f"Rotor Order: {self.rotor_order} \n"
                                  f"Ring setting: {self.ring_setting} \n"
                                  f"Start Key: {self.start_key}")
                            return True
        return False


    def parallel_attack(self, method, parallel):
        t0 = perf_counter()

        print(f"Total rotor order: {len(self.all_rotor_order)}, ring settings: {len(self.all_ring_settings)},"
              f"starting keys: {len(self.all_start_keys)}, plugboard comb: {len(self.all_plugboard_comb)},")
        print("\n")
        self.workers = min(self.workers, len(self.all_rotor_order))
        k, m = divmod(len(self.all_rotor_order), self.workers)
        rotor_order_chunk = [self.all_rotor_order[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(self.workers)]

        if parallel == True:
            print(f"Total perm Normally: {len(self.all_rotor_order) * len(self.all_ring_settings) * len(self.all_start_keys) * len(self.all_plugboard_comb)}")
            print(f"Total perm for 1 worker: {len(rotor_order_chunk[0]) * len(self.all_ring_settings) * len(self.all_start_keys) * len(self.all_plugboard_comb)}")
            print()

            with concurrent.futures.ProcessPoolExecutor(max_workers=self.workers) as executor:
                if method == "bombe":
                    futures = [executor.submit(self.attack, chunk) for chunk in rotor_order_chunk]
                elif method == "givenplugboard":
                    futures = [executor.submit(self.attack_given_plugboard, chunk) for chunk in rotor_order_chunk]
                elif method == "noplugboard":
                    futures = [executor.submit(self.attack_no_plugboard, chunk) for chunk in rotor_order_chunk]

                for future in concurrent.futures.as_completed(futures):
                    if future.result() == True:
                        t1 = perf_counter()
                        print("\nTime passed:", t0 - t1)
                        print("Terminating all tasks...")


        elif parallel == False:
            if method == "bombe":
                self.attack(self.all_rotor_order)
            elif method == "givenplugboard":
                self.attack_given_plugboard(self.all_rotor_order)
            elif method == "noplugboard":
                self.attack_no_plugboard(self.all_rotor_order)


