import random as rnd


class PermCipher:
    def __init__(self, block_length, order, plain_text):
        self.block_length = block_length
        self.order = order
        self.plain_text = plain_text
        self.cipher_text = ""

    def random_order(self):
        ord_list = list(range(self.block_length))
        self.order = rnd.sample(ord_list, self.block_length)

    def apply_rule(self, cipher_block):
        self.cipher_text += ''.join(c for _, c in sorted(zip(self.order, cipher_block)))

    def Encrypt(self):

        if self.order == None:
            self.random_order()
        print("Order is", self.order)

        cipher_block = ""
        for idx, p in enumerate(self.plain_text):
            cipher_block += p

            if (len(cipher_block) % (self.block_length) == 0) and idx != 0:
                self.apply_rule(cipher_block)
                cipher_block = ""

        return self.cipher_text
