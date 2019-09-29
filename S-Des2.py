

def permutation( bit, num):

        num = 'x' + num

        res = ''
        temp = []
        if bit == 10:
            temp = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        elif bit == 8:
            temp = [6, 3, 7, 4, 8, 5, 10, 9]
        else:
            temp = [2, 4, 3, 1]
        for i in temp:
            res += num[i]
        return res

def cut_half( num):
        return num[0: int(len(num)/2)], num[int(len(num)/2)
        
        :  len(num)]

def shift_left( bit, left_num, right_num):
        for i in range(bit):
            left_res = left_num[1: len(left_num)] + 
            
            left_num[0]
            left_num = left_res

        for i in range(bit):
            right_res = right_num[1: len(right_num)] + right_num[0]
            right_num = right_res
        return left_res, right_res

def ip( bit, num):
        num = 'x' + num
        res = ''
        temp = []
        if bit == 8:
            temp = [2, 6, 3, 1, 4, 8, 5, 7]

        for i in temp:
            res += num[i]

        return res

def ip_inverse( bit, num):
        num = 'x' + num
        res = ''
        temp = []
        if bit == 8:
            temp = [4, 1, 3, 5, 7, 2, 8, 6]

        for i in temp:
            res += num[i]

        return res

def ep( bit, num):
        num = 'x' + num
        res = ''
        expand = [4, 1, 2, 3, 2, 3, 4, 1]
        for i in expand:
            res += num[i]
        return res

def xor( key, num):
        res = ''
        for i in range(len(num)):
            if num[i] == key[i]:
                res += '0'
            else:
                res += '1'
        return res

def sbox( numl, numr):
        s0 = [['01', '00', '11', '10'], ['11', '10', '01', '00'],
              ['00', '10', '01', '11'], ['11', '01', '11', '10'], ]

        s1 = [['00', '01', '10', '11'], ['10', '00', '01', '11'],
              ['11', '00', '01', '00'], ['10', '01', '00', '11'], ]

        rl = int(numl[0] + numl[3], 2)
        cl = int(numl[1] + numl[2], 2)

        rr = int(numr[0] + numr[3], 2)
        cr = int(numr[1] + numr[2], 2)

        return s0[rl][cl] + s1[rr][cr]

def sw( num):
        return cut_half(num)[1] + cut_half(num)[0]

def gen_key( key):
        k = permutation(10, key)
        lh, rh = cut_half(k)
        lh, rh = shift_left(1, lh, rh)
        k1 = permutation(8, lh + rh)

        lh, rh = shift_left(2, lh, rh)
        k2 = permutation(8, lh + rh)

        return k1, k2

def encrypt( key, plain):
        enc = execute_encrypt(key ,plain)
        return enc
       

def decrypt( key, cipher):
        des = execute_decrypt(key,cipher)
        return des


def execute_encrypt(key ,plain):
        k1, k2 = gen_key(key)

        p = ip(8, plain)
        lh, rh = cut_half(p)
        op = ep(4, rh)
        op = xor(k1, op)
        sr = sbox(cut_half(op)[0], cut_half(op)[1])
        op = permutation(4, sr)
        op = xor(lh, op)
        op = op + rh

        op = sw(op)

        lh, rh = cut_half(op)
        op = ep(4, rh)
        op = xor(k2, op)
        sr = sbox(cut_half(op)[0], cut_half(op)[1])
        op = permutation(4, sr)
        op = xor(lh, op)
        op = op + rh
        cipher = ip_inverse(8, op)
        return cipher
    
           
def execute_decrypt(key,cipher):
        k1, k2 = gen_key(key)
        p = ip(8, cipher)
        lh, rh = cut_half(p)
        op = ep(4, rh)
        op = xor(k2, op)
        sr = sbox(cut_half(op)[0], cut_half(op)[1])
        op = permutation(4, sr)
        op = xor(lh, op)
        op = op + rh

        op = sw(op)

        lh, rh = cut_half(op)
        op = ep(4, rh)
        op = xor(k1, op)
        sr = sbox(cut_half(op)[0], cut_half(op)[1])
        op = permutation(4, sr)
        op = xor(lh, op)
        op = op + rh
        plain = ip_inverse(8, op)
        return plain
def sdes():

    ciphers =  ['0b11000001','0b1101010','0b10100','0b11111','0b10100100','0b10100','0b11111','0b10011010','0b10100100','0b10100100','0b1010001','0b1010001','0b10111111','0b11001010','0b10011010','0b10111111','0b1001111','0b1001111','0b1001111','0b10100100','0b1001111','0b10100100','0b1010001','0b10100100','0b1101010','0b1001111','0b11111','0b11000001','0b1010001','0b11111','0b11000001','0b1101010','0b11111','0b11111','0b1101010','0b1001111','0b11111','0b11001010','0b1101010','0b1001111','0b10011010','0b11111','0b11000001','0b10100100','0b1101010','0b11111','0b10111111','0b1101010','0b10111111','0b10100100','0b11111','0b1001111','0b10100','0b10100100','0b10100','0b10100100','0b1101010','0b10100','0b11111','0b1010001','0b10100100','0b10111111','0b1101010','0b1101010','0b1010001','0b10100100','0b1001111','0b10111111','0b10011010','0b1101010','0b11000001','0b1001111','0b10011010','0b10100','0b10111111','0b10111111','0b11111', ]
    student_number = '590610621'

    da_key = 0

    print('Cipher text: ')
    for cipher in ciphers:
        print(cipher, end=' ')

  
    for i in range(1024):
        key = str(bin(i))[2:]
        key = key.zfill(10)

        cipher_list = []
        count_correct_cipher = 0

     
        for num in range(10):

            plain = bin(ord(str(num)))[2:]
            plain = plain.zfill(8)

            cipher = encrypt(key=key, plain= plain)
            cipher_list.append(cipher)

        for index,number in enumerate(student_number):
            if(cipher_list[int(number)] == ciphers[index][2:].zfill(8)):
                count_correct_cipher += 1
            else: 
                break
   
        if(count_correct_cipher >= 9):
            da_key = str(bin(i))[2:].zfill(10)
            print('\n\nKey is:', da_key)

    plain_text = []


    for cipher in ciphers:
        cipher = str(cipher[2:].zfill(8))
        plain = decrypt(key = da_key, cipher = cipher)
        
        plain = chr(int(plain,2))

        plain_text.append(plain)


    print('\nPlain text:')
    for text in plain_text:
        print(text, end=' ')

if __name__ == '__main__':
    sdes()